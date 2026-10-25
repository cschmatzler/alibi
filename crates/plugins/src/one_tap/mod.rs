//! Google One Tap authentication with verified Google ID tokens.
use crate::authentication_helpers::{JsonField, RequestBody, parse_body};
use crate::oauth::handlers::fetch_user_info_from_provider;
use crate::oauth::{
    OAuthConfig, OAuthProcessPolicy, OAuthSignInError, OAuthTokenSet, OAuthUserInfo,
    OAuthUserInfoRequest, process_oauth_sign_in,
};
use alibi_core::error::codes;
use alibi_core::utils::json::JsValue;
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use serde_json::json;
use std::sync::Arc;

const MISSING_CLIENT: &str = "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google.";

/// Google client IDs accepted as the ID-token audience.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneTapClientId {
    Single(String),
    Multiple(Vec<String>),
}

impl From<String> for OneTapClientId {
    fn from(value: String) -> Self {
        Self::Single(value)
    }
}

impl From<&str> for OneTapClientId {
    fn from(value: &str) -> Self {
        Self::Single(value.into())
    }
}

impl From<Vec<String>> for OneTapClientId {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

pub use crate::oauth::OAuthJwksSource;

#[derive(Clone, Default)]
pub struct OneTapConfig {
    /// Overrides the registered Google provider's client IDs when truthy.
    pub client_id: Option<OneTapClientId>,
    pub disable_signup: bool,
    /// Optional application transport/cache; defaults to Google's official JWKS endpoint.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
}

impl std::fmt::Debug for OneTapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTapConfig").finish_non_exhaustive()
    }
}

pub struct OneTapPlugin {
    config: OneTapConfig,
    keys: Arc<dyn OAuthJwksSource>,
}

impl std::fmt::Debug for OneTapPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTapPlugin").finish_non_exhaustive()
    }
}

impl Default for OneTapPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl OneTapPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(OneTapConfig::default())
    }
    #[must_use]
    pub fn with_config(config: OneTapConfig) -> Self {
        let keys = config.jwks_source.clone().unwrap_or_else(|| {
            Arc::new(crate::oauth::HttpOAuthJwksSource::new(
                "https://www.googleapis.com/oauth2/v3/certs",
            ))
        });
        Self { config, keys }
    }
    async fn callback<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let content_type = req.headers.get("content-type");
        let media = content_type.map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
        if media.as_deref() != Some("application/json") {
            let message = media.map_or_else(
                || "Content-Type is required. Allowed types: application/json".to_owned(),
                |media| {
                    format!(
                        "Content-Type \"{media}\" is not allowed. Allowed types: application/json"
                    )
                },
            );
            return AuthResponse::json(
                415,
                &json!({"code":codes::UNSUPPORTED_MEDIA_TYPE,"message":message}),
            )
            .map_err(Into::into);
        }
        let body: OneTapCallbackInput = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        if !ctx.config.current_origin_check_disabled()
            && body
                .callback_url
                .as_deref()
                .is_some_and(|url| !ctx.config.is_redirect_target_trusted(url))
        {
            return AuthResponse::json(
                403,
                &json!({"code":codes::INVALID_CALLBACK_URL,"message":"Invalid callbackURL"}),
            )
            .map_err(Into::into);
        }
        self.callback_core(req, ctx, body).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep provider token validation, account linking policy, and session issuance in their request order"
    )]
    async fn callback_core<S: AuthSchema>(
        &self,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
        body: OneTapCallbackInput,
    ) -> AuthResult<AuthResponse> {
        use alibi_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        let oauth = ctx.extensions.get::<OAuthConfig>();
        let provider = oauth.as_ref().and_then(|config| config.provider("google"));
        let audiences = match &self.config.client_id {
            Some(OneTapClientId::Single(value)) if !value.is_empty() => vec![value.clone()],
            Some(OneTapClientId::Multiple(values)) => values.clone(),
            _ => provider
                .map(|provider| {
                    let mut values = vec![provider.client_id.clone()];
                    values.extend(provider.additional_client_ids.clone());
                    values
                })
                .unwrap_or_default(),
        };
        if audiences.is_empty()
            || !matches!(&self.config.client_id, Some(OneTapClientId::Multiple(_)))
                && audiences.len() == 1
                && audiences.first().is_some_and(String::is_empty)
        {
            return message(400, MISSING_CLIENT);
        }
        let Some(payload) = self.verify(&body.id_token, &audiences).await else {
            return message(400, "invalid id token");
        };
        if !payload.get("sub").is_some_and(js_truthy) {
            return message(400, "invalid id token");
        }
        let hosted_domain = provider
            .and_then(|provider| provider.hosted_domain.as_deref())
            .filter(|domain| !domain.is_empty());
        if let Some(domain) = hosted_domain {
            let token_domain = payload
                .get("hd")
                .and_then(JsValue::as_str)
                .filter(|value| !value.is_empty());
            if token_domain.is_none() || domain != "*" && token_domain != Some(domain) {
                return message(400, "invalid id token");
            }
        }
        // Map the verified token the way the redirect and `signIn.social` flows
        // do, so the Google provider's mapping or user-info handler applies.
        let (provider_user, profile) = if let Some(provider) = provider {
            match fetch_user_info_from_provider(
                provider,
                OAuthUserInfoRequest {
                    id_token: Some(body.id_token.clone()),
                    ..OAuthUserInfoRequest::default()
                },
            )
            .await
            {
                Ok(info) => (info.user, info.data),
                Err(_) => return message(400, "invalid id token"),
            }
        } else {
            let text = |claim: &str| {
                payload
                    .get(claim)
                    .and_then(JsValue::as_str)
                    .map(str::to_owned)
            };
            let user = OAuthUserInfo {
                additional_fields: Map::default(),
                id: String::new(),
                email: text("email").unwrap_or_default(),
                name: text("name"),
                image: text("picture"),
                email_verified: payload.get("email_verified").is_some_and(|value| {
                    value.as_bool() == Some(true) || value.as_str() == Some("true")
                }),
            };
            (user, payload.to_json_value()?)
        };
        if provider_user.email.is_empty() {
            return message(400, "Email not available in token");
        }
        let Some(sub) = payload
            .get("sub")
            .and_then(JsValue::as_str)
            .filter(|value| !value.is_empty())
        else {
            return message(400, "invalid id token");
        };
        let user = OAuthUserInfo {
            id: sub.into(),
            email: provider_user.email.to_lowercase(),
            name: Some(provider_user.name.unwrap_or_default()),
            ..provider_user
        };
        let policy = OAuthProcessPolicy {
            user_validation_method: None,
            override_user_info: provider
                .is_some_and(|provider| provider.override_user_info_on_sign_in),
            require_email_verification: provider
                .is_some_and(|provider| provider.require_email_verification),
            callback_url: None,
            use_updated_user: false,
        };
        let tokens = OAuthTokenSet {
            id_token: Some(body.id_token),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            ..Default::default()
        };
        let headers = req.session_headers();
        let meta = if let Some(request) = req.physical_request() {
            alibi_core::RequestMeta::from_request(request)
        } else {
            alibi_core::RequestMeta {
                ip_address: Some(
                    ctx.config
                        .advanced
                        .ip_address
                        .resolve_ip(headers)
                        .unwrap_or_default(),
                ),
                user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
            }
        };
        let result = process_oauth_sign_in(
            super::oauth::handlers::OAuthIdentity {
                provider_name: "google",
                user: &user,
                profile: &profile,
            },
            &policy,
            &tokens,
            self.config.disable_signup || provider.is_some_and(|provider| provider.disable_sign_up),
            &meta,
            ctx,
        )
        .await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(OAuthSignInError::IdentityDenied { code, message }) => {
                return AuthResponse::json(403, &json!({"code":code,"message":message}))
                    .map_err(Into::into);
            }
            Err(OAuthSignInError::AccountLookup(_)) => {
                return Ok(crate::oauth::handlers::ambiguous_account_sign_in_response(
                    ctx,
                ));
            }
            Err(OAuthSignInError::Generic(error)) => return message(401, &error),
            Err(OAuthSignInError::SessionAuth(error)) => return message(401, &error.to_string()),
            Err(OAuthSignInError::Banned(error)) => {
                return AuthResponse::json(
                    403,
                    &json!({"code":codes::BANNED_USER,"message":error}),
                )
                .map_err(Into::into);
            }
            Err(OAuthSignInError::EmailNotVerified) => {
                return AuthResponse::json(
                    403,
                    &json!({"code":codes::EMAIL_NOT_VERIFIED,"message":"Email not verified"}),
                )
                .map_err(Into::into);
            }
        };

        let dont_remember_name = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = crate::helpers::get_cookie(req, &dont_remember_name)
            .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
            .is_some_and(|value| !value.is_empty());
        let max_age = (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds());
        let mut response = AuthResponse::json(
            200,
            &json!({"token":outcome.session.token,"user":outcome.user}),
        )?
        .with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(Some(&outcome.session.token), max_age, &ctx.config)?,
        );
        if dont_remember {
            response = response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &dont_remember_name,
                    &sign_cookie_value("true", ctx.config.current_secret()),
                    None,
                    &ctx.config,
                )?,
            );
        }
        if let Some(cookie) = outcome.account_cookie.as_ref() {
            for header in crate::oauth::create_account_cookie_headers(&ctx.config, cookie, req)? {
                response.headers.append("Set-Cookie", header);
            }
        }
        Ok(response)
    }
    /// Authenticate a verified Google credential through the public server API.
    /// # Errors
    /// Returns an input serialization error.
    pub fn one_tap_callback_endpoint(
        input: &OneTapCallbackInput,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<OneTapAuthenticated>> {
        alibi_core::endpoint::ServerEndpoint::new("one-tap", "oneTapCallback").with_body(input)
    }

    async fn verify(&self, token: &str, audience: &[String]) -> Option<JsValue> {
        let mut policy = crate::oauth::OAuthIdTokenConfig::google();
        policy.selection = crate::oauth::OAuthJwksSelection::AllMatching;
        policy.jwks_source = self.keys.clone();
        crate::oauth::id_token::verify_jwks_token(token, audience, None, &policy).await
    }
}

/// Signed Google credential and optional callback URL for a One Tap server call.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTapCallbackInput {
    pub id_token: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

/// The Google account owner's new session token and public user view.
#[derive(Debug, Deserialize)]
pub struct OneTapAuthenticated {
    pub token: String,
    pub user: Box<alibi_core::UserView>,
}

impl RequestBody for OneTapCallbackInput {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("idToken", true),
        JsonField::string("callbackURL", false),
    ];
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OneTapPlugin {
    route_openapi_metadata!(S);

    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        vec![crate::endpoint::definition(
            "oneTapCallback",
            "oneTapCallback",
            Some("/one-tap/callback"),
            HttpMethod::Post,
        )]
    }
    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        Ok(alibi_core::endpoint::EndpointInput {
            body: Some(crate::endpoint::validate_fields(
                call.body(),
                "body",
                OneTapCallbackInput::FIELDS,
            )?),
            query: call.query().cloned(),
        })
    }
    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        let output = self.callback_core(call, ctx, call.body_as()?).await?;
        let value = alibi_core::utils::json::from_slice::<JsValue>(&output.body)?;
        let mut response = if output.status >= 400 {
            alibi_core::endpoint::EndpointResponse::error(crate::endpoint::error_response(
                output.clone(),
            ))
            .with_error_body(value)
        } else {
            alibi_core::endpoint::EndpointResponse::value(value)
        };
        response.set_status(Some(output.status));
        response.merge_headers(output.headers);
        Ok(response)
    }
    fn name(&self) -> &'static str {
        "one-tap"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/one-tap/callback", "one_tap_callback")]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() == &HttpMethod::Post && req.path() == "/one-tap/callback" {
            return self.callback(req, ctx).await.map(Some);
        }
        Ok(None)
    }
}

fn js_truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Date(_) | JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

fn message(status: u16, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(status, &json!({"message":message})).map_err(Into::into)
}
