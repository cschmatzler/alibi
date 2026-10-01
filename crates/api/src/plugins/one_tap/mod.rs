//! Google One Tap authentication with verified Google ID tokens.
use crate::plugins::authentication_helpers::{JsonField, RequestBody, parse_body};
use crate::plugins::oauth::{
    OAuthConfig, OAuthProcessPolicy, OAuthSignInError, OAuthTokenSet, OAuthUserInfo,
    process_oauth_sign_in,
};
use async_trait::async_trait;
use base64::Engine;
use better_auth_core::utils::json::{JsValue, parse_value};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
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

/// A transport/cache for Google's public signing keys. Token verification always
/// validates signatures and Google claims independently of this source.
#[async_trait]
pub trait GoogleJwksSource: Send + Sync {
    async fn fetch_keys(&self) -> Result<Vec<Value>, String>;
}
struct DefaultGoogleJwksSource(reqwest::Client);
#[async_trait]
impl GoogleJwksSource for DefaultGoogleJwksSource {
    async fn fetch_keys(&self) -> Result<Vec<Value>, String> {
        let bytes = self
            .0
            .get(GOOGLE_JWKS_URL)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .bytes()
            .await
            .map_err(|error| error.to_string())?;
        let data: Value =
            better_auth_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
        data.get("keys")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "Keys not found".into())
    }
}

#[derive(Clone, Default)]
pub struct OneTapConfig {
    /// Overrides the registered Google provider's client IDs when truthy.
    pub client_id: Option<OneTapClientId>,
    pub disable_signup: bool,
    /// Optional application transport/cache; defaults to Google's official JWKS endpoint.
    pub jwks_source: Option<Arc<dyn GoogleJwksSource>>,
}

pub struct OneTapPlugin {
    config: OneTapConfig,
    keys: Arc<dyn GoogleJwksSource>,
}
impl Default for OneTapPlugin {
    fn default() -> Self {
        Self::new()
    }
}
impl OneTapPlugin {
    pub fn new() -> Self {
        Self::with_config(OneTapConfig::default())
    }
    pub fn with_config(config: OneTapConfig) -> Self {
        let keys = config
            .jwks_source
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultGoogleJwksSource(reqwest::Client::new())));
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
            let message = match media {
                Some(media) => format!(
                    "Content-Type \"{media}\" is not allowed. Allowed types: application/json"
                ),
                None => "Content-Type is required. Allowed types: application/json".to_owned(),
            };
            return AuthResponse::json(
                415,
                &json!({"code":"UNSUPPORTED_MEDIA_TYPE","message":message}),
            )
            .map_err(Into::into);
        }
        let body: CallbackBody = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        if !ctx.config.advanced.disable_origin_check
            && body
                .callback_url
                .as_deref()
                .is_some_and(|url| !ctx.config.is_redirect_target_trusted(url))
        {
            return AuthResponse::json(
                403,
                &json!({"code":"INVALID_CALLBACK_URL","message":"Invalid callbackURL"}),
            )
            .map_err(Into::into);
        }
        let oauth = ctx.extensions.get::<OAuthConfig>();
        let provider = oauth
            .as_ref()
            .and_then(|config| config.providers.get("google"));
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
        let Some(email) = payload
            .get("email")
            .and_then(JsValue::as_str)
            .filter(|value| !value.is_empty())
        else {
            return message(400, "Email not available in token");
        };
        let Some(sub) = payload
            .get("sub")
            .and_then(JsValue::as_str)
            .filter(|value| !value.is_empty())
        else {
            return message(400, "invalid id token");
        };
        let user = OAuthUserInfo {
            id: sub.into(),
            email: email.to_lowercase(),
            name: Some(
                payload
                    .get("name")
                    .and_then(JsValue::as_str)
                    .unwrap_or_default()
                    .into(),
            ),
            image: payload
                .get("picture")
                .and_then(JsValue::as_str)
                .map(str::to_owned),
            email_verified: payload.get("email_verified").is_some_and(|value| {
                value.as_bool() == Some(true) || value.as_str() == Some("true")
            }),
        };
        let policy = OAuthProcessPolicy {
            override_user_info: false,
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
        let result = process_oauth_sign_in(
            "google",
            &policy,
            &user,
            &tokens,
            self.config.disable_signup || provider.is_some_and(|provider| provider.disable_sign_up),
            &better_auth_core::RequestMeta::from_request(req),
            ctx,
        )
        .await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(OAuthSignInError::Generic(error)) => return message(401, &error),
            Err(OAuthSignInError::Banned(error)) => {
                return AuthResponse::json(403, &json!({"code":"BANNED_USER","message":error}))
                    .map_err(Into::into);
            }
            Err(OAuthSignInError::EmailNotVerified) => {
                return AuthResponse::json(
                    403,
                    &json!({"code":"EMAIL_NOT_VERIFIED","message":"Email not verified"}),
                )
                .map_err(Into::into);
            }
        };
        use better_auth_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        let dont_remember_name = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = crate::plugins::helpers::get_cookie(req, &dont_remember_name)
            .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
            .is_some_and(|value| !value.is_empty());
        let max_age = (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds());
        let mut response = AuthResponse::json(
            200,
            &json!({"token":outcome.session.token,"user":outcome.user}),
        )?
        .with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(Some(&outcome.session.token), max_age, &ctx.config),
        );
        if dont_remember {
            response = response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &dont_remember_name,
                    &sign_cookie_value("true", &ctx.config.secret),
                    None,
                    &ctx.config,
                ),
            );
        }
        if let Some(cookie) = outcome.account_cookie.as_ref() {
            response = response.with_appended_header(
                "Set-Cookie",
                crate::plugins::oauth::create_account_cookie_header(
                    &ctx.config,
                    &ctx.config.secret,
                    cookie,
                )?,
            );
        }
        Ok(response)
    }
    async fn verify(&self, token: &str, audience: &[String]) -> Option<JsValue> {
        let parts: Vec<_> = token.split('.').collect();
        let [header_encoded, payload_encoded, signature] = parts.as_slice() else {
            return None;
        };
        let (signed, _) = token.rsplit_once('.')?;
        let raw_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_encoded)
            .ok()?;
        let raw_header = parse_value(std::str::from_utf8(&raw_header).ok()?).ok()?;
        let _ = raw_header.as_object()?;
        if raw_header.get("alg").and_then(JsValue::as_str) != Some("RS256") {
            return None;
        }
        let keys = self.keys.fetch_keys().await.ok()?;
        let selected: Vec<_> = keys
            .into_iter()
            .filter(|key| {
                let kid = raw_header.get("kid").filter(|kid| js_truthy(kid));
                kid.is_none_or(|kid| {
                    kid.as_str()
                        .is_some_and(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
                })
            })
            .collect();
        let mut public_keys = Vec::new();
        for key in selected {
            let key: jsonwebtoken::jwk::Jwk = serde_json::from_value(key).ok()?;
            public_keys.push(DecodingKey::from_jwk(&key).ok()?);
        }
        if let Some(crit) = raw_header.get("crit") {
            let names = crit.as_array()?;
            if names.is_empty()
                || names.iter().any(|name| name.as_str() != Some("b64"))
                || raw_header.get("b64").and_then(JsValue::as_bool) != Some(true)
            {
                return None;
            }
        }
        for key in public_keys {
            if jsonwebtoken::crypto::verify(signature, signed.as_bytes(), &key, Algorithm::RS256)
                .ok()
                == Some(true)
            {
                let raw_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload_encoded)
                    .ok()?;
                let payload = parse_value(std::str::from_utf8(&raw_payload).ok()?).ok()?;
                if valid_claims(&payload, audience) {
                    return Some(payload);
                }
            }
        }
        None
    }
}
fn valid_claims(payload: &JsValue, audiences: &[String]) -> bool {
    if !payload
        .get("iss")
        .and_then(JsValue::as_str)
        .is_some_and(|issuer| {
            issuer == "https://accounts.google.com" || issuer == "accounts.google.com"
        })
    {
        return false;
    }
    let matches_audience = match payload.get("aud") {
        Some(JsValue::String(value)) => audiences.contains(value),
        Some(JsValue::Array(values)) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| audiences.iter().any(|audience| audience == value))
        }),
        _ => false,
    };
    if !matches_audience {
        return false;
    }
    let now = Utc::now().timestamp() as f64;
    let Some(iat) = payload
        .get("iat")
        .and_then(JsValue::as_f64)
        .filter(|value| value.is_finite())
    else {
        return false;
    };
    if iat > now || now - iat > 3600.0 {
        return false;
    }
    for (claim, lower_bound) in [("exp", true), ("nbf", false)] {
        if let Some(value) = payload.get(claim) {
            let Some(date) = value.as_f64() else {
                return false;
            };
            if lower_bound && date <= now || !lower_bound && date > now {
                return false;
            }
        }
    }
    true
}
fn js_truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        _ => true,
    }
}
fn message(status: u16, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(status, &json!({"message":message})).map_err(Into::into)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallbackBody {
    id_token: String,
    callback_url: Option<String>,
}
impl RequestBody for CallbackBody {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("idToken", true),
        JsonField::string("callbackURL", false),
    ];
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OneTapPlugin {
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
