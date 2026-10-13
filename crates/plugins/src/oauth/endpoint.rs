//! Logical provider-token access uses the genuine session and shared account algorithm.
use super::{OAuthAccessToken, OAuthAccountProfile, OAuthAccountSelection, OAuthPlugin};
use alibi_core::endpoint::{
    EndpointCall, EndpointContextPatch, EndpointDefinition, EndpointInput, EndpointResponse,
    ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        crate::endpoint::definition(
            "callbackOAuth",
            "handleOAuthCallback",
            Some("/callback/:id"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "getAccessToken",
            "getAccessToken",
            Some("/get-access-token"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "refreshToken",
            "refreshToken",
            Some("/refresh-token"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "accountInfo",
            "accountInfo",
            Some("/account-info"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "signInSocial",
            "socialSignIn",
            Some("/sign-in/social"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "linkSocialAccount",
            "linkSocialAccount",
            Some("/link-social"),
            HttpMethod::Post,
        ),
    ]
}
/// Public result of the `refreshToken` server operation.
/// Provider-defined token scalars are preserved in the decoded result.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthRefreshResult {
    pub access_token: Option<serde_json::Value>,
    pub refresh_token: Option<serde_json::Value>,
    pub id_token: Option<serde_json::Value>,
    pub access_token_expires_at: Option<String>,
    pub refresh_token_expires_at: Option<String>,
    pub scope: Option<String>,
    pub provider_id: String,
    pub account_id: Option<String>,
}

fn selection_input(call: &EndpointCall) -> AuthResult<serde_json::Value> {
    Ok(alibi_core::utils::json::from_value(
        if call.operation_id() == "accountInfo" {
            call.query()
        } else {
            call.body()
        }
        .cloned()
        .unwrap_or(JsValue::Null),
    )?)
}
pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if call.operation_id() == "handleOAuthCallback" {
        return validate_callback(call);
    }
    if matches!(call.operation_id(), "socialSignIn" | "linkSocialAccount") {
        return validate_social(call);
    }
    _ = OAuthAccountSelection::from_value(&selection_input(call)?).map_err(|message| {
        crate::endpoint::validation(format!(
            "[{}] {message}",
            if call.operation_id() == "accountInfo" {
                "query"
            } else {
                "body"
            }
        ))
    })?;
    Ok(EndpointInput {
        body: call.body().cloned(),
        query: call.query().cloned(),
    })
}
impl OAuthPlugin {
    /// Read or refresh a provider account's access token through installed server hooks.
    #[must_use]
    pub fn get_access_token_endpoint(
        selection: OAuthAccountSelection,
        user_id: Option<&str>,
    ) -> ServerEndpoint<OAuthAccessToken> {
        Self::account_endpoint("getAccessToken", selection, user_id)
    }
    /// Refresh an owned provider grant through installed server hooks.
    #[must_use]
    pub fn refresh_token_endpoint(
        selection: OAuthAccountSelection,
        user_id: Option<&str>,
    ) -> ServerEndpoint<OAuthRefreshResult> {
        Self::account_endpoint("refreshToken", selection, user_id)
    }
    /// Fetch the selected provider profile through installed server hooks.
    #[must_use]
    pub fn account_info_endpoint(
        selection: OAuthAccountSelection,
        user_id: Option<&str>,
    ) -> ServerEndpoint<OAuthAccountProfile> {
        Self::account_endpoint("accountInfo", selection, user_id)
    }
    fn account_endpoint<T>(
        operation: &'static str,
        selection: OAuthAccountSelection,
        user_id: Option<&str>,
    ) -> ServerEndpoint<T> {
        let mut input = JsValue::Object(match selection {
            OAuthAccountSelection::Id(id) => [("accountId".into(), JsValue::String(id))]
                .into_iter()
                .collect(),
            OAuthAccountSelection::Cookie => [("useAccountCookie".into(), JsValue::Bool(true))]
                .into_iter()
                .collect(),
        });
        if let (Some(user), JsValue::Object(input)) = (user_id, &mut input) {
            let _ = input.insert("userId".into(), JsValue::String(user.into()));
        }
        let endpoint = ServerEndpoint::new("oauth", operation);
        if operation == "accountInfo" {
            endpoint.with_query_value(input)
        } else {
            endpoint.with_body_value(input)
        }
    }
    pub(super) async fn call_account_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let json = selection_input(call)?;
        let selection =
            OAuthAccountSelection::from_value(&json).map_err(crate::endpoint::validation)?;
        let mut input = call.clone();
        if ctx.config.session.has_server_session_store() {
            EndpointContextPatch {
                query: Some(JsValue::Object(
                    [("disableCookieCache".into(), JsValue::Bool(true))]
                        .into_iter()
                        .collect(),
                )),
                ..Default::default()
            }
            .apply(&mut input);
        }
        let read = alibi_core::session::cookie_cache::runtime::authenticated(ctx, &input, false)
            .await
            .ok()
            .flatten();
        let user_id = if let Some(read) = read {
            let user = ctx.user_view(&read.user);
            call.record_authenticated_session(user.clone(), read.session);
            user.id
        } else {
            if call.request().is_some() || call.headers().is_some() {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body());
            }
            json.get("userId")
                .and_then(serde_json::Value::as_str)
                .filter(|user| !user.is_empty())
                .ok_or(AuthError::Upstream {
                    status: 400,
                    code: "USER_ID_OR_SESSION_REQUIRED",
                    message: "Either userId or session is required",
                })?
                .to_owned()
        };
        let (value, cookies) = if call.operation_id() == "accountInfo" {
            let (value, cookies) = match Box::pin(super::account::account_info_for_selection(
                &self.config,
                call,
                ctx,
                &user_id,
                selection,
            ))
            .await
            {
                Ok(response) => response,
                Err(AuthError::Api {
                    code: Some(code), ..
                }) if code == "OAUTH_PROFILE_EXCEPTION" => {
                    return Ok(EndpointResponse::error(AuthError::Api {
                        status: 500,
                        code: None,
                        message: String::new(),
                    })
                    .without_error_body());
                }
                Err(error) => return Err(error),
            };
            (
                serde_json::to_value(value)
                    .map_err(|error| AuthError::internal(error.to_string()))?,
                cookies,
            )
        } else if call.operation_id() == "refreshToken" {
            Box::pin(super::account::refresh_token_for_selection(
                &self.config,
                call,
                ctx,
                &user_id,
                selection,
            ))
            .await?
        } else {
            let (value, cookies) = super::account::get_access_token_for_selection(
                &self.config,
                call,
                ctx,
                &user_id,
                selection,
            )
            .await?;
            (
                serde_json::to_value(value)
                    .map_err(|error| AuthError::internal(error.to_string()))?,
                cookies,
            )
        };
        let mut response = EndpointResponse::json(&value)?;
        for cookie in cookies {
            response = response.with_header("set-cookie", cookie);
        }
        Ok(response)
    }
}

fn validate_social(call: &EndpointCall) -> AuthResult<EndpointInput> {
    use crate::authentication_helpers::{JsonField, JsonFieldKind};
    if call.body().is_some_and(|body| body.as_object().is_some())
        && !call
            .body()
            .and_then(|body| body.get("provider"))
            .is_some_and(JsValue::is_string)
    {
        return Err(crate::endpoint::validation("[body.provider] Invalid input"));
    }
    let fields = &[
        JsonField::string("provider", true),
        JsonField::string("callbackURL", false),
        JsonField::string("newUserCallbackURL", false),
        JsonField::string("errorCallbackURL", false),
        JsonField::string("loginHint", false),
        JsonField {
            name: "disableRedirect",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
        JsonField {
            name: "requestSignUp",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
        JsonField {
            name: "idToken",
            kind: JsonFieldKind::Record,
            required: false,
        },
        JsonField {
            name: "additionalData",
            kind: JsonFieldKind::Record,
            required: false,
        },
        JsonField {
            name: "additionalParams",
            kind: JsonFieldKind::Record,
            required: false,
        },
    ];
    let linking = call.operation_id() == "linkSocialAccount";
    let fields = fields
        .iter()
        .filter(|field| !linking || field.name != "newUserCallbackURL")
        .map(|field| JsonField {
            name: field.name,
            kind: field.kind,
            required: field.required,
        })
        .collect::<Vec<_>>();
    let mut body = crate::endpoint::validate_fields(call.body(), "body", &fields)?;
    if let Some(scopes) = call.body().and_then(|body| body.get("scopes")) {
        let values = scopes.as_array().ok_or_else(|| {
            crate::endpoint::validation(format!(
                "[body.scopes] Invalid input: expected array, received {}",
                crate::authentication_helpers::json_type(Some(scopes))
            ))
        })?;
        for (index, value) in values.iter().enumerate() {
            if !value.is_string() {
                return Err(crate::endpoint::validation(format!(
                    "[body.scopes.{index}] Invalid input: expected string, received {}",
                    crate::authentication_helpers::json_type(Some(value))
                )));
            }
        }
        if let JsValue::Object(body) = &mut body {
            _ = body.insert("scopes".into(), scopes.clone());
        }
    }
    if let Some(params) = body.get("additionalParams").and_then(JsValue::as_object) {
        for (key, value) in params {
            if !value.is_string() {
                return Err(crate::endpoint::validation(format!(
                    "[body.additionalParams.{key}] Invalid input: expected string, received {}",
                    crate::authentication_helpers::json_type(Some(value))
                )));
            }
        }
    }
    if let Some(token) = body.get("idToken") {
        let token_fields = &[
            JsonField::string("token", true),
            JsonField::string("nonce", false),
            JsonField::string("accessToken", false),
            JsonField::string("refreshToken", false),
            JsonField {
                name: "user",
                kind: JsonFieldKind::Record,
                required: false,
            },
        ];
        let token_fields = token_fields
            .iter()
            .filter(|field| !linking || field.name != "user")
            .map(|field| JsonField {
                name: field.name,
                kind: field.kind,
                required: field.required,
            })
            .collect::<Vec<_>>();
        let parsed_token =
            crate::endpoint::validate_fields(Some(token), "body.idToken", &token_fields)?;
        if linking && let JsValue::Object(body) = &mut body {
            _ = body.insert("idToken".into(), parsed_token);
        }
    }
    let parsed: super::OAuthSocialSignInRequest =
        alibi_core::utils::json::from_value(body.clone())?;
    super::handlers::validate_authorization_params(parsed.additional_params.as_ref())?;
    if linking && call.headers().is_none() {
        return Err(crate::endpoint::validation("Headers is required"));
    }
    Ok(EndpointInput {
        body: Some(body),
        query: call.query().cloned(),
    })
}

impl OAuthPlugin {
    /// Link a provider account to the verified session owner through installed server hooks.
    pub fn link_social_account_endpoint(
        body: &super::OAuthLinkSocialRequest,
    ) -> AuthResult<ServerEndpoint<super::OAuthSocialSignInResponse>> {
        ServerEndpoint::new("oauth", "linkSocialAccount").with_body(body)
    }
    pub(super) async fn call_link_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let body: super::OAuthLinkSocialRequest = call.body_as()?;
        let (user, session) =
            ctx.require_cached_session(call)
                .await
                .map_err(|_| AuthError::Upstream {
                    status: 401,
                    code: "UNAUTHORIZED",
                    message: "Unauthorized",
                })?;
        call.record_authenticated_session(ctx.user_view(&user), session.clone());
        if let Some(token) = &body.id_token {
            let provider = self
                .config
                .providers
                .get(&body.provider)
                .ok_or_else(|| AuthError::not_found("Provider not found"))?;
            return EndpointResponse::json(
                &Box::pin(super::handlers::link_with_id_token_core(
                    &body, token, provider, &session, ctx,
                ))
                .await?,
            );
        }
        let flow = match Box::pin(super::handlers::link_social_core(
            &body,
            &session,
            &self.config,
            call.request(),
            ctx,
        ))
        .await
        {
            Ok(flow) => flow,
            Err(AuthError::Config(_)) => {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 500,
                    code: None,
                    message: String::new(),
                })
                .without_error_body());
            }
            Err(error) => return Err(error),
        };
        flow_response(&flow, &ctx.config)
    }
    /// Initiate social sign-in or admit an ID token through installed server hooks.
    pub fn sign_in_social_endpoint(
        body: &super::OAuthSocialSignInRequest,
    ) -> AuthResult<ServerEndpoint<super::OAuthSocialSignInResponse>> {
        ServerEndpoint::new("oauth", "signInSocial").with_body(body)
    }
    pub(super) async fn call_social_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let body: super::OAuthSocialSignInRequest = call.body_as()?;
        let headers = call.headers().cloned().unwrap_or_default();
        let meta = alibi_core::RequestMeta {
            ip_address: Some(
                ctx.config
                    .advanced
                    .ip_address
                    .resolve_ip(&headers)
                    .unwrap_or_default(),
            ),
            user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
        };
        if let Some(token) = &body.id_token {
            let provider = self
                .config
                .providers
                .get(&body.provider)
                .ok_or_else(|| AuthError::not_found("Provider not found"))?;
            let value =
                super::handlers::sign_in_with_id_token_core(&body, token, provider, &meta, ctx)
                    .await?;
            let mut response = EndpointResponse::json(&value)?;
            if let Some(token) = &value.token {
                response.merge_headers(crate::authentication_helpers::session_cookie_headers(
                    &ctx.config,
                    token,
                    false,
                )?);
            }
            return Ok(response);
        }
        start_social_flow_response(&body, &self.config, call.request(), ctx).await
    }
}

pub(crate) async fn start_social_flow_response(
    body: &super::OAuthSocialSignInRequest,
    config: &super::OAuthConfig,
    request: Option<&alibi_core::AuthRequest>,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<EndpointResponse> {
    let flow = match Box::pin(super::handlers::social_sign_in_core(
        body, config, request, ctx,
    ))
    .await
    {
        Ok(flow) => flow,
        Err(AuthError::Config(_)) => {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 500,
                code: None,
                message: String::new(),
            })
            .without_error_body());
        }
        Err(error) => return Err(error),
    };
    flow_response(&flow, &ctx.config)
}

fn flow_response(
    flow: &super::handlers::InitiatedOAuthFlow,
    config: &alibi_core::AuthConfig,
) -> AuthResult<EndpointResponse> {
    let mut response = EndpointResponse::json(&flow.response)?;
    if flow.response.redirect
        && let Some(url) = &flow.response.url
    {
        response = response.with_header("location", url);
    }
    let cookie = match config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            super::handlers::state_cookie_header(config, config.current_secret(), &flow.state)?
        }
        alibi_core::OAuthStateStrategy::Cookie => {
            super::handlers::cookie_state_header(config, &flow.payload)?
        }
    };
    Ok(response.with_header("set-cookie", cookie))
}

fn validate_callback(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let fields = [
        "code",
        "error",
        "device_id",
        "error_description",
        "state",
        "user",
        "iss",
    ]
    .map(|name| crate::authentication_helpers::JsonField::string(name, false));
    let parse = |value: Option<&JsValue>, location: &str| {
        value
            .map(|value| crate::endpoint::validate_fields(Some(value), location, &fields))
            .transpose()
    };
    Ok(EndpointInput {
        body: parse(call.body(), "body")?,
        query: parse(call.query(), "query")?,
    })
}
impl OAuthPlugin {
    /// Redeem a provider callback through installed server hooks and genuine logical input.
    /// Redirects remain API errors with their Location and complete cookie headers.
    pub fn callback_oauth_endpoint(
        provider: &str,
        query: Option<&super::OAuthCallbackInput>,
    ) -> AuthResult<ServerEndpoint<JsValue>> {
        let endpoint = ServerEndpoint::new("oauth", "callbackOAuth")
            .with_params(&serde_json::json!({"id":provider}))?;
        match query {
            Some(query) => endpoint.with_query(query),
            None => Ok(endpoint),
        }
    }
    pub(super) async fn call_callback_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let invalid =
            || super::handlers::callback_failure_redirect(ctx, "invalid_callback_request");
        let method = call.method().unwrap_or(&HttpMethod::Get);
        let response = if !matches!(method, HttpMethod::Get | HttpMethod::Post)
            || (method == &HttpMethod::Get && call.query().is_none())
        {
            invalid()
        } else {
            let provider = call
                .params()
                .and_then(|params| params.get("id"))
                .map(JsValue::coerce_string)
                .transpose()
                .map_err(AuthError::internal)?
                .ok_or_else(|| AuthError::internal("Missing OAuth provider parameters"))?;
            let map =
                |value: Option<&JsValue>| -> AuthResult<std::collections::HashMap<String, String>> {
                    value
                        .cloned()
                        .map_or_else(
                            || Ok(std::collections::HashMap::new()),
                            alibi_core::utils::json::from_value,
                        )
                        .map_err(AuthError::from)
                };
            let query = map(call.query())?;
            if method == &HttpMethod::Post {
                let mut data = map(call.body())?;
                data.extend(query);
                super::handlers::callback_post_response(ctx, &provider, &data)
            } else {
                Box::pin(super::handlers::callback_core(
                    &self.config,
                    &provider,
                    &query,
                    call,
                    ctx,
                ))
                .await?
            }
        };
        let mut output = if response.status == 302 {
            EndpointResponse::redirect(
                response
                    .headers
                    .get("location")
                    .cloned()
                    .unwrap_or_default(),
            )
        } else {
            EndpointResponse::error(AuthError::Api {
                status: response.status,
                code: None,
                message: String::new(),
            })
            .without_error_body()
        };
        for (name, value) in response.headers {
            // A redirect API error carries endpoint headers; HTTP conversion
            // adds the content type of its absent body at the outer boundary.
            if !name.eq_ignore_ascii_case("content-type") {
                output = output.with_header(name, value);
            }
        }
        Ok(output)
    }
}
