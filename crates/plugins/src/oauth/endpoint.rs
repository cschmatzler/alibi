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
    if call.operation_id() == "socialSignIn" {
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
    let mut body = crate::endpoint::validate_fields(call.body(), "body", fields)?;
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
        _ = crate::endpoint::validate_fields(Some(token), "body.idToken", token_fields)?;
    }
    let parsed: super::OAuthSocialSignInRequest =
        alibi_core::utils::json::from_value(body.clone())?;
    super::handlers::validate_authorization_params(parsed.additional_params.as_ref())?;
    Ok(EndpointInput {
        body: Some(body),
        query: call.query().cloned(),
    })
}

impl OAuthPlugin {
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
        let flow = match Box::pin(super::handlers::social_sign_in_core(
            &body,
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
        let mut response = EndpointResponse::json(&flow.response)?;
        if flow.response.redirect
            && let Some(url) = &flow.response.url
        {
            response = response.with_header("location", url);
        }
        let cookie = match ctx.config.account.store_state_strategy {
            alibi_core::OAuthStateStrategy::Automatic
            | alibi_core::OAuthStateStrategy::Database => super::handlers::state_cookie_header(
                &ctx.config,
                ctx.config.current_secret(),
                &flow.state,
            )?,
            alibi_core::OAuthStateStrategy::Cookie => {
                super::handlers::cookie_state_header(&ctx.config, &flow.payload)?
            }
        };
        Ok(response.with_header("set-cookie", cookie))
    }
}
