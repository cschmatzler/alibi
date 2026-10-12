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
