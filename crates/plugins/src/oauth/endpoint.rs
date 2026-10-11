//! Logical provider-token access uses the genuine session and shared account algorithm.
use super::{OAuthAccessToken, OAuthAccountSelection, OAuthPlugin};
use alibi_core::endpoint::{
    EndpointCall, EndpointContextPatch, EndpointDefinition, EndpointInput, EndpointResponse,
    ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![crate::endpoint::definition(
        "getAccessToken",
        "getAccessToken",
        Some("/get-access-token"),
        HttpMethod::Post,
    )]
}
fn selection_input(call: &EndpointCall) -> AuthResult<serde_json::Value> {
    Ok(alibi_core::utils::json::from_value(
        call.body().cloned().unwrap_or(JsValue::Null),
    )?)
}
pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    _ = OAuthAccountSelection::from_value(&selection_input(call)?)
        .map_err(|message| crate::endpoint::validation(format!("[body] {message}")))?;
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
        ServerEndpoint::new("oauth", "getAccessToken").with_body_value(input)
    }
    pub(super) async fn call_access_endpoint(
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
        let (value, cookies) = super::account::get_access_token_for_selection(
            &self.config,
            call,
            ctx,
            &user_id,
            selection,
        )
        .await?;
        let mut response = EndpointResponse::json(&value)?;
        for cookie in cookies {
            response = response.with_header("set-cookie", cookie);
        }
        Ok(response)
    }
}
