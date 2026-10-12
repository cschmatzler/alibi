//! Installed admin server operations share authorization and stored output with HTTP.
use super::{AdminPlugin, MESSAGE_GET_USER, get_user_core, types::GetUserQuery};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![crate::endpoint::definition(
        "getUser",
        "getUser",
        Some("/admin/get-user"),
        HttpMethod::Get,
    )]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let query = crate::endpoint::validate_fields(
        call.query(),
        "query",
        &[crate::authentication_helpers::JsonField::string("id", true)],
    )?;
    Ok(EndpointInput {
        query: Some(query),
        body: call.body().cloned(),
    })
}

impl AdminPlugin {
    /// Read a user through the installed admin policy and server endpoint hooks.
    #[must_use]
    pub fn get_user_endpoint(id: impl Into<String>) -> ServerEndpoint<super::AdminUserOutput> {
        ServerEndpoint::new("admin", "getUser").with_query_value(JsValue::Object(
            [("id".into(), JsValue::String(id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    pub(super) async fn call_get_user(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        // The reference middleware resolves a fresh authoritative session and
        // converts a failed nested session read to an absent session.
        let Ok((user, session)) = ctx.require_authoritative_session_record(call).await else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body());
        };
        let principal = ctx.user_view(&user);
        call.record_authenticated_session(principal.clone(), session);
        self.authorize(&principal, "user", "get", MESSAGE_GET_USER)?;
        let query: GetUserQuery = call.query_as()?;
        EndpointResponse::json(&get_user_core(&query, ctx).await?)
    }
}
