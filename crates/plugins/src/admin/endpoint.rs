//! Installed admin server operations share authorization and stored output with HTTP.
use super::{
    AdminPlugin, MESSAGE_CHANGE_ROLE, MESSAGE_GET_USER, create_user_core, get_user_core,
    set_role_core,
    types::{CreateUserRequest, GetUserQuery, SetRoleRequest},
};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        crate::endpoint::definition(
            "getUser",
            "getUser",
            Some("/admin/get-user"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "createUser",
            "createUser",
            Some("/admin/create-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "setRole",
            "setUserRole",
            Some("/admin/set-role"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    if call.operation_id() == "createUser" {
        let body: CreateUserRequest =
            super::validation::body_value("create-user", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::from(serde_json::to_value(body)?)),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "setUserRole" {
        let body: SetRoleRequest = super::validation::body_value("set-role", call.body().cloned())
            .map_err(crate::endpoint::error_response)?;
        if call.headers().is_none() {
            return Err(crate::endpoint::validation("Headers is required"));
        }
        return Ok(EndpointInput {
            body: Some(JsValue::from(serde_json::to_value(body)?)),
            query: call.query().cloned(),
        });
    }
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

    /// Assign literal roles through installed server policy and hooks.
    pub fn set_role_endpoint(
        body: &super::AdminSetRoleRequest,
    ) -> AuthResult<ServerEndpoint<super::AdminUserResponse>> {
        ServerEndpoint::new("admin", "setRole").with_body(body)
    }

    /// Provision a user through installed server policy and hooks.
    /// Without a Request or headers, the call is trusted; supplying either requires a session.
    pub fn create_user_endpoint(
        body: &super::AdminCreateUserRequest,
    ) -> AuthResult<ServerEndpoint<super::AdminUserResponse>> {
        ServerEndpoint::new("admin", "createUser").with_body(body)
    }

    pub(super) async fn call_admin_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        // The reference middleware resolves a fresh authoritative session and
        // converts a failed nested session read to an absent session.
        let read = ctx.require_authoritative_session_record(call).await.ok();
        if call.operation_id() == "createUser" {
            let body: CreateUserRequest = call.body_as()?;
            if let Some((user, session)) = read {
                let principal = ctx.user_view(&user);
                call.record_authenticated_session(principal.clone(), session);
                self.authorize_create_user(&principal, &body)?;
            } else if call.request().is_some() || call.headers().is_some() {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body());
            }
            return EndpointResponse::json(&create_user_core(&body, &self.config, ctx).await?);
        }
        let Some((user, session)) = read else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body());
        };
        let principal = ctx.user_view(&user);
        call.record_authenticated_session(principal.clone(), session);
        if call.operation_id() == "setUserRole" {
            self.authorize(&principal, "user", "set-role", MESSAGE_CHANGE_ROLE)?;
            let body: SetRoleRequest = call.body_as()?;
            return EndpointResponse::json(&set_role_core(&body, &self.config, ctx).await?);
        }
        self.authorize(&principal, "user", "get", MESSAGE_GET_USER)?;
        let query: GetUserQuery = call.query_as()?;
        EndpointResponse::json(&get_user_core(&query, ctx).await?)
    }
}
