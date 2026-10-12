//! Installed admin server operations share authorization and stored output with HTTP.
use super::{
    AdminPlugin, MESSAGE_BAN_USERS, MESSAGE_CHANGE_ROLE, MESSAGE_DELETE_USERS, MESSAGE_GET_USER,
    MESSAGE_IMPERSONATE_USERS, MESSAGE_LIST_USER_SESSIONS, MESSAGE_LIST_USERS,
    MESSAGE_REVOKE_USER_SESSIONS, MESSAGE_SET_USER_PASSWORD, MESSAGE_UPDATE_USERS, ban_user_core,
    create_user_core, get_user_core, impersonate_user_core, list_user_sessions_core,
    list_users_core, remove_user_core, revoke_user_session_core, revoke_user_sessions_core,
    set_role_core, set_user_password_core,
    types::{
        AdminUpdateUserRequest, BanUserRequest, CreateUserRequest, GetUserQuery,
        HasPermissionRequest, PermissionResponse, RevokeSessionRequest, SetRoleRequest,
        SetUserPasswordRequest, UserIdRequest,
    },
    unban_user_core, update_user_core,
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
            "stopImpersonating",
            "stopImpersonating",
            Some("/admin/stop-impersonating"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "impersonateUser",
            "impersonateUser",
            Some("/admin/impersonate-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "setUserPassword",
            "setUserPassword",
            Some("/admin/set-user-password"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "removeUser",
            "removeUser",
            Some("/admin/remove-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "revokeUserSessions",
            "revokeUserSessions",
            Some("/admin/revoke-user-sessions"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "revokeUserSession",
            "revokeUserSession",
            Some("/admin/revoke-user-session"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "banUser",
            "banUser",
            Some("/admin/ban-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "unbanUser",
            "unbanUser",
            Some("/admin/unban-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "listUserSessions",
            "adminListUserSessions",
            Some("/admin/list-user-sessions"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "listUsers",
            "listUsers",
            Some("/admin/list-users"),
            HttpMethod::Get,
        ),
        crate::endpoint::definition(
            "adminUpdateUser",
            "adminUpdateUser",
            Some("/admin/update-user"),
            HttpMethod::Post,
        ),
        crate::endpoint::definition(
            "userHasPermission",
            "userHasPermission",
            Some("/admin/has-permission"),
            HttpMethod::Post,
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
    if call.operation_id() == "stopImpersonating" {
        if call.headers().is_none() {
            return Err(crate::endpoint::validation("Headers is required"));
        }
        return Ok(EndpointInput {
            body: call.body().cloned(),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "impersonateUser" {
        let body: UserIdRequest =
            super::validation::body_value("impersonate-user", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("userId".into(), JsValue::String(body.user_id))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "setUserPassword" {
        let body: SetUserPasswordRequest =
            super::validation::body_value("set-user-password", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(alibi_core::utils::json::to_value(&body)?.into()),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "removeUser" {
        let body: UserIdRequest =
            super::validation::body_value("remove-user", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("userId".into(), JsValue::String(body.user_id))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "revokeUserSessions" {
        let body: UserIdRequest =
            super::validation::body_value("revoke-user-sessions", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("userId".into(), JsValue::String(body.user_id))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "revokeUserSession" {
        let body: RevokeSessionRequest =
            super::validation::body_value("revoke-user-session", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("sessionToken".into(), JsValue::String(body.session_token))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "banUser" {
        let body: BanUserRequest = super::validation::body_value("ban-user", call.body().cloned())
            .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(alibi_core::utils::json::to_value(&body)?.into()),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "unbanUser" {
        let body: UserIdRequest = super::validation::body_value("unban-user", call.body().cloned())
            .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("userId".into(), JsValue::String(body.user_id))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "adminListUserSessions" {
        let body: UserIdRequest =
            super::validation::body_value("list-user-sessions", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [("userId".into(), JsValue::String(body.user_id))]
                    .into_iter()
                    .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "listUsers" {
        return super::listing::validate(call);
    }
    if call.operation_id() == "adminUpdateUser" {
        let body: AdminUpdateUserRequest =
            super::validation::body_value("update-user", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::from(serde_json::to_value(body)?)),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "userHasPermission" {
        let body: HasPermissionRequest =
            super::validation::body_value("has-permission", call.body().cloned())
                .map_err(crate::endpoint::error_response)?;
        return Ok(EndpointInput {
            body: Some(JsValue::from(serde_json::to_value(body)?)),
            query: call.query().cloned(),
        });
    }
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

    /// Evaluate permissions through the installed admin policy and server hooks.
    /// Trusted selectors apply only without a Request or headers; a session always wins.
    pub fn user_has_permission_endpoint(
        body: &super::AdminPermissionRequest,
    ) -> AuthResult<ServerEndpoint<super::AdminPermissionResponse>> {
        ServerEndpoint::new("admin", "userHasPermission").with_body(body)
    }

    /// Update a user through authoritative admin policy and installed server hooks.
    pub fn admin_update_user_endpoint(
        body: &super::AdminUpdateUserRequest,
    ) -> AuthResult<ServerEndpoint<super::AdminUserOutput>> {
        ServerEndpoint::new("admin", "adminUpdateUser").with_body(body)
    }

    /// List users through authoritative admin policy and installed server hooks.
    pub fn list_users_endpoint(
        query: &super::AdminListUsersQuery,
    ) -> AuthResult<ServerEndpoint<super::AdminListUsersResponse>> {
        ServerEndpoint::new("admin", "listUsers").with_query(query)
    }

    /// List a user's stored sessions through authoritative admin policy and server hooks.
    #[must_use]
    pub fn list_user_sessions_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<super::AdminUserSessionsResponse> {
        ServerEndpoint::new("admin", "listUserSessions").with_body_value(JsValue::Object(
            [("userId".into(), JsValue::String(user_id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    /// Restore the original session from a signed impersonation cookie.
    #[must_use]
    pub fn stop_impersonating_endpoint() -> ServerEndpoint<super::AdminImpersonationResponse> {
        ServerEndpoint::new("admin", "stopImpersonating")
    }

    async fn call_stop_impersonating(
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let (user, session) = match ctx.require_cached_session(call).await {
            Ok(read) => read,
            Err(AuthError::Unauthenticated) => {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body());
            }
            Err(error) => return Err(error),
        };
        let user = match &user {
            alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
            alibi_core::AuthenticatedUser::Cached(user) => (**user).clone(),
        };
        call.record_authenticated_session(user, session.clone());
        let headers = call.headers().cloned().unwrap_or_default();
        let (value, token, dont_remember) =
            super::stop_impersonating_core(&session, &headers, ctx).await?;
        let mut response = EndpointResponse::json(&value)?;
        response.merge_headers(super::cookies::restoration_cookie_headers(
            &ctx.config,
            &token,
            dont_remember,
        )?);
        Ok(response)
    }

    /// Create an impersonation session and publish cookies through authoritative admin policy.
    #[must_use]
    pub fn impersonate_user_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<super::AdminImpersonationResponse> {
        ServerEndpoint::new("admin", "impersonateUser").with_body_value(JsValue::Object(
            [("userId".into(), JsValue::String(user_id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    /// Replace or create a credential through authoritative admin policy and server hooks.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn set_user_password_endpoint(
        input: &super::AdminSetUserPasswordRequest,
    ) -> AuthResult<ServerEndpoint<alibi_core::StatusResponse>> {
        ServerEndpoint::new("admin", "setUserPassword").with_body(input)
    }

    /// Remove a stored user, their accounts and sessions through authoritative admin policy.
    #[must_use]
    pub fn remove_user_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<super::AdminSuccessResponse> {
        ServerEndpoint::new("admin", "removeUser").with_body_value(JsValue::Object(
            [("userId".into(), JsValue::String(user_id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    /// Revoke all stored sessions for a user through authoritative administrative policy.
    #[must_use]
    pub fn revoke_user_sessions_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<super::AdminSuccessResponse> {
        ServerEndpoint::new("admin", "revokeUserSessions").with_body_value(JsValue::Object(
            [("userId".into(), JsValue::String(user_id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    /// Revoke one stored session token through authoritative administrative policy.
    #[must_use]
    pub fn revoke_user_session_endpoint(
        session_token: impl Into<String>,
    ) -> ServerEndpoint<super::AdminSuccessResponse> {
        ServerEndpoint::new("admin", "revokeUserSession").with_body_value(JsValue::Object(
            [("sessionToken".into(), JsValue::String(session_token.into()))]
                .into_iter()
                .collect(),
        ))
    }

    /// Ban a stored user and revoke their sessions through authoritative admin policy.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn ban_user_endpoint(
        input: &super::AdminBanUserRequest,
    ) -> AuthResult<ServerEndpoint<super::AdminUserResponse>> {
        ServerEndpoint::new("admin", "banUser").with_body(input)
    }

    /// Clear a stored user's ban through authoritative admin policy and server hooks.
    #[must_use]
    pub fn unban_user_endpoint(
        user_id: impl Into<String>,
    ) -> ServerEndpoint<super::AdminUserResponse> {
        ServerEndpoint::new("admin", "unbanUser").with_body_value(JsValue::Object(
            [("userId".into(), JsValue::String(user_id.into()))]
                .into_iter()
                .collect(),
        ))
    }

    async fn call_permission_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        let body: HasPermissionRequest = call.body_as()?;
        let requested = body.permissions.as_ref().ok_or_else(|| {
            message_error("invalid permission check. no permission(s) were passed.")
        })?;
        let read = ctx.require_authoritative_session_record(call).await.ok();
        let (user_id, role) = if let Some((user, session)) = read {
            let user = ctx.user_view(&user);
            call.record_authenticated_session(user.clone(), session);
            (Some(user.id), user.role)
        } else {
            if call.request().is_some() || call.headers().is_some() {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body());
            }
            let id = body.user_id.as_ref().filter(|id| !id.is_empty());
            if let Some(role) = body.role.as_ref().filter(|role| !role.is_empty()) {
                (id.cloned(), Some(role.clone()))
            } else if let Some(id) = id {
                let user = ctx
                    .database
                    .get_user_by_id_record(id)
                    .await?
                    .ok_or_else(|| message_error("user not found"))?;
                let user = ctx.user_view(&user);
                (Some(user.id), user.role)
            } else {
                return Err(message_error("user id or role is required"));
            }
        };
        EndpointResponse::json(&PermissionResponse {
            error: None,
            success: super::access::has_permission(
                user_id.as_deref(),
                role.as_deref(),
                &self.config,
                requested,
            ),
        })
    }

    pub(super) async fn call_admin_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "stopImpersonating" {
            return Self::call_stop_impersonating(call, ctx).await;
        }
        if call.operation_id() == "userHasPermission" {
            return self.call_permission_endpoint(call, ctx).await;
        }
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
        call.record_authenticated_session(principal.clone(), session.clone());
        if call.operation_id() == "impersonateUser" {
            self.authorize(&principal, "user", "impersonate", MESSAGE_IMPERSONATE_USERS)?;
            let body: UserIdRequest = call.body_as()?;
            let headers = call.headers().cloned().unwrap_or_default();
            let ip = ctx
                .config
                .advanced
                .ip_address
                .resolve_ip(&headers)
                .unwrap_or_default();
            let agent = headers.get("user-agent").cloned().unwrap_or_default();
            return match impersonate_user_core(
                &body,
                principal.id.as_str(),
                principal.role.as_deref(),
                Some(&ip),
                Some(&agent),
                &self.config,
                ctx,
            )
            .await
            {
                Ok((user, token)) => {
                    let mut response = EndpointResponse::json(&user)?;
                    response.merge_headers(super::cookies::impersonation_cookie_headers(
                        &ctx.config,
                        &headers,
                        &session.token,
                        &token,
                    )?);
                    Ok(response)
                }
                Err(super::AdminDateOperationError::Auth(error)) => Err(error),
                Err(super::AdminDateOperationError::InvalidDate) => {
                    Ok(EndpointResponse::error(AuthError::Api {
                        status: 500,
                        code: None,
                        message: String::new(),
                    })
                    .without_error_body())
                }
            };
        }
        if call.operation_id() == "setUserPassword" {
            self.authorize(
                &principal,
                "user",
                "set-password",
                MESSAGE_SET_USER_PASSWORD,
            )?;
            let body: SetUserPasswordRequest = call.body_as()?;
            return EndpointResponse::json(&set_user_password_core(&body, ctx).await?);
        }
        if call.operation_id() == "removeUser" {
            self.authorize(&principal, "user", "delete", MESSAGE_DELETE_USERS)?;
            let body: UserIdRequest = call.body_as()?;
            return EndpointResponse::json(
                &remove_user_core(&body, principal.id.as_str(), ctx).await?,
            );
        }
        if call.operation_id() == "revokeUserSessions" {
            self.authorize(
                &principal,
                "session",
                "revoke",
                MESSAGE_REVOKE_USER_SESSIONS,
            )?;
            let body: UserIdRequest = call.body_as()?;
            return EndpointResponse::json(&revoke_user_sessions_core(&body, ctx).await?);
        }
        if call.operation_id() == "revokeUserSession" {
            self.authorize(
                &principal,
                "session",
                "revoke",
                MESSAGE_REVOKE_USER_SESSIONS,
            )?;
            let body: RevokeSessionRequest = call.body_as()?;
            return EndpointResponse::json(&revoke_user_session_core(&body, ctx).await?);
        }
        if call.operation_id() == "banUser" {
            self.authorize(&principal, "user", "ban", MESSAGE_BAN_USERS)?;
            let body: BanUserRequest = call.body_as()?;
            return match ban_user_core(&body, principal.id.as_str(), &self.config, ctx).await {
                Ok(user) => EndpointResponse::json(&user),
                Err(super::AdminDateOperationError::Auth(error)) => Err(error),
                Err(super::AdminDateOperationError::InvalidDate) => {
                    Ok(EndpointResponse::error(AuthError::Api {
                        status: 500,
                        code: None,
                        message: String::new(),
                    })
                    .without_error_body())
                }
            };
        }
        if call.operation_id() == "unbanUser" {
            self.authorize(&principal, "user", "ban", MESSAGE_BAN_USERS)?;
            let body: UserIdRequest = call.body_as()?;
            return EndpointResponse::json(&unban_user_core(&body, ctx).await?);
        }
        if call.operation_id() == "adminListUserSessions" {
            self.authorize(&principal, "session", "list", MESSAGE_LIST_USER_SESSIONS)?;
            let body: UserIdRequest = call.body_as()?;
            return EndpointResponse::json(&list_user_sessions_core(&body, ctx).await?);
        }
        if call.operation_id() == "listUsers" {
            self.authorize(&principal, "user", "list", MESSAGE_LIST_USERS)?;
            let query = super::listing::params(call)?;
            return EndpointResponse::json(&list_users_core(&query, ctx).await?);
        }
        if call.operation_id() == "adminUpdateUser" {
            self.authorize(&principal, "user", "update", MESSAGE_UPDATE_USERS)?;
            let body: AdminUpdateUserRequest = call.body_as()?;
            return EndpointResponse::json(
                &update_user_core(&body, &principal, &self.config, ctx).await?,
            );
        }
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

fn message_error(message: &str) -> AuthError {
    AuthError::Api {
        status: 400,
        code: None,
        message: message.into(),
    }
}
