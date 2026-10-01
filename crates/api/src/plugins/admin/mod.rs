use std::collections::HashMap;

use better_auth_core::entity::AuthUser;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name,
};
use better_auth_core::utils::username::{UsernameValidationError, validate_username};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, ErrorCodeMessageResponse,
};

pub mod access;
mod callbacks;
pub(crate) use callbacks::BannedUserMessagePolicy;
pub use callbacks::{AdminBannedUserMessage, AdminBannedUserMessageHandler};
pub(super) mod handlers;
pub(super) mod types;
mod validation;

#[cfg(test)]
mod tests;

use crate::plugins::helpers::{delete_session_cookie_headers, get_cookie};
use access::{has_permission, is_admin_role, is_admin_user_id};
use handlers::*;
use types::*;

const MESSAGE_CHANGE_ROLE: &str = "You are not allowed to change users role";
const MESSAGE_CREATE_USERS: &str = "You are not allowed to create users";
const MESSAGE_LIST_USERS: &str = "You are not allowed to list users";
const MESSAGE_LIST_USER_SESSIONS: &str = "You are not allowed to list users sessions";
const MESSAGE_BAN_USERS: &str = "You are not allowed to ban users";
const MESSAGE_IMPERSONATE_USERS: &str = "You are not allowed to impersonate users";
const MESSAGE_REVOKE_USER_SESSIONS: &str = "You are not allowed to revoke users sessions";
const MESSAGE_DELETE_USERS: &str = "You are not allowed to delete users";
const MESSAGE_SET_USER_PASSWORD: &str = "You are not allowed to set users password";
const MESSAGE_GET_USER: &str = "You are not allowed to get user";
const MESSAGE_UPDATE_USERS: &str = "You are not allowed to update users";
const MESSAGE_USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken. Please try another.";
const MESSAGE_USERNAME_TOO_SHORT: &str = "Username is too short";
const MESSAGE_USERNAME_TOO_LONG: &str = "Username is too long";
const MESSAGE_INVALID_USERNAME: &str = "Username is invalid";

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_string()),
            message: message.to_string(),
        },
    )
    .map_err(AuthError::from)
}

/// Admin plugin for user management operations.
pub struct AdminPlugin {
    config: AdminConfig,
}

/// Configuration for the admin plugin.
#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "AdminPlugin")]
pub struct AdminConfig {
    /// Default role assigned to new users and role-less permission checks.
    #[config(default = "user".to_string())]
    pub default_role: String,
    /// Roles treated as "admin" for target-admin checks such as impersonation.
    /// None uses the default admin role; explicit lists are validated at initialization.
    #[config(default = None)]
    pub admin_roles: Option<Vec<String>>,
    /// Users that always bypass admin permission checks.
    #[config(default = None)]
    pub admin_user_ids: Option<Vec<String>>,
    /// Custom role definitions. When provided, these replace the built-in
    /// `admin` and `user` role permissions. None uses builtins; Some(empty) grants none.
    #[config(default = None)]
    pub roles: Option<HashMap<String, access::RolePermissions>>,
    /// Default reason applied when banning a user without an explicit reason.
    #[config(default = None)]
    pub default_ban_reason: Option<String>,
    /// Default ban duration in seconds, including fractions; zero/NaN act as unset.
    #[config(default = None)]
    pub default_ban_expires_in: Option<f64>,
    /// Custom impersonation lifetime in seconds, including fractions; zero/NaN use one hour.
    #[config(default = None)]
    pub impersonation_session_duration: Option<f64>,
    /// Message surfaced to banned users.
    #[config(default = "You have been banned from this application. Please contact support if you believe this is an error.".to_string())]
    pub banned_user_message: String,
    /// Optional asynchronous message callback over the stored application user.
    /// When configured, this takes precedence over `banned_user_message`.
    #[config(skip, default = None)]
    pub banned_user_message_callback: Option<AdminBannedUserMessageHandler>,
    /// Whether other admin users may be impersonated.
    #[config(default = false)]
    pub allow_impersonating_admins: bool,
}

better_auth_core::impl_auth_plugin! {
    AdminPlugin, "admin";
    routes {
        post "/admin/set-role" => handle_set_role, "admin_set_role";
        get  "/admin/get-user" => handle_get_user, "admin_get_user";
        post "/admin/create-user" => handle_create_user, "admin_create_user";
        post "/admin/update-user" => handle_update_user, "admin_update_user";
        get  "/admin/list-users" => handle_list_users, "admin_list_users";
        post "/admin/list-user-sessions" => handle_list_user_sessions, "admin_list_user_sessions";
        post "/admin/ban-user" => handle_ban_user, "admin_ban_user";
        post "/admin/unban-user" => handle_unban_user, "admin_unban_user";
        post "/admin/impersonate-user" => handle_impersonate_user, "admin_impersonate_user";
        post "/admin/stop-impersonating" => handle_stop_impersonating, "admin_stop_impersonating";
        post "/admin/revoke-user-session" => handle_revoke_user_session, "admin_revoke_user_session";
        post "/admin/revoke-user-sessions" => handle_revoke_user_sessions, "admin_revoke_user_sessions";
        post "/admin/remove-user" => handle_remove_user, "admin_remove_user";
        post "/admin/set-user-password" => handle_set_user_password, "admin_set_user_password";
        post "/admin/has-permission" => handle_has_permission, "admin_has_permission";
    }
    extra {
        fn session_fields(&self) -> better_auth_core::field_policy::FieldConfigs {
            [("impersonatedBy".into(), better_auth_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})).read_only())].into_iter().collect()
        }

        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> better_auth_core::AuthResult<()> {
            if let Some(admin_roles) = &self.config.admin_roles {
                let roles = self.config.roles.clone().unwrap_or_else(access::default_roles);
                let names: Vec<_> = roles.keys().map(|name| name.to_lowercase()).collect();
                let invalid: Vec<_> = admin_roles.iter()
                    .filter(|role| !names.contains(&role.to_lowercase()))
                    .map(String::as_str).collect();
                if !invalid.is_empty() {
                    return Err(AuthError::config(format!(
                        "Invalid admin roles: {}. Admin roles must be defined in the 'roles' configuration.",
                        invalid.join(", ")
                    )));
                }
            }
            if let Some(handler) = &self.config.banned_user_message_callback {
                handler.validate::<S::User>()?;
                ctx.extensions.insert(BannedUserMessagePolicy(handler.clone()));
            }
            let default_role = self.config.default_role.clone();
            ctx.register_user_create_transform(move |mut input| {
                _ = input.banned.get_or_insert(false);
                _ = input.role.get_or_insert_with(|| default_role.clone());
                Ok(input)
            });
            ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));
            ctx.set_metadata(
                "admin.default_role",
                serde_json::Value::String(self.config.default_role.clone()),
            );
            ctx.set_metadata(
                "admin.banned_user_message",
                serde_json::Value::String(self.config.banned_user_message.clone()),
            );
            Ok(())
        }
    }
}

impl AdminPlugin {
    /// Configure an awaited message callback over the exact stored user entity.
    #[must_use]
    pub fn banned_user_message_callback<U: AuthUser, H: AdminBannedUserMessage<U>>(
        mut self,
        handler: H,
    ) -> Self {
        self.config.banned_user_message_callback =
            Some(AdminBannedUserMessageHandler::new::<U, H>(handler));
        self
    }

    async fn require_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<(UserView, SessionView)>> {
        match ctx.require_session(req).await {
            Ok((user, session)) => Ok(Some((UserView::from(&user), SessionView::from(&session)))),
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn missing_session_response() -> AuthResponse {
        AuthResponse::new(401).with_header("Content-Type", "application/json")
    }

    fn authorize(
        &self,
        user: &UserView,
        resource: &str,
        action: &str,
        message: &str,
    ) -> AuthResult<()> {
        let permissions = HashMap::from([(resource.to_string(), vec![action.to_string()])]);
        if has_permission(
            Some(user.id.as_str()),
            user.role.as_deref(),
            &self.config,
            &permissions,
        ) {
            Ok(())
        } else {
            Err(AuthError::forbidden(message))
        }
    }

    async fn handle_set_role(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SetRoleRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "set-role", MESSAGE_CHANGE_ROLE)?;
        let response = set_role_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_get_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let query = match validation::get_user(req) {
            Ok(query) => query,
            Err(response) => return Ok(response),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "get", MESSAGE_GET_USER)?;
        let response = get_user_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_create_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: CreateUserRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "create", MESSAGE_CREATE_USERS)?;
        // The source checks presence after nullish body/data precedence; empty
        // strings/arrays still request role authority. Validate nested types later.
        if body.role.is_some()
            || body
                .data
                .as_ref()
                .is_some_and(|data| data.contains_key("role"))
        {
            self.authorize(&user, "user", "set-role", MESSAGE_CHANGE_ROLE)?;
        }
        let response = create_user_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut body: AdminUpdateUserRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "update", MESSAGE_UPDATE_USERS)?;
        let username = body
            .data
            .remove("username")
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .map(|value| value.to_lowercase());
        let display_username = body
            .data
            .remove("displayUsername")
            .and_then(|value| value.as_str().map(ToOwned::to_owned));

        if let Some(username) = username.as_deref() {
            match validate_username(username) {
                Ok(()) => {}
                Err(UsernameValidationError::TooShort) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_SHORT",
                        MESSAGE_USERNAME_TOO_SHORT,
                    );
                }
                Err(UsernameValidationError::TooLong) => {
                    return username_error_response(
                        400,
                        "USERNAME_IS_TOO_LONG",
                        MESSAGE_USERNAME_TOO_LONG,
                    );
                }
                Err(UsernameValidationError::Invalid) => {
                    return username_error_response(
                        400,
                        "USERNAME_IS_INVALID",
                        MESSAGE_INVALID_USERNAME,
                    );
                }
            }

            if let Some(existing_user) = ctx.database.get_user_by_username(username).await?
                && AuthUser::id(&existing_user).as_ref() != body.user_id
            {
                return username_error_response(
                    400,
                    "USERNAME_IS_ALREADY_TAKEN",
                    MESSAGE_USERNAME_IS_ALREADY_TAKEN,
                );
            }
        }

        if let Some(username) = username {
            _ = body
                .data
                .insert("username".to_string(), serde_json::Value::String(username));
        }
        if let Some(display_username) = display_username {
            _ = body.data.insert(
                "displayUsername".to_string(),
                serde_json::Value::String(display_username),
            );
        }

        let response = update_user_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_users(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validation::list_users(req) {
            return Ok(response);
        }
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "list", MESSAGE_LIST_USERS)?;
        let query = ListUsersQueryParams {
            limit: req.query.get("limit").and_then(|value| value.parse().ok()),
            offset: req.query.get("offset").and_then(|value| value.parse().ok()),
            search_field: req.query.get("searchField").cloned(),
            search_value: req.query.get("searchValue").cloned(),
            search_operator: req.query.get("searchOperator").cloned(),
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
            filter_field: req.query.get("filterField").cloned(),
            filter_value: req.query.get("filterValue").cloned(),
            filter_operator: req.query.get("filterOperator").cloned(),
        };
        let response = list_users_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "session", "list", MESSAGE_LIST_USER_SESSIONS)?;
        let response = list_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_ban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: BanUserRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
        let response = match ban_user_core(&body, user.id.as_str(), &self.config, ctx).await {
            Ok(response) => response,
            Err(AdminDateOperationError::InvalidDate) => return Ok(AuthResponse::new(500)),
            Err(AdminDateOperationError::Auth(error)) => return Err(error),
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_unban_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "ban", MESSAGE_BAN_USERS)?;
        let response = unban_user_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_impersonate_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "impersonate", MESSAGE_IMPERSONATE_USERS)?;
        let (response, token) = match impersonate_user_core(
            &body,
            user.id.as_str(),
            req.headers
                .get("x-forwarded-for")
                .map(|value| value.as_str()),
            req.headers.get("user-agent").map(|value| value.as_str()),
            &self.config,
            ctx,
        )
        .await
        {
            Ok(response) => response,
            Err(AdminDateOperationError::InvalidDate) => return Ok(AuthResponse::new(500)),
            Err(AdminDateOperationError::Auth(error)) => return Err(error),
        };
        let dont_remember = get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember"))
            .and_then(|value| {
                better_auth_core::utils::cookie_utils::verify_cookie_value(
                    &value,
                    &ctx.config.secret,
                )
            })
            .is_some_and(|value| !value.is_empty());
        let admin_cookie = create_admin_session_cookie_value(
            &ctx.config.secret,
            &AdminSessionCookiePayload {
                session_token: session.token.clone(),
                dont_remember,
            },
            ctx.config.session.expires_in,
        )?;
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");

        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in delete_session_cookie_headers(&ctx.config) {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &admin_cookie_name,
                &admin_cookie,
                Some(ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            ),
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(Some(&token), None, &ctx.config),
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(&ctx.config, "dont_remember"),
                &better_auth_core::utils::cookie_utils::sign_cookie_value(
                    "true",
                    &ctx.config.secret,
                ),
                None,
                &ctx.config,
            ),
        );
        Ok(auth_response)
    }

    async fn handle_stop_impersonating(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validation::parse(req) {
            return Ok(response);
        }
        let Some((_, session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        if session.impersonated_by.is_none() {
            return Err(AuthError::bad_request("You are not impersonating anyone"));
        }

        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        let admin_cookie_value = get_cookie(req, &admin_cookie_name)
            .ok_or_else(|| AuthError::internal("Failed to find admin session"))?;
        let admin_cookie =
            decode_admin_session_cookie_value(&ctx.config.secret, &admin_cookie_value)
                .map_err(|_| AuthError::internal("Failed to find admin session"))?;

        let (response, new_token) = stop_impersonating_core(&session, &admin_cookie, ctx).await?;

        let mut auth_response = AuthResponse::json(200, &response)?;
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(&new_token),
                if admin_cookie.dont_remember {
                    None
                } else {
                    Some(ctx.config.session.expires_in.num_seconds())
                },
                &ctx.config,
            ),
        );
        if admin_cookie.dont_remember {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &related_cookie_name(&ctx.config, "dont_remember"),
                    &better_auth_core::utils::cookie_utils::sign_cookie_value(
                        "true",
                        &ctx.config.secret,
                    ),
                    None,
                    &ctx.config,
                ),
            );
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_clear_cookie(&admin_cookie_name, &ctx.config),
        );
        Ok(auth_response)
    }

    async fn handle_revoke_user_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: RevokeSessionRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "session", "revoke", MESSAGE_REVOKE_USER_SESSIONS)?;
        let response = revoke_user_session_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_revoke_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "session", "revoke", MESSAGE_REVOKE_USER_SESSIONS)?;
        let response = revoke_user_sessions_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_remove_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "delete", MESSAGE_DELETE_USERS)?;
        let response = remove_user_core(&body, user.id.as_str(), ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_set_user_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SetUserPasswordRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "set-password", MESSAGE_SET_USER_PASSWORD)?;
        let response = set_user_password_core(&body, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_has_permission(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: HasPermissionRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        if body.permissions.is_none() {
            return AuthResponse::json(400, &serde_json::json!({"message":"invalid permission check. no permission(s) were passed."})).map_err(AuthError::from);
        }
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        let response = has_permission_core(&body, &user, &self.config)?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }
}

pub(super) fn target_is_admin(
    user_id: Option<&str>,
    role: Option<&str>,
    config: &AdminConfig,
) -> bool {
    is_admin_user_id(user_id, config) || is_admin_role(role, config)
}

pub use access::RolePermissions;
