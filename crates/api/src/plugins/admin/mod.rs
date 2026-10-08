pub mod access;

mod callbacks;

pub(super) mod handlers;

pub(super) mod types;

mod validation;

use crate::plugins::helpers::{delete_session_cookie_headers, get_cookie};
pub use access::RolePermissions;
use access::{has_permission, is_admin_role, is_admin_user_id};
use alibi_core::entity::AuthUser;
use alibi_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name,
};
use alibi_core::utils::username::{UsernameValidationError, validate_username};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, ErrorCodeMessageResponse,
};
pub(in crate::plugins) use callbacks::BannedUserMessagePolicy;
pub use callbacks::{AdminBannedUserMessage, AdminBannedUserMessageHandler};
use handlers::AdminDateOperationError;
use handlers::{
    AdminSessionCookiePayload, ban_user_core, create_admin_session_cookie_value, create_user_core,
    decode_admin_session_cookie_value, get_user_core, has_permission_core, impersonate_user_core,
    list_user_sessions_core, list_users_core, remove_user_core, revoke_user_session_core,
    revoke_user_sessions_core, set_role_core, set_user_password_core, stop_impersonating_core,
    unban_user_core, update_user_core,
};
use std::collections::HashMap;
use types::{
    AdminUpdateUserRequest, BanUserRequest, CreateUserRequest, HasPermissionRequest,
    ListUsersQueryParams, RevokeSessionRequest, SetRoleRequest, SetUserPasswordRequest,
    UserIdRequest,
};

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

/// Admin plugin for user management operations.
pub struct AdminPlugin {
    config: AdminConfig,
}

/// Configuration for the admin plugin.
#[derive(Debug, Clone, alibi_core::PluginConfig)]
#[plugin(name = "AdminPlugin")]
pub struct AdminConfig {
    /// Default role assigned to new users and role-less permission checks.
    #[config(default = "user".to_owned())]
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
    pub roles: Option<HashMap<String, RolePermissions>>,
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
    #[config(default = "You have been banned from this application. Please contact support if you believe this is an error.".to_owned())]
    pub banned_user_message: String,
    /// Optional asynchronous message callback over the stored application user.
    /// When configured, this takes precedence over `banned_user_message`.
    #[config(skip, default = None)]
    pub banned_user_message_callback: Option<AdminBannedUserMessageHandler>,
    /// Whether other admin users may be impersonated.
    #[config(default = false)]
    pub allow_impersonating_admins: bool,
}

alibi_core::impl_auth_plugin! {
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
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }

        fn session_fields(&self) -> alibi_core::field_policy::FieldConfigs {
            std::iter::once(("impersonatedBy".into(), alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})).read_only())).collect()
        }

        async fn on_init(
            &self,
            ctx: &mut alibi_core::AuthInitContext<S>,
        ) -> AuthResult<()> {
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
            let validation_enabled = ctx.config.user_validation.is_some();
            ctx.register_user_create_transform(move |mut input| {
                if !validation_enabled {_ = input.banned.get_or_insert(false);}
                _ = input.role.get_or_insert_with(|| default_role.clone());
                Ok(input)
            });
            if validation_enabled {ctx.register_user_creation_adapter_default(|mut input| {
                _ = input.banned.get_or_insert(false); Ok(input)
            });}
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<Option<(UserView, SessionView)>> {
        match ctx.require_authoritative_session(req).await {
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
        let permissions = HashMap::from([(resource.to_owned(), vec![action.to_owned()])]);
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
            drop(
                body.data
                    .insert("username".to_owned(), serde_json::Value::String(username)),
            );
        }
        if let Some(display_username) = display_username {
            drop(body.data.insert(
                "displayUsername".to_owned(),
                serde_json::Value::String(display_username),
            ));
        }

        let response = update_user_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_users(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
            filter_value: req.query_values("filterValue").map(|values| match values {
                [value] => alibi_core::UserFilterValue::Scalar(value.clone()),
                values => alibi_core::UserFilterValue::Multiple(values.to_vec()),
            }),
            filter_operator: req.query.get("filterOperator").cloned(),
        };
        let response = list_users_core(&query, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_list_user_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: UserIdRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "impersonate", MESSAGE_IMPERSONATE_USERS)?;
        let metadata = alibi_core::RequestMeta::from_request(req);
        let (response, token) = match impersonate_user_core(
            &body,
            user.id.as_str(),
            user.role.as_deref(),
            metadata.ip_address.as_deref(),
            metadata.user_agent.as_deref(),
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
                alibi_core::utils::cookie_utils::verify_cookie_value(
                    &value,
                    ctx.config.current_secret(),
                )
            })
            .is_some_and(|value| !value.is_empty());
        let admin_cookie = create_admin_session_cookie_value(
            ctx.config.current_secret(),
            &AdminSessionCookiePayload {
                session_token: session.token.clone(),
                dont_remember,
            },
            ctx.config.session.expires_in,
        )?;
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");

        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in delete_session_cookie_headers(&ctx.config)? {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &admin_cookie_name,
                &admin_cookie,
                Some(ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            )?,
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(Some(&token), None, &ctx.config)?,
        );
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(&ctx.config, "dont_remember"),
                &alibi_core::utils::cookie_utils::sign_cookie_value(
                    "true",
                    ctx.config.current_secret(),
                ),
                None,
                &ctx.config,
            )?,
        );
        Ok(auth_response)
    }

    async fn handle_stop_impersonating(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validation::parse(req) {
            return Ok(response);
        }
        let session = match ctx.require_cached_session(req).await {
            Ok((_, session)) => session,
            Err(AuthError::Unauthenticated) => return Ok(Self::missing_session_response()),
            Err(error) => return Err(error),
        };
        if session.impersonated_by.is_none() {
            return Err(AuthError::bad_request("You are not impersonating anyone"));
        }

        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        let admin_cookie_value =
            get_cookie(req, &admin_cookie_name).ok_or_else(|| AuthError::Api {
                status: 500,
                code: None,
                message: "Failed to find admin session".into(),
            })?;
        let admin_cookie =
            decode_admin_session_cookie_value(ctx.config.current_secret(), &admin_cookie_value)
                .map_err(|_error| AuthError::Api {
                    status: 500,
                    code: None,
                    message: "Failed to find admin session".into(),
                })?;

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
            )?,
        );
        if admin_cookie.dont_remember {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &related_cookie_name(&ctx.config, "dont_remember"),
                    &alibi_core::utils::cookie_utils::sign_cookie_value(
                        "true",
                        ctx.config.current_secret(),
                    ),
                    None,
                    &ctx.config,
                )?,
            );
        }
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            create_clear_cookie(&admin_cookie_name, &ctx.config)?,
        );
        Ok(auth_response)
    }

    async fn handle_revoke_user_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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

impl std::fmt::Debug for AdminPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminPlugin").finish_non_exhaustive()
    }
}

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_owned()),
            message: message.to_owned(),
        },
    )
    .map_err(AuthError::from)
}

pub(super) fn target_is_admin(
    user_id: Option<&str>,
    role: Option<&str>,
    config: &AdminConfig,
) -> bool {
    is_admin_user_id(user_id, config) || is_admin_role(role, config)
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use alibi_core::entity::{AuthAccount, AuthSession};
    use alibi_core::utils::cookie_utils::related_cookie_name;
    use alibi_core::wire::{SessionView, UserView};
    use alibi_core::{AuthPlugin, CreateSession, CreateUser, HttpMethod};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn create_admin_context() -> (
        AuthContext<TestSchema>,
        UserView,
        SessionView,
        UserView,
        SessionView,
    ) {
        let ctx = test_helpers::create_test_context().await;

        let admin = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("admin@example.com")
                .with_name("Admin")
                .with_role("admin"),
        )
        .await;
        let admin_session =
            test_helpers::create_session(&ctx, admin.id.clone(), Duration::hours(24)).await;

        let user = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("user@example.com")
                .with_name("Regular User")
                .with_role("user"),
        )
        .await;
        let user_session =
            test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

        (ctx, admin, admin_session, user, user_session)
    }

    fn make_request(
        method: HttpMethod,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        test_helpers::create_auth_json_request_no_query(method, path, Some(token), body)
    }

    fn json_body(resp: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&resp.body).unwrap()
    }

    fn set_cookie_value(resp: &AuthResponse, name: &str) -> Option<String> {
        resp.headers.get_all("Set-Cookie").find_map(|header| {
            let (cookie_name, remainder) = header.split_once('=')?;
            if cookie_name != name {
                return None;
            }
            Some(remainder.split(';').next().unwrap_or_default().to_owned())
        })
    }

    #[tokio::test]
    async fn test_custom_admin_role_can_use_permission_engine() {
        let config = Arc::new(alibi_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = test_helpers::create_test_database().await;
        let ctx = AuthContext::new(config, Arc::clone(&database));

        let admin = database
            .create_user(
                CreateUser::new()
                    .with_email("superadmin@example.com")
                    .with_name("Super Admin")
                    .with_role("superadmin"),
            )
            .await
            .unwrap();

        let admin_session = database
            .create_session(CreateSession {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                token: None,
                active_team_id: None,
                user_id: admin.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        let _user = database
            .create_user(
                CreateUser::new()
                    .with_email("user@example.com")
                    .with_name("User")
                    .with_role("user"),
            )
            .await
            .unwrap();

        let plugin = AdminPlugin::with_config(AdminConfig {
            admin_roles: Some(vec!["superadmin".to_owned()]),
            roles: Some(HashMap::from([(
                "superadmin".to_owned(),
                RolePermissions::new()
                    .allow(
                        "user",
                        [
                            "create",
                            "list",
                            "set-role",
                            "ban",
                            "impersonate",
                            "delete",
                            "set-password",
                            "get",
                            "update",
                        ],
                    )
                    .allow("session", ["list", "revoke", "delete"]),
            )])),
            ..Default::default()
        });

        let req = make_request(
            HttpMethod::Get,
            "/admin/list-users",
            &admin_session.token,
            None,
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            (*(json_body(&resp))
                .get("total")
                .unwrap_or(&serde_json::Value::Null)),
            2
        );
    }

    #[tokio::test]
    async fn test_ban_revokes_user_sessions() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_ne!(sessions.len(), 0);

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banReason": "bad behavior"
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);

        let sessions_2 = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(sessions_2.len(), 0);
    }

    #[tokio::test]
    async fn test_unban_clears_ban_reason_and_expires() {
        let (ctx, _admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/ban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
                "banReason": "spam",
                "banExpiresIn": 3600
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status, 200);

        let req_2 = make_request(
            HttpMethod::Post,
            "/admin/unban-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(resp_2.status, 200);

        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_user.banned, Some(false));
        assert!(updated_user.ban_reason.is_none());
        assert!(updated_user.ban_expires.is_none());
    }

    #[tokio::test]
    async fn test_impersonation_session_tracks_admin_id() {
        let (ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );

        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        assert!(
            set_cookie_value(&resp, &admin_cookie_name).is_some(),
            "impersonation should emit an admin_session cookie"
        );
        let token = (*(*(json_body(&resp))
            .get("session")
            .unwrap_or(&serde_json::Value::Null))
        .get("token")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned();
        let session = ctx.database.get_session(&token).await.unwrap().unwrap();

        assert_eq!(session.impersonated_by().unwrap(), admin.id);
    }

    #[tokio::test]
    async fn test_stop_impersonating_restores_admin_session() {
        let (mut ctx, admin, admin_session, user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();
        let mut init =
            alibi_core::AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        plugin.on_init(&mut init).await.unwrap();
        ctx.metadata.extend(init.into_parts().metadata);

        let req = make_request(
            HttpMethod::Post,
            "/admin/impersonate-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user.id,
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let impersonation_token = (*(*(json_body(&resp))
            .get("session")
            .unwrap_or(&serde_json::Value::Null))
        .get("token")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned();
        let admin_cookie_name = related_cookie_name(&ctx.config, "admin_session");
        let admin_cookie = set_cookie_value(&resp, &admin_cookie_name)
            .expect("impersonation should set the admin_session cookie");

        let mut req_2 = make_request(
            HttpMethod::Post,
            "/admin/stop-impersonating",
            &impersonation_token,
            None,
        );
        req_2.headers.insert(
            "cookie".to_owned(),
            format!(
                "{}; {admin_cookie_name}={admin_cookie}",
                req_2
                    .headers
                    .get("cookie")
                    .expect("impersonated browser has a signed session cookie")
            ),
        );
        let resp_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        let body = json_body(&resp_2);

        let restored_token = (*(*(body).get("session").unwrap_or(&serde_json::Value::Null))
            .get("token")
            .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap();
        assert_eq!(
            restored_token, admin_session.token,
            "stop-impersonating should restore the original admin session token"
        );
        let restored_session = ctx
            .database
            .get_session(restored_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored_session.user_id, admin.id);
        assert!(restored_session.impersonated_by.is_none());
        assert!(
            ctx.database
                .get_session(&impersonation_token)
                .await
                .unwrap()
                .is_none()
        );
        let cleared_admin_cookie = resp_2
            .headers
            .get_all("Set-Cookie")
            .find(|header| header.starts_with(&format!("{admin_cookie_name}=")))
            .expect("stop-impersonating should clear admin_session");
        assert!(
            cleared_admin_cookie.contains("Max-Age=0"),
            "admin_session should be cleared after stop-impersonating"
        );
    }

    #[tokio::test]
    async fn test_list_user_sessions_missing_user_returns_empty_array() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/list-user-sessions",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "missing-user",
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(json_body(&resp), serde_json::json!({ "sessions": [] }));
    }

    #[tokio::test]
    async fn test_revoke_user_sessions_missing_user_still_succeeds() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/revoke-user-sessions",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": "missing-user",
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(json_body(&resp), serde_json::json!({ "success": true }));
    }

    #[tokio::test]
    async fn test_stop_impersonating_without_impersonated_session_returns_bad_request() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/stop-impersonating",
            &admin_session.token,
            None,
        );
        let err = plugin.on_request(&req, &ctx).await.unwrap_err();
        let response = err.to_auth_response();
        assert_eq!(response.status, 400);
        assert_eq!(
            json_body(&response),
            serde_json::json!({
                // Upstream throws this via `APIError.fromStatus`, which carries no
                // code — only errors built from a code constant have one.
                "message": "You are not impersonating anyone"
            })
        );
    }

    #[tokio::test]
    async fn test_remove_user_cleans_up_sessions_and_accounts() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "tobedeleted@example.com",
                "password": "securepassword123",
                "name": "To Be Deleted"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let user_id = (*(*(json_body(&resp))
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned();

        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);

        let req_2 = make_request(
            HttpMethod::Post,
            "/admin/remove-user",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
            })),
        );
        let resp_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(resp_2.status, 200);

        assert!(
            ctx.database
                .get_user_by_id(&user_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ctx.database
                .get_user_accounts(&user_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn test_set_user_password_updates_credential_account() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "pwuser@example.com",
                "password": "oldpassword123",
                "name": "PW User"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let user_id = (*(*(json_body(&resp))
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned();

        let before = ctx.database.get_user_accounts(&user_id).await.unwrap();
        let old_password = (*(before)
            .first()
            .expect("persisted rows contain the requested index"))
        .password()
        .unwrap()
        .to_owned();

        let req_2 = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
                "newPassword": "newpassword456"
            })),
        );
        let resp_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(resp_2.status, 200);

        let after = ctx.database.get_user_accounts(&user_id).await.unwrap();
        let new_password = (*(after)
            .first()
            .expect("persisted rows contain the requested index"))
        .password()
        .unwrap()
        .to_owned();
        assert_ne!(old_password, new_password);
    }

    #[tokio::test]
    async fn test_set_user_password_creates_canonical_credential_when_missing() {
        let (ctx, _admin, admin_session, _user, _user_session) = create_admin_context().await;
        let plugin = AdminPlugin::new();

        let req = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(serde_json::json!({
                "email": "passwordless@example.com",
                "name": "Passwordless User"
            })),
        );
        let resp = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        let user_id = (*(*(json_body(&resp))
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned();

        let req_2 = make_request(
            HttpMethod::Post,
            "/admin/set-user-password",
            &admin_session.token,
            Some(serde_json::json!({
                "userId": user_id,
                "newPassword": "newpassword456"
            })),
        );
        let resp_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(resp_2.status, 200);

        let accounts = ctx.database.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        let account = accounts
            .first()
            .expect("password setting creates a credential");
        assert_eq!(account.user_id(), user_id);
        assert_eq!(account.account_id(), user_id);
        assert_eq!(account.provider_id(), "credential");
        assert!(
            alibi_core::PasswordHasher::verify(
                &alibi_core::ScryptHasher,
                account.password().unwrap(),
                "newpassword456",
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn admin_creation_stores_application_metadata_without_reserved_role_input() {
        let (ctx, admin, admin_session, _other, other_session) = create_admin_context().await;
        let expected = serde_json::json!({"preferences":{"theme":"night","nested":{"$serde_json::private::RawValue":"literal"}}});
        let request = make_request(
            HttpMethod::Post,
            "/admin/create-user",
            &admin_session.token,
            Some(
                serde_json::json!({"email":"metadata-user@fixture.test","name":"Metadata user","data":{"role":"user","preferences":expected.get("preferences").unwrap()}}),
            ),
        );
        let response = AdminPlugin::new()
            .on_request(&request, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        let created = ctx
            .database
            .get_user_by_email("metadata-user@fixture.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created.role(), Some("user"));
        assert_eq!(created.metadata(), &expected);
        assert_eq!(
            json_body(&response)
                .get("user")
                .and_then(|user| user.get("id"))
                .and_then(serde_json::Value::as_str),
            Some(created.id.as_str())
        );
        assert!(
            ctx.database
                .get_session(&admin_session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            ctx.database
                .get_session(&other_session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&admin.id)
                .await
                .unwrap()
                .unwrap()
                .role(),
            Some("admin")
        );
    }
}
// LCOV_EXCL_STOP
