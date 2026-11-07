pub mod access;

mod callbacks;
mod cookies;
mod endpoint;
mod listing;

pub(super) mod handlers;

pub(super) mod types;

mod validation;

pub use access::{
    DEFAULT_STATEMENTS, RolePermissions, admin_role, default_ac, default_roles, user_role,
};
use access::{has_permission, is_admin_role, is_admin_user_id};
use alibi_core::entity::AuthUser;
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult};
pub(crate) use callbacks::BannedUserMessagePolicy;
pub use callbacks::{AdminBannedUserMessage, AdminBannedUserMessageHandler};
use handlers::AdminDateOperationError;
use handlers::{
    ban_user_core, create_user_core, get_user_core, has_permission_core, impersonate_user_core,
    list_user_sessions_core, list_users_core, remove_user_core, revoke_user_session_core,
    revoke_user_sessions_core, set_role_core, set_user_password_core, stop_impersonating_core,
    unban_user_core, update_user_core,
};
use std::collections::HashMap;
pub use types::{
    AdminListUsersQuery, AdminUpdateUserRequest, AdminUserView as AdminUserOutput,
    BanUserRequest as AdminBanUserRequest, CreateUserRequest as AdminCreateUserRequest,
    HasPermissionRequest as AdminPermissionRequest, PermissionResponse as AdminPermissionResponse,
    RoleInput as AdminRoleInput, SetRoleRequest as AdminSetRoleRequest,
    SetUserPasswordRequest as AdminSetUserPasswordRequest, SuccessResponse as AdminSuccessResponse,
};
/// Stored session and safe user returned by an administrative session operation.
pub type AdminImpersonationResponse =
    types::SessionUserResponse<alibi_core::wire::SessionView, alibi_core::wire::UserView>;
/// Safe user result returned by admin mutation operations.
pub type AdminUserResponse = types::UserResponse<AdminUserOutput>;
/// Safe user page returned by the listUsers server operation.
pub type AdminListUsersResponse = types::ListUsersResponse<AdminUserOutput>;
/// Session page returned by the admin listUserSessions server operation.
pub type AdminUserSessionsResponse = types::ListSessionsResponse<alibi_core::wire::SessionView>;
use types::{
    BanUserRequest, CreateUserRequest, HasPermissionRequest, ListUsersQueryParams,
    RevokeSessionRequest, SetRoleRequest, SetUserPasswordRequest, UserIdRequest,
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
    /// Start from [`default_roles`] and extend [`admin_role`] to retain built-in grants.
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
    route_openapi_metadata!(S);

        fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> { endpoint::definitions() }
        fn validate_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, _: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointInput> { endpoint::validate(call) }
        async fn on_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, ctx: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointResponse> { self.call_admin_endpoint(call, ctx).await }

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
            ctx.register_session_created_hook(std::sync::Arc::new(AdminSessionGuard));
            ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));
            ctx.set_metadata("admin.impersonation_session_duration", serde_json::json!(self.config.impersonation_session_duration.unwrap_or(3600.0)));
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

fn ban_expired_at(
    user: &impl alibi_core::AuthUser,
    now: chrono::DateTime<chrono::Utc>,
) -> AuthResult<bool> {
    if let Some(value) = user
        .adapter_snapshot()
        .and_then(|output| output.values().get("banExpires"))
        .or_else(|| {
            user.retained_user_view()
                .and_then(|view| view.extension_fields.get("banExpires"))
        })
    {
        if !alibi_core::utils::json::JsValue::from(value.clone()).is_truthy() {
            return Ok(false);
        }
        let millis = match value {
            alibi_core::utils::json::JsValue::Date(value) => Some(value.timestamp_millis() as f64),
            alibi_core::utils::json::JsValue::Number(value) => Some(*value)
                .filter(|value| value.abs() <= 8_640_000_000_000_000.0)
                .map(f64::trunc),
            alibi_core::utils::json::JsValue::Bool(value) => Some(f64::from(u8::from(*value))),
            alibi_core::utils::json::JsValue::String(value) => value
                .as_str()
                .and_then(alibi_core::utils::datetime::parse_date_millis)
                .map(|value| value as f64),
            alibi_core::utils::json::JsValue::Array(_)
            | alibi_core::utils::json::JsValue::Object(_) => value
                .coerce_js_string()
                .map_err(AuthError::internal)?
                .as_str()
                .and_then(alibi_core::utils::datetime::parse_date_millis)
                .map(|value| value as f64),
            _ => None,
        };
        return Ok(millis.is_some_and(|value| value < now.timestamp_millis() as f64));
    }
    Ok(user.ban_expires().is_some_and(|expiry| expiry < now))
}

struct AdminSessionGuard;

#[async_trait::async_trait]
impl<S: alibi_core::AuthSchema> alibi_core::store::SessionCreatedHook<S> for AdminSessionGuard {
    async fn before_create(
        &self,
        input: &alibi_core::CreateSession,
        ctx: &AuthContext<S>,
        transaction: Option<&dyn alibi_core::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let user = match transaction {
            Some(transaction) => transaction.get_user_by_id_record(&input.user_id).await?,
            None => ctx.database.get_user_by_id_record(&input.user_id).await?,
        };
        let Some(user) = user else {
            return Ok(());
        };
        if !user.banned() {
            return Ok(());
        }
        if ban_expired_at(&user, chrono::Utc::now())? {
            let update = alibi_core::UpdateUser {
                banned: Some(false),
                clear_ban_reason: true,
                ban_expires: Some(None),
                ..Default::default()
            };
            _ = match transaction {
                Some(transaction) => {
                    transaction
                        .update_user_record(&input.user_id, update)
                        .await?
                }
                None => {
                    ctx.database
                        .update_user_record(&input.user_id, update)
                        .await?
                }
            };
            return Ok(());
        }
        Err(AuthError::banned_user(
            crate::helpers::resolve_admin_banned_user_message(ctx, &user).await?,
        ))
    }

    async fn after_create(
        &self,
        _: &S::Session,
        _: &dyn alibi_core::AuthStore<S>,
    ) -> AuthResult<()> {
        Ok(())
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
        match ctx.require_authoritative_cached_session(req).await {
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

    fn authorize_create_user(&self, user: &UserView, body: &CreateUserRequest) -> AuthResult<()> {
        self.authorize(user, "user", "create", MESSAGE_CREATE_USERS)?;
        // The source checks presence after nullish body/data precedence; empty
        // strings/arrays still request role authority. Validate nested types later.
        if body.role.is_some()
            || body
                .data
                .as_ref()
                .is_some_and(|data| data.contains_key("role"))
        {
            self.authorize(user, "user", "set-role", MESSAGE_CHANGE_ROLE)?;
        }
        if body.data.as_ref().is_some_and(|data| {
            ["banned", "banReason", "banExpires"]
                .iter()
                .any(|key| data.contains_key(*key))
        }) {
            self.authorize(user, "user", "ban", MESSAGE_BAN_USERS)?;
        }
        Ok(())
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
        self.authorize_create_user(&user, &body)?;
        let response = create_user_core(&body, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: AdminUpdateUserRequest = match validation::body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let Some((user, _session)) = self.require_session(req, ctx).await? else {
            return Ok(Self::missing_session_response());
        };
        self.authorize(&user, "user", "update", MESSAGE_UPDATE_USERS)?;
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
            source_limit: req
                .query
                .get("limit")
                .and_then(|value| alibi_core::utils::javascript::string_to_number(value))
                .filter(|value| !value.is_nan() && *value != 0.0),
            source_offset: req
                .query
                .get("offset")
                .and_then(|value| alibi_core::utils::javascript::string_to_number(value))
                .filter(|value| !value.is_nan() && *value != 0.0),
            limit: req
                .query
                .get("limit")
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0),
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
        let (response, token) = match impersonate_user_core(
            &body,
            user.id.as_str(),
            user.role.as_deref(),
            req,
            &self.config,
            ctx,
        )
        .await
        {
            Ok(response) => response,
            Err(AdminDateOperationError::InvalidDate) => return Ok(AuthResponse::new(500)),
            Err(AdminDateOperationError::Auth(error)) => return Err(error),
        };
        let mut auth_response = AuthResponse::json(200, &response)?;
        for (name, value) in cookies::impersonation_cookie_headers(
            &ctx.config,
            &req.headers,
            &session.token,
            &token,
        )? {
            auth_response.headers.append(name, value);
        }
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
        if session.impersonated_by.as_deref().is_none_or(str::is_empty) {
            return Err(AuthError::bad_request("You are not impersonating anyone"));
        }

        let (response, token, dont_remember) = stop_impersonating_core(&session, req, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        for (name, value) in
            cookies::restoration_cookie_headers(&ctx.config, &token, dont_remember)?
        {
            auth_response.headers.append(name, value);
        }
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
    use crate::test_helpers;
    use alibi_core::entity::{AuthAccount, AuthSession};
    use alibi_core::utils::cookie_utils::related_cookie_name;
    use alibi_core::wire::{SessionView, UserView};
    use alibi_core::{AuthPlugin, CreateSession, CreateUser, HttpMethod};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    mod native_creation {
        use super::*;
        use alibi_core::UpdateUser;
        use chrono::Datelike;

        #[tokio::test]
        async fn native_username_lookup_observes_sqlite_affinity_and_current_transaction() {
            let (ctx, _, _, _, _) = create_admin_context().await;
            let mut input = alibi_core::CreateUser::new().with_email("raw-username@fixture.test");
            input
                .adapter_native_fields
                .insert("username".into(), serde_json::json!(42).into());
            let user = ctx.database.create_user(input).await.unwrap();
            let found = ctx
                .database
                .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(42.0))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                alibi_core::AuthUser::id(&found),
                alibi_core::AuthUser::id(&user)
            );
            for raw in [serde_json::json!([]), serde_json::json!({})] {
                assert!(
                    ctx.database
                        .get_user_by_username_value(&raw.into())
                        .await
                        .is_err()
                );
            }
            alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
                Box::pin(async move {
                    let mut input = alibi_core::CreateUser::new()
                        .with_email("transaction-username@fixture.test");
                    input
                        .adapter_native_fields
                        .insert("username".into(), serde_json::json!(73).into());
                    let created = tx.create_user(input).await?;
                    let found = tx
                        .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(73.0))
                        .await?
                        .unwrap();
                    assert_eq!(
                        alibi_core::AuthUser::id(&found),
                        alibi_core::AuthUser::id(&created)
                    );
                    Ok(())
                })
            })
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn false_ban_patch_preserves_omissions_and_honors_explicit_values() {
            let (ctx, admin, _, user, _) = create_admin_context().await;
            let expiry = chrono::DateTime::from_timestamp_millis(4_102_444_800_123).unwrap();
            ctx.database
                .update_user_record(
                    &user.id,
                    UpdateUser {
                        banned: Some(true),
                        ban_reason: Some("preserved".into()),
                        ban_expires: Some(Some(expiry)),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            for (data, reason, expected_expiry) in [
                (
                    serde_json::json!({"banned": false}),
                    Some("preserved"),
                    Some(expiry),
                ),
                (
                    serde_json::json!({"banned": false, "banReason": "replacement", "banExpires": "2099-01-01T00:00:00Z"}),
                    Some("replacement"),
                    Some(
                        chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    ),
                ),
                (
                    serde_json::json!({"banned": false, "banReason": null, "banExpires": null}),
                    None,
                    None,
                ),
            ] {
                handlers::update_user_core(
                    &types::AdminUpdateUserRequest::new(
                        &user.id,
                        data.as_object().unwrap().clone(),
                    ),
                    &admin,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                let stored = ctx
                    .database
                    .get_user_by_id_record(&user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!stored.banned());
                assert_eq!(stored.ban_reason(), reason);
                assert_eq!(stored.ban_expires(), expected_expiry);
            }
        }

        #[tokio::test]
        async fn admin_creation_native_scalar_affinity_and_nulls_are_persisted() {
            let (mut ctx, _, _, _, _) = create_admin_context().await;
            let init = alibi_core::plugin::AuthInitContext::new(
                Arc::clone(&ctx.config),
                Arc::clone(&ctx.database),
            );
            ctx.database = init.database_with_registered_transforms();
            let mut input = types::CreateUserRequest::new("raw-native@fixture.test", "Outer name");
            input.data = Some(
                serde_json::json!({
                    "id": "native-affinity-user",
                    "image": 42, "emailVerified": "not-a-boolean",
                    "displayUsername": false, "phoneNumber": 12345,
                    "lastLoginMethod": null, "banned": 2,
                    "twoFactorEnabled": "false", "isAnonymous": null,
                    "phoneNumberVerified": 1, "banReason": 7,
                    "banExpires": "2099-01-01", "createdAt": "2020-01-01"
                })
                .as_object()
                .unwrap()
                .clone(),
            );
            let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let response = serde_json::to_value(&created).unwrap();
            assert_eq!(response["user"]["id"], "native-affinity-user");
            assert_eq!(response["user"]["twoFactorEnabled"], "false");
            assert_eq!(response["user"]["banned"], false);
            assert_eq!(response["user"]["isAnonymous"], serde_json::Value::Null);
            let stored = ctx
                .database
                .get_user_by_id_record(&created.user.id)
                .await
                .unwrap()
                .unwrap();
            use alibi_core::entity::AuthUser as _;
            assert_eq!(stored.image(), Some("42"));
            assert_eq!(stored.display_username(), Some("0"));
            assert_eq!(stored.phone_number(), Some("12345"));
            assert_eq!(stored.ban_reason(), Some("7"));
            assert!(!stored.banned());
            assert_eq!(stored.created_at().year(), 2020);
            assert_eq!(stored.ban_expires().unwrap().year(), 2099);
            let values = stored.raw_snapshot().values();
            assert_eq!(values["emailVerified"], "not-a-boolean");
            assert_eq!(values["banned"], false);
            assert_eq!(values["twoFactorEnabled"], "false");
            assert_eq!(values["isAnonymous"], serde_json::Value::Null);
            assert_eq!(values["phoneNumberVerified"], true);

            let mut defaults =
                types::CreateUserRequest::new("raw-defaults@fixture.test", "Defaults");
            defaults.data = Some(
                serde_json::json!({
                    "emailVerified": null, "createdAt": null, "updatedAt": null,
                    "image": null, "banned": null, "twoFactorEnabled": null
                })
                .as_object()
                .unwrap()
                .clone(),
            );
            let created = handlers::create_user_core(&defaults, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let stored = ctx
                .database
                .get_user_by_id_record(&created.user.id)
                .await
                .unwrap()
                .unwrap();
            assert!(!stored.email_verified());
            assert_eq!(stored.image(), None);
            assert_eq!(
                stored.raw_snapshot().values()["banned"],
                serde_json::Value::Null
            );
        }

        #[tokio::test]
        async fn admin_creation_numeric_dates_keep_sqlite_date_affinity_and_raw_wire_values() {
            use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
            let database = Database::connect("sqlite::memory:").await.unwrap();
            alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
                .await
                .unwrap();
            let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
                test_helpers::create_test_config(),
                database.clone(),
            ));
            let ctx = AuthContext::new(Arc::new(test_helpers::create_test_config()), store);
            for (index, value) in [
                serde_json::json!(0),
                serde_json::json!(-1),
                serde_json::json!(1.9),
                serde_json::json!(true),
                serde_json::json!(1e20),
            ]
            .into_iter()
            .enumerate()
            {
                let mut input = types::CreateUserRequest::new(
                    format!("numeric-date-{index}@fixture.test"),
                    "Date",
                );
                input.data = Some(
                    serde_json::json!({
                        "createdAt": value, "updatedAt": value, "banExpires": value
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                );
                let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap();
                let expected = if value.is_boolean() {
                    serde_json::json!(1)
                } else {
                    value
                };
                let response = serde_json::to_value(&created).unwrap();
                for field in ["createdAt", "updatedAt", "banExpires"] {
                    assert_eq!(response["user"][field], expected, "{field}");
                }
                let retained = ctx
                    .database
                    .get_user_by_id_record(&created.user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.raw_snapshot().values()["createdAt"], expected);
                let row = database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
            "SELECT typeof(\"createdAt\") AS storage_type, CAST(\"createdAt\" AS REAL) AS stored FROM user WHERE id = ?",
            [created.user.id.into()]
        )).await.unwrap().unwrap();
                let kind: String = row.try_get("", "storage_type").unwrap();
                assert!(matches!(kind.as_str(), "integer" | "real"), "{kind}");
                let stored: f64 = row.try_get("", "stored").unwrap();
                assert_eq!(stored, expected.as_f64().unwrap());
            }
        }

        #[tokio::test]
        async fn numeric_native_ban_expiry_uses_truthiness_and_date_timeclip() {
            use alibi_core::store::SessionCreatedHook;
            let (ctx, _, _, _, _) = create_admin_context().await;
            for (index, (expiry, expired)) in [
                (serde_json::json!(0), false),
                (serde_json::json!(-1), true),
                (serde_json::json!(1.9), true),
                (serde_json::json!(-0.5), true),
                (serde_json::json!(1e20), false),
                (serde_json::json!(-1e20), false),
            ]
            .into_iter()
            .enumerate()
            {
                let mut input = types::CreateUserRequest::new(
                    format!("numeric-ban-{index}@fixture.test"),
                    "Ban",
                );
                input.data = Some(
            serde_json::json!({"banned": true, "banExpires": expiry, "banReason": "expired reason"})
                .as_object()
                .unwrap()
                .clone(),
        );
                let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap();
                let result = AdminSessionGuard
                    .before_create(
                        &CreateSession {
                            user_id: created.user.id.clone(),
                            expires_at: Utc::now() + Duration::hours(1),
                            token: None,
                            ip_address: None,
                            user_agent: None,
                            impersonated_by: None,
                            active_organization_id: None,
                            active_team_id: None,
                            additional_fields: Default::default(),
                        },
                        &ctx,
                        None,
                    )
                    .await;
                assert_eq!(result.is_ok(), expired, "{expiry}: {result:?}");
                let stored = ctx
                    .database
                    .get_user_by_id_record(&created.user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(stored.banned(), !expired);
                assert_eq!(
                    stored.ban_reason(),
                    if expired {
                        None
                    } else {
                        Some("expired reason")
                    }
                );
                assert_eq!(stored.ban_expires().is_none(), expired);
            }
        }

        #[tokio::test]
        async fn admin_creation_malformed_native_fields_reach_storage_failure() {
            let (ctx, _, _, _, _) = create_admin_context().await;
            for (index, data) in [
                serde_json::json!({"image": {"not": "a scalar"}}),
                serde_json::json!({"banned": []}),
                serde_json::json!({"createdAt": "definitely not a date"}),
                serde_json::json!({"banExpires": "invalid"}),
            ]
            .into_iter()
            .enumerate()
            {
                let email = format!("raw-malformed-{index}@fixture.test");
                let mut input = types::CreateUserRequest::new(&email, "Malformed");
                input.data = Some(data.as_object().unwrap().clone());
                let error = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap_err();
                assert_eq!(error.status_code(), 500, "{error:?}");
                assert!(
                    ctx.database
                        .get_user_by_email(&alibi_core::utils::json::JsString::from(&email))
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        }

        #[tokio::test]
        async fn native_secondary_user_roundtrip_retains_raw_dates_and_boolean_presence() {
            use alibi_core::{AuthSchema, AuthUser, CacheAdapter};
            let (ctx, _, _, user, _) = create_admin_context().await;
            let user = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            let cache = alibi_core::MemoryCacheAdapter::new();
            type User = <TestSchema as AuthSchema>::User;
            for (index, created_at) in [
                serde_json::json!(1e20),
                serde_json::json!(-1),
                serde_json::json!(1.9),
                serde_json::json!("2099-01-01T00:00:00.000Z"),
            ]
            .into_iter()
            .enumerate()
            {
                let mut snapshot = user.secondary_snapshot().unwrap();
                snapshot["created_at"] = created_at.clone().into();
                snapshot["updated_at"] = serde_json::json!(-1e20).into();
                snapshot["ban_expires"] = serde_json::json!(-0.5).into();
                snapshot["email_verified"] = serde_json::json!("false").into();
                snapshot["two_factor_enabled"] = serde_json::json!("false").into();
                snapshot["banned"] = serde_json::json!(false).into();
                snapshot["is_anonymous"] = serde_json::Value::Null.into();
                snapshot
                    .as_object_mut()
                    .unwrap()
                    .shift_remove("phone_number_verified");
                snapshot.as_object_mut().unwrap().shift_remove("image");
                snapshot["username"] = serde_json::Value::Null.into();
                snapshot["name"] = serde_json::Value::Null.into();
                snapshot["unknownNative"] = serde_json::json!("must not retain").into();
                cache
                    .set(
                        &format!("native-user-{index}"),
                        &snapshot.to_string(),
                        Duration::seconds(60),
                    )
                    .await
                    .unwrap();
            }
            ctx.database.delete_user(&user.id()).await.unwrap();
            for index in 0..4 {
                let source: serde_json::Value = serde_json::from_str(
                    &cache
                        .get(&format!("native-user-{index}"))
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                let decoded = User::from_secondary_snapshot_record(source.clone().into()).unwrap();
                let wire = serde_json::to_value(alibi_core::UserView::from(&decoded)).unwrap();
                assert_eq!(wire["createdAt"], source["created_at"]);
                assert_eq!(wire["updatedAt"], source["updated_at"]);
                assert_eq!(wire["banExpires"], source["ban_expires"]);
                assert_eq!(wire["emailVerified"], "false");
                assert_eq!(wire["twoFactorEnabled"], "false");
                assert_eq!(wire["isAnonymous"], serde_json::Value::Null);
                assert!(wire.get("phoneNumberVerified").is_none());
                assert!(wire.get("image").is_none());
                assert_eq!(wire.get("username"), Some(&serde_json::Value::Null));
                assert_eq!(wire.get("name"), Some(&serde_json::Value::Null));
                assert_eq!(decoded.name(), Some(""));
                assert!(decoded.email_verified());
                assert!(decoded.two_factor_enabled());
                assert!(!decoded.banned());
                assert!(
                    decoded
                        .raw_snapshot()
                        .field_is_undefined("phoneNumberVerified")
                );
                assert!(!decoded.raw_snapshot().contains_field("unknownNative"));
                let encoded = decoded.secondary_snapshot().unwrap();
                for field in [
                    "created_at",
                    "updated_at",
                    "ban_expires",
                    "email_verified",
                    "two_factor_enabled",
                    "is_anonymous",
                ] {
                    assert_eq!(encoded[field], source[field], "{field}");
                }
                assert!(encoded.get("phone_number_verified").is_none());
                assert!(encoded.get("image").is_none());
                assert_eq!(
                    encoded.get("username"),
                    Some(&alibi_core::utils::json::JsValue::Null)
                );
                assert_eq!(
                    encoded.get("name"),
                    Some(&alibi_core::utils::json::JsValue::Null)
                );
            }
        }

        #[tokio::test]
        async fn unrelated_user_update_retains_native_sqlite_scalars() {
            use alibi_core::AuthUser;
            use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
            let database = Database::connect("sqlite::memory:").await.unwrap();
            alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
                .await
                .unwrap();
            let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
                test_helpers::create_test_config(),
                database.clone(),
            ));
            let ctx = AuthContext::new(Arc::new(test_helpers::create_test_config()), store);
            let mut input = types::CreateUserRequest::new("update-native@fixture.test", "Native");
            input.data = Some(
                serde_json::json!({
                    "emailVerified": 2, "banned": 0.5, "twoFactorEnabled": -1,
                    "isAnonymous": "pending", "phoneNumberVerified": -2,
                    "createdAt": 1e20, "banExpires": -0.5
                })
                .as_object()
                .unwrap()
                .clone(),
            );
            let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let updated = ctx
                .database
                .update_user_record(
                    &created.user.id,
                    alibi_core::UpdateUser {
                        name: Some("Changed".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.name(), Some("Changed"));
            let wire = serde_json::to_value(alibi_core::UserView::from(&updated)).unwrap();
            assert_eq!(wire["banned"], false);
            assert_eq!(wire["emailVerified"], false);
            assert_eq!(wire["twoFactorEnabled"], false);
            assert_eq!(wire["isAnonymous"], "pending");
            assert_eq!(wire["phoneNumberVerified"], false);
            assert_eq!(wire["createdAt"], serde_json::json!(1e20));
            assert_eq!(wire["banExpires"], serde_json::json!(-0.5));
            let row = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT typeof(banned) AS kind, banned, createdAt, banExpires FROM user WHERE id = ?",
            [created.user.id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
            assert_eq!(row.try_get::<String>("", "kind").unwrap(), "real");
            assert_eq!(row.try_get::<f64>("", "banned").unwrap(), 0.5);
            assert_eq!(row.try_get::<f64>("", "createdAt").unwrap(), 1e20);
            assert_eq!(row.try_get::<f64>("", "banExpires").unwrap(), -0.5);
        }

        #[tokio::test]
        async fn admin_update_ban_expiry_accepts_javascript_dates_and_invalid_date_fails_before_write()
         {
            use alibi_core::AuthUser;
            let (ctx, admin, _, user, _) = create_admin_context().await;
            for (input, expected) in [
                ("2099-01-01", "2099-01-01T00:00:00.000Z"),
                ("January 2, 2099", "2099-01-02T00:00:00.000Z"),
            ] {
                let data = serde_json::json!({"banExpires": input});
                let response = handlers::update_user_core(
                    &types::AdminUpdateUserRequest::new(
                        &user.id,
                        data.as_object().unwrap().clone(),
                    ),
                    &admin,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                assert_eq!(
                    serde_json::to_value(&response).unwrap()["banExpires"],
                    expected
                );
                let stored = ctx
                    .database
                    .get_user_by_id_record(&user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    stored.ban_expires().unwrap().timestamp_millis(),
                    alibi_core::utils::datetime::parse_date_millis(expected).unwrap()
                );
            }
            let before = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            let data = serde_json::json!({"name": "Must not write", "banExpires": "not a date"});
            let error = handlers::update_user_core(
                &types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone()),
                &admin,
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap_err();
            assert_eq!(error.status_code(), 500);
            assert!(error.to_string().contains("Invalid time value"));
            let after = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(before.name(), after.name());
            assert_eq!(before.ban_expires(), after.ban_expires());
        }

        #[tokio::test]
        async fn native_secondary_nonidentity_texts_keep_raw_cache_values() {
            use alibi_core::{AuthSchema, AuthUser, CacheAdapter};
            let (ctx, _, _, user, _) = create_admin_context().await;
            let user = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            let cache = alibi_core::MemoryCacheAdapter::new();
            type User = <TestSchema as AuthSchema>::User;
            let mut source = user.secondary_snapshot().unwrap();
            source["name"] = serde_json::json!(42).into();
            source["email"] = serde_json::Value::Null.into();
            source["image"] = serde_json::json!({"cached": true}).into();
            source["display_username"] = serde_json::json!(false).into();
            source["unknownText"] = serde_json::json!("not declared").into();
            cache
                .set(
                    "native-text-user",
                    &source.to_string(),
                    Duration::seconds(60),
                )
                .await
                .unwrap();
            ctx.database.delete_user(&user.id()).await.unwrap();
            let cached =
                serde_json::from_str(&cache.get("native-text-user").await.unwrap().unwrap())
                    .unwrap();
            let record = User::from_secondary_snapshot_record(cached).unwrap();
            assert_eq!(record.name(), Some(""));
            assert_eq!(record.email(), Some(""));
            assert_eq!(record.image(), None);
            assert_eq!(record.display_username(), None);
            let wire = serde_json::to_value(alibi_core::UserView::from(&record)).unwrap();
            assert_eq!(wire["name"], 42);
            assert_eq!(wire["email"], serde_json::Value::Null);
            assert_eq!(wire["image"], source["image"]);
            assert_eq!(wire["displayUsername"], false);
            assert!(wire.get("unknownText").is_none());
            let encoded = record.secondary_snapshot().unwrap();
            for field in ["name", "email", "image", "display_username"] {
                assert_eq!(encoded[field], source[field]);
            }
            assert!(encoded.get("unknownText").is_none());
        }

        #[tokio::test]
        async fn native_ban_expiry_updates_preserve_scalars_and_expanded_dates() {
            use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
            let database = Database::connect("sqlite::memory:").await.unwrap();
            alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
                .await
                .unwrap();
            let (_, acting_admin, _, _, _) = create_admin_context().await;
            let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
                test_helpers::create_test_config(),
                database.clone(),
            ));
            let ctx = AuthContext::new(Arc::new(test_helpers::create_test_config()), store);
            let expanded = "+275760-09-13T00:00:00.000Z";
            let mut input = types::CreateUserRequest::new("expanded-date@fixture.test", "Date");
            input.data = Some(
                serde_json::json!({
                    "createdAt": expanded, "updatedAt": expanded, "banExpires": expanded
                })
                .as_object()
                .unwrap()
                .clone(),
            );
            let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let wire = serde_json::to_value(&created).unwrap();
            for field in ["createdAt", "updatedAt", "banExpires"] {
                assert_eq!(wire["user"][field], expanded);
            }
            let row = database
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT createdAt AS value, typeof(createdAt) AS kind FROM user WHERE id = ?",
                    [created.user.id.clone().into()],
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.try_get::<String>("", "value").unwrap(), expanded);
            assert_eq!(row.try_get::<String>("", "kind").unwrap(), "text");
            for value in [
                serde_json::json!(0),
                serde_json::json!(-0.5),
                serde_json::json!(1.9),
                serde_json::json!(true),
                serde_json::json!(1e20),
                serde_json::json!(-1e20),
                serde_json::json!(expanded),
                serde_json::Value::Null,
            ] {
                let response = handlers::update_user_core(
                    &types::AdminUpdateUserRequest::new(
                        &created.user.id,
                        serde_json::json!({"banExpires": value})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    &acting_admin,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                let expected = if value.is_boolean() {
                    serde_json::json!(1)
                } else {
                    value.clone()
                };
                let wire = serde_json::to_value(response).unwrap();
                assert_eq!(wire["banExpires"], expected);
                let retained = ctx
                    .database
                    .get_user_by_id_record(&created.user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.raw_snapshot().values()["banExpires"], expected);
                let row = database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
            "SELECT json_quote(banExpires) AS value, typeof(banExpires) AS kind FROM user WHERE id = ?",
            [created.user.id.clone().into()])).await.unwrap().unwrap();
                let physical: serde_json::Value =
                    serde_json::from_str(&row.try_get::<String>("", "value").unwrap()).unwrap();
                assert_eq!(physical, expected);
                let expected_kind = if expected.is_null() {
                    "null"
                } else if expected.is_string() {
                    "text"
                } else if expected.as_f64().unwrap().fract() == 0.0
                    && expected.as_f64().unwrap().abs() < i64::MAX as f64
                {
                    "integer"
                } else {
                    "real"
                };
                assert_eq!(row.try_get::<String>("", "kind").unwrap(), expected_kind);
            }
        }

        #[tokio::test]
        async fn stateless_ban_expiry_comparisons_keep_native_truthiness_and_timeclip() {
            use alibi_core::store::UserStore;
            let store = alibi_core::store::stateless::StatelessStore::default();
            for (index, (expiry, expired)) in [
                (serde_json::json!(0), false),
                (serde_json::json!(-0.5), true),
                (serde_json::json!(1.9), true),
                (serde_json::json!(1e20), false),
                (serde_json::json!(-1e20), false),
            ]
            .into_iter()
            .enumerate()
            {
                let user = store
                    .create_user(alibi_core::CreateUser {
                        email: Some(format!("stateless-ban-{index}@fixture.test")),
                        banned: Some(true),
                        adapter_native_fields: [("banExpires".into(), expiry.clone().into())]
                            .into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    super::super::ban_expired_at(&user, Utc::now()).unwrap(),
                    expired,
                    "{expiry}"
                );
                let stored = store.get_user_by_id(&user.id).await.unwrap().unwrap();
                assert_eq!(serde_json::to_value(stored).unwrap()["banExpires"], expiry);
            }
        }

        #[tokio::test]
        async fn stateless_structured_ban_expiry_uses_date_primitive_conversion_and_errors() {
            use alibi_core::store::SessionCreatedHook;
            let ctx = AuthContext::new(
                Arc::new(crate::test_helpers::create_test_config()),
                Arc::new(alibi_core::store::stateless::StatelessStore::default()),
            );
            for (index, (expiry, expired)) in [
                (serde_json::json!(["2000-01-01"]), Some(true)),
                (serde_json::json!([0]), Some(true)),
                (serde_json::json!([["2000-01-01"]]), Some(true)),
                (serde_json::json!([]), Some(false)),
                (serde_json::json!({}), Some(false)),
                (serde_json::json!({"toString": null}), None),
                (serde_json::json!({"toString": 1}), None),
            ]
            .into_iter()
            .enumerate()
            {
                let user = ctx
                    .database
                    .create_user_record(alibi_core::CreateUser {
                        email: Some(format!("structured-expiry-{index}@fixture.test")),
                        banned: Some(true),
                        adapter_native_fields: [
                            ("banExpires".into(), expiry.clone().into()),
                            ("banReason".into(), serde_json::json!("retained").into()),
                        ]
                        .into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let result = AdminSessionGuard
                    .before_create(
                        &CreateSession {
                            user_id: user.id().to_string(),
                            expires_at: Utc::now() + Duration::hours(1),
                            token: None,
                            ip_address: None,
                            user_agent: None,
                            impersonated_by: None,
                            active_organization_id: None,
                            active_team_id: None,
                            additional_fields: Default::default(),
                        },
                        &ctx,
                        None,
                    )
                    .await;
                if let Some(expired) = expired {
                    assert_eq!(result.is_ok(), expired, "{expiry}: {result:?}");
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.status_code(), 500);
                    assert!(
                        error
                            .to_string()
                            .contains("Cannot convert object to primitive value")
                    );
                }
                let stored = ctx
                    .database
                    .get_user_by_id_record(user.id().as_ref())
                    .await
                    .unwrap()
                    .unwrap();
                let wire = serde_json::to_value(UserView::from(&stored)).unwrap();
                assert_eq!(stored.banned(), expired != Some(true));
                assert_eq!(
                    wire["banExpires"],
                    if expired == Some(true) {
                        serde_json::Value::Null
                    } else {
                        expiry
                    }
                );
                assert_eq!(
                    wire["banReason"],
                    if expired == Some(true) {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!("retained")
                    }
                );
            }
        }
    }

    mod username_creation {
        use super::*;
        use crate::email_password::{EmailPasswordPlugin, UsernameConfig, UsernameNormalization};
        use alibi_core::field_policy::{SessionFields, UserFields};
        use alibi_core::{AuthInitContext, AuthPlugin, AuthUser};
        use std::sync::Mutex;

        async fn username_context(
            policy: UsernameConfig,
            events: Option<Arc<Mutex<Vec<String>>>>,
        ) -> AuthContext<TestSchema> {
            let (mut ctx, _, _, _, _) = create_admin_context().await;
            let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
            if let Some(events) = events.clone() {
                init.register_user_create_transform(move |mut data| {
                    events.lock().unwrap().push("before".into());
                    data.username = Some("ORDERED".into());
                    Ok(data)
                });
            }
            let plugin = EmailPasswordPlugin::new()
                .enable_username(true)
                .username_config(policy.clone());
            <EmailPasswordPlugin as AuthPlugin<TestSchema>>::on_init(&plugin, &mut init)
                .await
                .unwrap();
            init.extensions
                .insert(UserFields(SessionFields(policy.fields())));
            let mut adapter_fields = policy.fields();
            adapter_fields.extend(init.config.user.additional_fields.clone());
            init.extensions
                .insert(alibi_core::field_policy::AdapterFieldPolicies {
                    user: alibi_core::field_policy::SessionAdapterFields(Arc::new(adapter_fields)),
                    ..Default::default()
                });
            if let Some(events) = events {
                init.register_user_create_transform(move |data| {
                    events
                        .lock()
                        .unwrap()
                        .push(format!("after:{}", data.username.as_deref().unwrap()));
                    Ok(data)
                });
            }
            ctx.metadata = init.metadata.clone();
            ctx.extensions = init.extensions.clone();
            ctx.database = init.database_with_registered_transforms();
            ctx
        }

        mod username_update {
            use super::*;

            fn update_request(id: &str, data: serde_json::Value) -> types::AdminUpdateUserRequest {
                types::AdminUpdateUserRequest::new(id, data.as_object().unwrap().clone())
            }

            fn update_call(
                user: UserView,
                session: SessionView,
                path: &str,
            ) -> alibi_core::endpoint::EndpointCall {
                let definition = alibi_core::endpoint::EndpointDefinition {
                    name: "update-user",
                    operation_id: "updateUser",
                    path: Some(path.into()),
                    method: HttpMethod::Post,
                };
                let call = alibi_core::endpoint::EndpointCall::new(
                    &definition,
                    None,
                    None,
                    Default::default(),
                );
                call.record_authenticated_session(user, session);
                call
            }

            #[tokio::test]
            async fn admin_username_updates_use_actual_actor_and_keep_falsy_display_without_create_fallback()
             {
                let ctx = username_context(UsernameConfig::default(), None).await;
                let admin = ctx
                    .database
                    .get_user_by_email_record(&"admin@example.com".into())
                    .await
                    .unwrap()
                    .unwrap();
                let acting = UserView::from(&admin);
                let created = handlers::create_user_core(
                    &provision(
                        "updated-username@fixture.test",
                        serde_json::json!({"username":"EXISTING"}),
                    ),
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap()
                .user;
                let input = update_request(&created.id, serde_json::json!({"username":"existing"}));
                let error =
                    handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx)
                        .await
                        .unwrap_err();
                assert!(matches!(
                    error,
                    AuthError::Upstream {
                        code: "USERNAME_IS_ALREADY_TAKEN",
                        ..
                    }
                ));
                let session =
                    test_helpers::create_session(&ctx, created.id.clone(), Duration::hours(1))
                        .await;
                let self_call = update_call(created.clone(), session.clone(), "/admin/update-user");
                let result = alibi_core::endpoint::with_endpoint_call_context(
                    self_call,
                    handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx),
                )
                .await
                .unwrap();
                assert_eq!(
                    result
                        .values()
                        .get("username")
                        .and_then(alibi_core::utils::json::JsValue::as_str),
                    Some("existing")
                );
                let other_call = update_call(acting.clone(), session.clone(), "/admin/update-user");
                assert!(
                    alibi_core::endpoint::with_endpoint_call_context(
                        other_call,
                        handlers::update_user_core(&input, &acting, &AdminConfig::default(), &ctx)
                    )
                    .await
                    .is_err()
                );
                let changed = handlers::update_user_core(
                    &update_request(
                        &created.id,
                        serde_json::json!({"username":"NEW_NAME","displayUsername":false}),
                    ),
                    &acting,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                assert_eq!(
                    changed
                        .values()
                        .get("username")
                        .and_then(alibi_core::utils::json::JsValue::as_str),
                    Some("new_name")
                );
                assert_eq!(
                    changed
                        .values()
                        .get("displayUsername")
                        .and_then(alibi_core::utils::json::JsValue::as_str),
                    Some("0")
                );
                let nulled = handlers::update_user_core(
                    &update_request(
                        &created.id,
                        serde_json::json!({"username":null,"displayUsername":null}),
                    ),
                    &acting,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                assert!(nulled.values()["username"].is_null());
                assert!(nulled.values()["displayUsername"].is_null());
                let default_numeric = handlers::update_user_core(
                    &update_request(&created.id, serde_json::json!({"username":42})),
                    &acting,
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap_err();
                assert_eq!(default_numeric.status_code(), 500);
                assert!(
                    ctx.database
                        .get_user_by_id(&created.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .username()
                        .is_none()
                );
                let skip = update_call(acting.clone(), session, "/update-user");
                let skipped = alibi_core::endpoint::with_endpoint_call_context(
                    skip,
                    handlers::update_user_core(
                        &update_request(&created.id, serde_json::json!({"username":"X"})),
                        &acting,
                        &AdminConfig::default(),
                        &ctx,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(
                    skipped
                        .values()
                        .get("username")
                        .and_then(alibi_core::utils::json::JsValue::as_str),
                    Some("x")
                );
            }

            #[tokio::test]
            async fn admin_username_updates_await_ordered_validation_and_stop_later_hooks() {
                for admit in [true, false] {
                    let (mut ctx, _, _, target, _) = create_admin_context().await;
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
                    let log = events.clone();
                    init.register_user_update_transform(move |_, input| {
                        log.lock().unwrap().push("before".to_owned());
                        Ok(input)
                    });
                    let log = events.clone();
                    let policy = UsernameConfig {
                        validator: Some(Arc::new(move |username: String| {
                            let log = log.clone();
                            async move {
                                tokio::task::yield_now().await;
                                log.lock().unwrap().push(format!("validator:{username}"));
                                Ok(admit)
                            }
                        })),
                        ..Default::default()
                    };
                    let plugin = EmailPasswordPlugin::new()
                        .enable_username(true)
                        .username_config(policy.clone());
                    <EmailPasswordPlugin as AuthPlugin<TestSchema>>::on_init(&plugin, &mut init)
                        .await
                        .unwrap();
                    init.extensions
                        .insert(UserFields(SessionFields(policy.fields())));
                    init.extensions
                        .insert(alibi_core::field_policy::AdapterFieldPolicies {
                            user: alibi_core::field_policy::SessionAdapterFields(Arc::new(
                                policy.fields(),
                            )),
                            ..Default::default()
                        });
                    let log = events.clone();
                    init.register_user_update_transform(move |_, input| {
                        log.lock().unwrap().push("after".to_owned());
                        assert_eq!(input.username.as_deref(), Some("ORDERED"));
                        Ok(input)
                    });
                    ctx.metadata = init.metadata.clone();
                    ctx.extensions = init.extensions.clone();
                    ctx.database = init.database_with_registered_transforms();
                    let result = ctx
                        .database
                        .update_user(
                            &target.id,
                            alibi_core::UpdateUser {
                                username: Some("ORDERED".into()),
                                name: Some("Changed".into()),
                                ..Default::default()
                            },
                        )
                        .await;
                    let stored = ctx
                        .database
                        .get_user_by_id(&target.id)
                        .await
                        .unwrap()
                        .unwrap();
                    if admit {
                        result.unwrap();
                        assert_eq!(
                            *events.lock().unwrap(),
                            ["before", "validator:ORDERED", "after"]
                        );
                        assert_eq!(stored.username(), Some("ordered"));
                        assert_eq!(stored.name(), Some("Changed"));
                    } else {
                        assert_eq!(result.unwrap_err().status_code(), 400);
                        assert_eq!(*events.lock().unwrap(), ["before", "validator:ORDERED"]);
                        assert_eq!(stored.username(), None);
                        assert_eq!(stored.name(), target.name.as_deref());
                    }
                }
            }

            #[tokio::test]
            async fn admin_username_updates_preserve_scalars_and_observe_current_transaction() {
                let policy = UsernameConfig {
                    normalization: UsernameNormalization::Preserve,
                    ..Default::default()
                };
                let ctx = username_context(policy, None).await;
                let acting = UserView::from(
                    &ctx.database
                        .get_user_by_email_record(&"admin@example.com".into())
                        .await
                        .unwrap()
                        .unwrap(),
                );
                let target = handlers::create_user_core(
                    &provision("preserved-update@fixture.test", serde_json::json!({})),
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap()
                .user;
                for raw in [
                    serde_json::json!("KeEpCaSe"),
                    serde_json::json!(42),
                    serde_json::json!(false),
                    serde_json::json!(""),
                ] {
                    let changed = handlers::update_user_core(
                        &update_request(
                            &target.id,
                            serde_json::json!({"username":raw,"displayUsername":false}),
                        ),
                        &acting,
                        &AdminConfig::default(),
                        &ctx,
                    )
                    .await
                    .unwrap();
                    let expected = match raw {
                        serde_json::Value::String(text) => text,
                        serde_json::Value::Bool(_) => "0".into(),
                        _ => "42".into(),
                    };
                    assert_eq!(
                        changed
                            .values()
                            .get("username")
                            .and_then(alibi_core::utils::json::JsValue::as_str),
                        Some(expected.as_str())
                    );
                    assert_eq!(
                        changed
                            .values()
                            .get("displayUsername")
                            .and_then(alibi_core::utils::json::JsValue::as_str),
                        Some("0")
                    );
                }
                alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
                    Box::pin(async move {
                        let first = tx
                            .create_user(CreateUser::new().with_email("update-tx-a@fixture.test"))
                            .await?;
                        let second = tx
                            .create_user(CreateUser::new().with_email("update-tx-b@fixture.test"))
                            .await?;
                        let updated = tx
                            .update_user(
                                first.id().as_ref(),
                                alibi_core::UpdateUser {
                                    username: Some("InTransaction".into()),
                                    ..Default::default()
                                },
                            )
                            .await?;
                        assert_eq!(updated.username(), Some("InTransaction"));
                        let error = tx
                            .update_user(
                                second.id().as_ref(),
                                alibi_core::UpdateUser {
                                    username: Some("InTransaction".into()),
                                    name: Some("Never".into()),
                                    ..Default::default()
                                },
                            )
                            .await
                            .unwrap_err();
                        assert!(matches!(
                            error,
                            AuthError::Upstream {
                                code: "USERNAME_IS_ALREADY_TAKEN",
                                ..
                            }
                        ));
                        assert_ne!(
                            tx.get_user_by_id(second.id().as_ref())
                                .await?
                                .unwrap()
                                .name(),
                            Some("Never")
                        );
                        Ok(())
                    })
                })
                .await
                .unwrap();
            }
        }

        fn provision(email: &str, data: serde_json::Value) -> types::CreateUserRequest {
            let mut input = types::CreateUserRequest::new(email, "Username");
            input.data = Some(data.as_object().unwrap().clone());
            input
        }

        #[tokio::test]
        async fn admin_username_creation_validates_raw_fields_and_preserves_display_fallback() {
            let ctx = username_context(UsernameConfig::default(), None).await;
            for (index, username, status) in [
                (0, serde_json::json!(42), 500),
                (1, serde_json::json!("ab"), 400),
                (2, serde_json::json!("not allowed"), 400),
            ] {
                let email = format!("invalid-username-{index}@fixture.test");
                let error = handlers::create_user_core(
                    &provision(&email, serde_json::json!({"username": username})),
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap_err();
                assert_eq!(error.status_code(), status, "{error:?}");
                assert!(
                    ctx.database
                        .get_user_by_email(&(email).into())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            let user = handlers::create_user_core(
                &provision(
                    "mixed-username@fixture.test",
                    serde_json::json!({"username":"MiXeD","displayUsername":false}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap();
            assert_eq!(user.user.username.as_deref(), Some("mixed"));
            assert_eq!(user.user.display_username.as_deref(), Some("MiXeD"));
            let error = handlers::create_user_core(
                &provision(
                    "duplicate-username@fixture.test",
                    serde_json::json!({"username":"MIXED"}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                alibi_core::AuthError::Upstream {
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    ..
                }
            ));

            let policy = UsernameConfig {
                normalization: UsernameNormalization::Preserve,
                ..UsernameConfig::default()
            };
            let ctx = username_context(policy, None).await;
            let preserved = handlers::create_user_core(
                &provision(
                    "preserve-username@fixture.test",
                    serde_json::json!({"username":"KeEpCaSe"}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap();
            assert_eq!(preserved.user.username.as_deref(), Some("KeEpCaSe"));
            let numeric = handlers::create_user_core(
                &provision(
                    "number-username@fixture.test",
                    serde_json::json!({"username":42,"displayUsername":false}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap();
            assert_eq!(numeric.user.username.as_deref(), Some("42"));
            assert_eq!(numeric.user.display_username.as_deref(), Some("42"));
            let duplicate = handlers::create_user_core(
                &provision(
                    "number-duplicate@fixture.test",
                    serde_json::json!({"username":42}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                duplicate,
                alibi_core::AuthError::Upstream {
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    ..
                }
            ));
        }

        #[tokio::test]
        async fn admin_username_async_validator_runs_between_application_hooks_and_stops_on_error()
        {
            let events = Arc::new(Mutex::new(Vec::new()));
            let log = events.clone();
            let policy = UsernameConfig {
                validator: Some(Arc::new(move |value: String| {
                    let log = log.clone();
                    async move {
                        tokio::task::yield_now().await;
                        log.lock().unwrap().push(format!("validator:{value}"));
                        Ok(true)
                    }
                })),
                ..UsernameConfig::default()
            };
            let ctx = username_context(policy, Some(events.clone())).await;
            let user = handlers::create_user_core(
                &provision(
                    "ordered-username@fixture.test",
                    serde_json::json!({"username":"bad value"}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap();
            assert_eq!(user.user.username.as_deref(), Some("ordered"));
            assert_eq!(
                *events.lock().unwrap(),
                ["before", "validator:ORDERED", "after:ordered"]
            );

            let events = Arc::new(Mutex::new(Vec::new()));
            let log = events.clone();
            let policy = UsernameConfig {
                validator: Some(Arc::new(move |_: String| {
                    let log = log.clone();
                    async move {
                        log.lock().unwrap().push("validator".into());
                        Err(alibi_core::AuthError::internal("validator rejected"))
                    }
                })),
                ..UsernameConfig::default()
            };
            let ctx = username_context(policy, Some(events.clone())).await;
            let error = handlers::create_user_core(
                &provision(
                    "validator-error@fixture.test",
                    serde_json::json!({"username":"initial"}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap_err();
            assert_eq!(error.status_code(), 500);
            assert_eq!(*events.lock().unwrap(), ["before", "validator"]);
            assert!(
                ctx.database
                    .get_user_by_email(&("validator-error@fixture.test").into())
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn admin_username_duplicate_hook_uses_current_transaction_and_endpoint_skip() {
            let ctx = username_context(UsernameConfig::default(), None).await;
            alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
                Box::pin(async move {
                    let mut input = CreateUser::new().with_email("username-tx-first@fixture.test");
                    input.username = Some("IN_TRANSACTION".into());
                    let created = tx.create_user(input).await?;
                    assert_eq!(created.username(), Some("in_transaction"));
                    let mut input = CreateUser::new().with_email("username-tx-second@fixture.test");
                    input.username = Some("in_transaction".into());
                    let error = tx.create_user(input).await.unwrap_err();
                    assert!(matches!(
                        error,
                        alibi_core::AuthError::Upstream {
                            code: "USERNAME_IS_ALREADY_TAKEN",
                            ..
                        }
                    ));
                    assert!(
                        tx.get_user_by_email(&("username-tx-second@fixture.test").into())
                            .await?
                            .is_none()
                    );
                    Ok(())
                })
            })
            .await
            .unwrap();

            let request =
                alibi_core::AuthRequest::new(alibi_core::HttpMethod::Post, "/sign-up/email");
            let mut input = CreateUser::new().with_email("username-skip@fixture.test");
            input.username = Some("X".into());
            let created = alibi_core::hooks::with_request_hook_context(
                &request,
                ctx.database.create_user(input),
            )
            .await
            .unwrap();
            assert_eq!(created.username(), Some("x"));
        }

        #[tokio::test]
        async fn admin_username_memory_scalars_keep_strict_lookup_and_preserved_case() {
            use alibi_core::store::stateless::{StatelessSchema, StatelessStore};
            let config = Arc::new(alibi_core::AuthConfig::default());
            let physical = Arc::new(StatelessStore::default());
            let mut init = AuthInitContext::new(config.clone(), physical);
            let policy = UsernameConfig {
                normalization: UsernameNormalization::Preserve,
                ..UsernameConfig::default()
            };
            let plugin = EmailPasswordPlugin::new()
                .enable_username(true)
                .username_config(policy.clone());
            <EmailPasswordPlugin as AuthPlugin<StatelessSchema>>::on_init(&plugin, &mut init)
                .await
                .unwrap();
            init.extensions
                .insert(UserFields(SessionFields(policy.fields())));
            let ctx = AuthContext::with_metadata(
                config,
                init.database_with_registered_transforms(),
                init.metadata.clone(),
            )
            .with_extensions(init.extensions.clone());
            for (email, value) in [
                ("memory-numeric@fixture.test", serde_json::json!(4242)),
                ("memory-text@fixture.test", serde_json::json!("4242")),
                ("memory-case@fixture.test", serde_json::json!("KeEpCaSe")),
            ] {
                let response = handlers::create_user_core(
                    &provision(
                        email,
                        serde_json::json!({"username":value,"displayUsername":false}),
                    ),
                    &AdminConfig::default(),
                    &ctx,
                )
                .await
                .unwrap();
                let wire = serde_json::to_value(response.user).unwrap();
                assert_eq!(wire["username"], value);
                assert_eq!(wire["displayUsername"], value);
                let stored = ctx
                    .database
                    .get_user_by_email(&(email).into())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(serde_json::to_value(stored).unwrap()["username"], value);
            }
            let error = handlers::create_user_core(
                &provision(
                    "memory-duplicate@fixture.test",
                    serde_json::json!({"username":4242}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                alibi_core::AuthError::Upstream {
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    ..
                }
            ));
        }

        #[tokio::test]
        async fn admin_username_hidden_display_is_not_persisted_and_without_plugin_case_is_unchanged()
         {
            let policy = UsernameConfig {
                include_display_username: false,
                ..UsernameConfig::default()
            };
            let ctx = username_context(policy, None).await;
            let response = handlers::create_user_core(
                &provision(
                    "hidden-display@fixture.test",
                    serde_json::json!({"username":"MIXED","displayUsername":"Ignored"}),
                ),
                &AdminConfig::default(),
                &ctx,
            )
            .await
            .unwrap();
            let wire = serde_json::to_value(response.user).unwrap();
            assert_eq!(wire["username"], "mixed");
            assert!(wire.get("displayUsername").is_none());
            let stored = ctx
                .database
                .get_user_by_email(&("hidden-display@fixture.test").into())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.display_username(), None);

            let (ctx, _, _, _, _) = create_admin_context().await;
            let mut input = CreateUser::new().with_email("no-username-plugin@fixture.test");
            input.username = Some("UnChanged".into());
            let stored = ctx.database.create_user(input).await.unwrap();
            assert_eq!(stored.username(), Some("UnChanged"));
        }
    }

    mod supplied_ids {
        use super::*;

        #[tokio::test]
        async fn admin_supplied_ids_use_string_defaults_and_actual_sqlite_parameters() {
            use alibi_core::AuthUser;
            let (ctx, _, _, _, _) = create_admin_context().await;
            for (index, (raw, expected)) in [
                (serde_json::json!("admin-provided-id"), "admin-provided-id"),
                (serde_json::json!(2), "2"),
                (serde_json::json!(1.9), "1.9"),
                (serde_json::json!(true), "1"),
            ]
            .into_iter()
            .enumerate()
            {
                let email = format!("supplied-id-{index}@fixture.test");
                let mut input = types::CreateUserRequest::new(&email, "Supplied identifier");
                input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
                let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap();
                assert_eq!(created.user.id, expected);
                assert_eq!(
                    ctx.database
                        .get_user_by_id(expected)
                        .await
                        .unwrap()
                        .unwrap()
                        .email(),
                    Some(email.as_str())
                );
                assert_eq!(
                    ctx.database
                        .get_user_by_email(&email.into())
                        .await
                        .unwrap()
                        .unwrap()
                        .id(),
                    expected
                );
            }
            for (index, data) in [serde_json::json!({}), serde_json::json!({"id":null})]
                .into_iter()
                .enumerate()
            {
                let email = format!("default-id-{index}@fixture.test");
                let mut input = types::CreateUserRequest::new(&email, "Generated identifier");
                input.data = Some(data.as_object().unwrap().clone());
                let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap();
                assert!(!created.user.id.is_empty());
                assert_eq!(
                    ctx.database
                        .get_user_by_id(&created.user.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .email(),
                    Some(email.as_str())
                );
            }
            for (index, raw) in [
                serde_json::json!(false),
                serde_json::json!(0),
                serde_json::json!(""),
                serde_json::json!({}),
                serde_json::json!([]),
            ]
            .into_iter()
            .enumerate()
            {
                let email = format!("invalid-id-{index}@fixture.test");
                let mut input = types::CreateUserRequest::new(&email, "Must not persist");
                input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
                let error = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap_err();
                assert_eq!(error.status_code(), 500, "{raw:?}: {error:?}");
                assert!(
                    ctx.database
                        .get_user_by_email(&email.into())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        }

        #[tokio::test]
        async fn supplied_native_ids_do_not_invoke_the_application_generator() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = calls.clone();
            let mut config = test_helpers::create_test_config();
            config.advanced.database.generate_id =
                Some(alibi_core::config::DatabaseIdStrategy::Custom(Arc::new(
                    move |model: &str, _: Option<usize>| {
                        assert_eq!(model, "user");
                        Ok(Some(format!(
                            "generated-{}",
                            observed.fetch_add(1, Ordering::SeqCst)
                        )))
                    },
                )));
            let config = Arc::new(config);
            let database = alibi_seaorm::sea_orm::Database::connect("sqlite::memory:")
                .await
                .unwrap();
            alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
                .await
                .unwrap();
            let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
                config.clone(),
                database,
            ));
            let ctx = AuthContext::new(config, store);
            for (index, raw) in [
                serde_json::json!("provided"),
                serde_json::json!(71),
                serde_json::json!(true),
                serde_json::json!(false),
                serde_json::json!(0),
                serde_json::json!(""),
            ]
            .into_iter()
            .enumerate()
            {
                let mut input = types::CreateUserRequest::new(
                    format!("counter-id-{index}@fixture.test"),
                    "Counter",
                );
                input.data = Some(serde_json::json!({"id":raw}).as_object().unwrap().clone());
                let result =
                    handlers::create_user_core(&input, &AdminConfig::default(), &ctx).await;
                assert_eq!(result.is_ok(), index < 3);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
            for (index, data) in [serde_json::json!({"id":null}), serde_json::json!({})]
                .into_iter()
                .enumerate()
            {
                let mut input = types::CreateUserRequest::new(
                    format!("counter-default-{index}@fixture.test"),
                    "Counter",
                );
                input.data = Some(data.as_object().unwrap().clone());
                let user = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
                    .await
                    .unwrap();
                assert_eq!(user.user.id, format!("generated-{index}"));
                assert_eq!(calls.load(Ordering::SeqCst), index + 1);
            }
        }
    }

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
    async fn admin_update_null_name_reaches_storage_validation() {
        let (ctx, admin, _, user, _) = create_admin_context().await;
        let error = update_user_core(
            &types::AdminUpdateUserRequest::new(
                &user.id,
                serde_json::json!({"name":null})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            &admin,
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code(), 500);
        assert_eq!(
            error.to_string(),
            "Internal server error: field value cannot be represented by its model column"
        );
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        use alibi_core::entity::AuthUser as _;
        assert_eq!(stored.name(), Some("Regular User"));
    }

    #[tokio::test]
    async fn empty_impersonation_marker_cannot_be_stopped() {
        let (ctx, _, _, user, _) = create_admin_context().await;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: user.id,
                expires_at: Utc::now() + Duration::hours(24),
                impersonated_by: Some(String::new()),
                additional_fields: Default::default(),
                token: None,
                ip_address: None,
                user_agent: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await
            .unwrap();
        let session = SessionView::from(&session);
        let req = make_request(
            HttpMethod::Post,
            "/admin/stop-impersonating",
            &session.token,
            Some(serde_json::json!({})),
        );
        let error = stop_impersonating_core(&session, &req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(error.to_string(), "You are not impersonating anyone");
        let error = AdminPlugin::new()
            .handle_stop_impersonating(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(error.to_string(), "You are not impersonating anyone");
    }

    #[tokio::test]
    async fn admin_update_null_ban_expiry_clears_without_unbanning() {
        let (ctx, admin, _, user, _) = create_admin_context().await;
        ctx.database
            .update_user_record(
                &user.id,
                alibi_core::UpdateUser {
                    banned: Some(true),
                    ban_reason: Some("retained".into()),
                    ban_expires: Some(Some(Utc::now() + Duration::hours(1))),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let body = types::AdminUpdateUserRequest::new(
            &user.id,
            serde_json::json!({"banExpires": null})
                .as_object()
                .unwrap()
                .clone(),
        );
        handlers::update_user_core(&body, &admin, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        use alibi_core::entity::AuthUser as _;
        assert!(stored.banned());
        assert_eq!(stored.ban_reason(), Some("retained"));
        assert!(stored.ban_expires().is_none());
    }

    #[tokio::test]
    async fn admin_update_null_ban_reason_clears_without_unbanning() {
        let (mut ctx, admin, _, user, _) = create_admin_context().await;
        let cache = Arc::new(alibi_core::store::MemoryCacheAdapter::new());
        let mut config = (*ctx.config).clone();
        config.session.secondary_storage = Some(cache.clone());
        ctx.config = Arc::new(config);
        let init = alibi_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
        ctx.database = init.database_with_registered_transforms();
        let expiry = Utc::now() + Duration::hours(1);
        ctx.database
            .update_user_record(
                &user.id,
                alibi_core::UpdateUser {
                    banned: Some(true),
                    ban_reason: Some("removed".into()),
                    ban_expires: Some(Some(expiry)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(1)).await;
        let body = types::AdminUpdateUserRequest::new(
            &user.id,
            serde_json::json!({"banReason": null})
                .as_object()
                .unwrap()
                .clone(),
        );
        handlers::update_user_core(&body, &admin, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        use alibi_core::entity::AuthUser as _;
        assert!(stored.banned());
        assert!(stored.ban_reason().is_none());
        assert!(stored.ban_expires().is_some());
        use alibi_core::store::CacheAdapter as _;
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(&session.token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"]["ban_reason"], serde_json::Value::Null);
        assert_eq!(cached["user"]["banned"], true);
        assert!(!cached["user"]["ban_expires"].is_null());

        ctx.database
            .update_user_record(
                &user.id,
                alibi_core::UpdateUser {
                    ban_reason: Some("must not win".into()),
                    clear_ban_reason: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.ban_reason().is_none());
    }

    #[test]
    fn empty_admin_id_does_not_bypass_role_permissions() {
        let config = AdminConfig {
            admin_user_ids: Some(vec![String::new(), "trusted".to_owned()]),
            ..AdminConfig::default()
        };
        let requested =
            std::collections::HashMap::from([("user".to_owned(), vec!["delete".to_owned()])]);
        assert!(!access::has_permission(
            Some(""),
            Some("user"),
            &config,
            &requested
        ));
        assert!(!access::has_permission(
            None,
            Some("user"),
            &config,
            &requested
        ));
        assert!(access::has_permission(
            Some("trusted"),
            Some("user"),
            &config,
            &requested
        ));
        assert!(access::has_permission(
            Some(""),
            Some("admin"),
            &config,
            &requested
        ));
    }

    #[tokio::test]
    async fn admin_update_phone_fields_persist_and_can_clear_number() {
        let (ctx, admin, _, user, _) = create_admin_context().await;
        for (data, expected_phone, expected_verified) in [
            (
                serde_json::json!({"phoneNumber": "+15551234567", "phoneNumberVerified": true}),
                Some("+15551234567"),
                true,
            ),
            (
                serde_json::json!({"phoneNumber": null, "phoneNumberVerified": false}),
                None,
                false,
            ),
        ] {
            let body =
                types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone());
            handlers::update_user_core(&body, &admin, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let stored = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            use alibi_core::entity::AuthUser as _;
            assert_eq!(stored.phone_number(), expected_phone);
            assert_eq!(stored.phone_number_verified(), Some(expected_verified));
        }
    }

    #[tokio::test]
    async fn admin_update_persists_trusted_additional_fields() {
        let mut config = test_helpers::create_test_config();
        config.user.additional_fields.insert(
            "profileLabel".to_owned(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .field_name("displayUsername")
                .read_only(),
        );
        let mut ctx = test_helpers::create_test_context_with_config(config).await;
        let init =
            alibi_core::AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        ctx.database = init.database_with_registered_transforms();
        let admin = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("admin@fixture.test")
                .with_role("admin"),
        )
        .await;
        let user =
            test_helpers::create_user(&ctx, CreateUser::new().with_email("profile@fixture.test"))
                .await;
        let data = serde_json::json!({"profileLabel":"Trusted label","unconfigured":"Ignored"});
        let input = types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone());
        let output = handlers::update_user_core(&input, &admin, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        use alibi_core::entity::AuthUser as _;
        assert_eq!(stored.display_username(), Some("Trusted label"));
        assert_eq!(output.values()["profileLabel"], "Trusted label");
        assert!(!output.values().contains_key("unconfigured"));
    }

    #[tokio::test]
    async fn admin_update_preserves_plugin_profile_fields() {
        let (ctx, admin, _, user, _) = create_admin_context().await;
        for (data, anonymous, method) in [
            (
                serde_json::json!({"isAnonymous": true, "lastLoginMethod": "email"}),
                true,
                Some("email"),
            ),
            (
                serde_json::json!({"isAnonymous": false, "lastLoginMethod": null}),
                false,
                None,
            ),
        ] {
            let input =
                types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone());
            handlers::update_user_core(&input, &admin, &AdminConfig::default(), &ctx)
                .await
                .unwrap();
            let stored = ctx
                .database
                .get_user_by_id_record(&user.id)
                .await
                .unwrap()
                .unwrap();
            use alibi_core::entity::AuthUser as _;
            assert_eq!(stored.is_anonymous(), Some(anonymous));
            assert_eq!(stored.last_login_method(), method);
        }
    }

    #[tokio::test]
    async fn admin_creation_preserves_native_data_and_outer_identity() {
        let (ctx, _, _, _, _) = create_admin_context().await;
        let mut input = types::CreateUserRequest::new("native-data@fixture.test", "Outer name");
        input.role = Some(types::RoleInput::One("user".to_owned()));
        input.data = Some(
            serde_json::json!({
                "email": "ignored@fixture.test", "name": "Ignored name", "role": "admin",
                "emailVerified": true, "image": "https://example.com/image.png",
                "username": "native-data", "displayUsername": "Native Data",
                "isAnonymous": true, "phoneNumber": "+15559876543", "phoneNumberVerified": true,
                "lastLoginMethod": "email", "twoFactorEnabled": true, "banned": true
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&created.user.id)
            .await
            .unwrap()
            .unwrap();
        use alibi_core::entity::AuthUser as _;
        assert_eq!(stored.email(), Some("native-data@fixture.test"));
        assert_eq!(stored.name(), Some("Outer name"));
        assert_eq!(stored.role(), Some("user"));
        assert!(stored.email_verified());
        assert_eq!(stored.image(), Some("https://example.com/image.png"));
        assert_eq!(stored.username(), Some("native-data"));
        assert_eq!(stored.display_username(), Some("Native Data"));
        assert_eq!(stored.is_anonymous(), Some(true));
        assert_eq!(stored.phone_number(), Some("+15559876543"));
        assert_eq!(stored.phone_number_verified(), Some(true));
        assert_eq!(stored.last_login_method(), Some("email"));
        assert!(stored.two_factor_enabled());
        assert!(stored.banned());
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

        _ = database
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
    async fn admin_creation_ignores_unconfigured_application_fields_without_reserved_role_input() {
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
            .get_user_by_email(&alibi_core::utils::json::JsString::from(
                "metadata-user@fixture.test",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created.role(), Some("user"));
        assert_eq!(created.metadata(), serde_json::json!({}));
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
