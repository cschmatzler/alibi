mod update;
pub use update::handle_update_user;

pub(super) mod handlers;

pub(super) mod types;

use alibi_core::wire::UserView;
use alibi_core::{AuthContext, AuthPlugin, AuthRoute};
use alibi_core::{AuthError, AuthResult};
use alibi_core::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use chrono::Duration;
use handlers::{change_email_core, delete_user_callback_core, delete_user_core};
use std::sync::Arc;
use types::{ChangeEmailRequest, DeleteUserRequest, TokenQuery};

/// The initialized user's full snapshot passed to application lifecycle hooks.
pub type UserInfo = UserView;

/// Custom callback for sending change-email confirmation emails.
///
/// If set on [`ChangeEmailConfig`], this callback is invoked instead of the
/// default [`EmailProvider`](alibi_core::EmailProvider). This allows callers to customise the email
/// subject, template, and delivery mechanism.
#[async_trait]
pub trait SendChangeEmailConfirmation: Send + Sync {
    async fn send(
        &self,
        user: &UserInfo,
        new_email: &str,
        url: &str,
        token: &str,
    ) -> AuthResult<()>;
}

/// Application delivery of an issued account-deletion proof. The original
/// request is available through `current_request_hook_context` during delivery.
#[async_trait]
pub trait SendDeleteAccountVerification: Send + Sync {
    async fn send(&self, user: &UserInfo, url: &str, token: &str) -> AuthResult<()>;
}

/// Hook invoked **before** a user is deleted.
///
/// Return `Err(...)` from [`before_delete`](BeforeDeleteUser::before_delete) to
/// abort the deletion.
#[async_trait]
pub trait BeforeDeleteUser: Send + Sync {
    async fn before_delete(&self, user: &UserInfo) -> AuthResult<()>;
}

/// Hook invoked **after** a user has been deleted.
#[async_trait]
pub trait AfterDeleteUser: Send + Sync {
    async fn after_delete(&self, user: &UserInfo) -> AuthResult<()>;
}

/// Configuration for the change-email feature.
#[derive(Clone, Default)]
pub struct ChangeEmailConfig {
    /// Whether the change-email endpoints are enabled. Default: `false`.
    pub enabled: bool,
    /// If `true`, the new email is updated immediately without sending a
    /// verification email. Default: `false`.
    pub update_without_verification: bool,
    /// Optional custom callback for sending the confirmation email.
    pub send_change_email_confirmation: Option<Arc<dyn SendChangeEmailConfirmation>>,
}

impl std::fmt::Debug for ChangeEmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeEmailConfig")
            .field("enabled", &self.enabled)
            .field(
                "update_without_verification",
                &self.update_without_verification,
            )
            .field(
                "send_change_email_confirmation",
                &self.send_change_email_confirmation.is_some(),
            )
            .finish()
    }
}

/// Configuration for the delete-user feature.
#[derive(Clone)]
pub struct DeleteUserConfig {
    /// Whether the delete-user endpoints are enabled. Default: `false`.
    pub enabled: bool,
    /// How long a delete-confirmation token remains valid. Default: 1 day.
    pub delete_token_expires_in: Duration,
    /// If `true`, a verification email must be confirmed before the account is
    /// deleted using the configured `EmailProvider`. Default: `false`.
    pub require_verification: bool,
    /// Custom delivery of an account-deletion proof. A configured callback
    /// selects verification before the session-freshness check.
    pub send_delete_account_verification: Option<Arc<dyn SendDeleteAccountVerification>>,
    /// Hook called before the user record is removed.
    pub before_delete: Option<Arc<dyn BeforeDeleteUser>>,
    /// Hook called after the user record has been removed.
    pub after_delete: Option<Arc<dyn AfterDeleteUser>>,
}

impl std::fmt::Debug for DeleteUserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeleteUserConfig")
            .field("enabled", &self.enabled)
            .field("delete_token_expires_in", &self.delete_token_expires_in)
            .field("require_verification", &self.require_verification)
            .field(
                "send_delete_account_verification",
                &self.send_delete_account_verification.is_some(),
            )
            .field("before_delete", &self.before_delete.is_some())
            .field("after_delete", &self.after_delete.is_some())
            .finish()
    }
}

impl Default for DeleteUserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            delete_token_expires_in: Duration::hours(24),
            require_verification: false,
            send_delete_account_verification: None,
            before_delete: None,
            after_delete: None,
        }
    }
}

/// Combined configuration for the [`UserManagementPlugin`].
#[derive(Debug, Clone, Default)]
pub struct UserManagementConfig {
    pub change_email: ChangeEmailConfig,
    pub delete_user: DeleteUserConfig,
}

/// User self-service management plugin (change email & delete account).
pub struct UserManagementPlugin {
    config: UserManagementConfig,
}

impl std::fmt::Debug for UserManagementPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserManagementPlugin")
            .finish_non_exhaustive()
    }
}

impl UserManagementPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: UserManagementConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: UserManagementConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn change_email_enabled(mut self, enabled: bool) -> Self {
        self.config.change_email.enabled = enabled;
        self
    }

    #[must_use]
    pub const fn update_without_verification(mut self, flag: bool) -> Self {
        self.config.change_email.update_without_verification = flag;
        self
    }

    #[must_use]
    pub fn send_change_email_confirmation(
        mut self,
        cb: Arc<dyn SendChangeEmailConfirmation>,
    ) -> Self {
        self.config.change_email.send_change_email_confirmation = Some(cb);
        self
    }

    #[must_use]
    pub const fn delete_user_enabled(mut self, enabled: bool) -> Self {
        self.config.delete_user.enabled = enabled;
        self
    }

    #[must_use]
    pub const fn delete_token_expires_in(mut self, duration: Duration) -> Self {
        self.config.delete_user.delete_token_expires_in = duration;
        self
    }

    #[must_use]
    pub const fn require_delete_verification(mut self, require: bool) -> Self {
        self.config.delete_user.require_verification = require;
        self
    }

    #[must_use]
    pub fn send_delete_account_verification(
        mut self,
        sender: Arc<dyn SendDeleteAccountVerification>,
    ) -> Self {
        self.config.delete_user.send_delete_account_verification = Some(sender);
        self
    }

    #[must_use]
    pub fn before_delete(mut self, hook: Arc<dyn BeforeDeleteUser>) -> Self {
        self.config.delete_user.before_delete = Some(hook);
        self
    }

    #[must_use]
    pub fn after_delete(mut self, hook: Arc<dyn AfterDeleteUser>) -> Self {
        self.config.delete_user.after_delete = Some(hook);
        self
    }
}

impl Default for UserManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl UserManagementPlugin {
    /// `POST /change-email`
    async fn handle_change_email(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = handlers::authoritative_session(req, ctx).await?;
        let body: ChangeEmailRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        if !self.config.change_email.enabled {
            return Err(AuthError::bad_request("Change email is disabled"));
        }
        let projection = change_email_core(&body, &user, &session, &self.config, ctx).await?;
        let mut response = AuthResponse::json(200, &alibi_core::StatusResponse { status: true })?;
        if projection.is_some() {
            append_session_cookie(&mut response, req, &session.token, &ctx.config)?;
        }
        Ok(response)
    }

    /// `POST /delete-user`
    async fn handle_delete_user(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = handlers::authoritative_session(req, ctx).await?;
        let body: DeleteUserRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        if !self.config.delete_user.enabled {
            return Ok(AuthResponse::new(404).with_header("Content-Type", "application/json"));
        }
        let response = delete_user_core(&body, &user, &session, req, &self.config, ctx).await?;
        let deleted =
            response.message == "User deleted" && body.token.as_deref().is_none_or(str::is_empty);
        let mut response = AuthResponse::json(200, &response)?;
        if deleted {
            append_clear_session_cookies(&mut response, &ctx.config)?;
        }
        Ok(response)
    }

    /// `GET /delete-user/callback`
    async fn handle_delete_user_callback(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if !self.config.delete_user.enabled {
            return Err(AuthError::Api {
                status: 404,
                code: Some("NOT_FOUND".into()),
                message: "Not found".into(),
            });
        }
        let (user, _) = handlers::authoritative_session(req, ctx)
            .await
            .map_err(|_error| AuthError::not_found("Failed to get user info"))?;
        let query: TokenQuery = serde_json::from_value(serde_json::json!({
            "token": req.query.get("token").cloned(),
            "callbackURL": req.query.get("callbackURL").cloned(),
        }))
        .map_err(|_error| AuthError::bad_request("Verification token is required"))?;
        let response =
            delete_user_callback_core(&query.token, &user, req, true, &self.config, ctx).await?;
        if let Some(callback_url) = query.callback_url.filter(|url| !url.is_empty()) {
            let mut headers = alibi_core::Headers::new();
            _ = headers.insert("Location".to_owned(), callback_url);
            _ = headers.insert("Content-Type".to_owned(), "application/json".to_owned());
            let mut response_2 = AuthResponse {
                status: 302,
                headers,
                body: Vec::new(),
            };
            append_clear_session_cookies(&mut response_2, &ctx.config)?;
            return Ok(response_2);
        }

        let mut response = AuthResponse::json(200, &response)?;
        append_clear_session_cookies(&mut response, &ctx.config)?;
        Ok(response)
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> AuthPlugin<S> for UserManagementPlugin {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &alibi_core::AuthInitContext<S>,
    ) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "user-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/change-email", "change_email"),
            AuthRoute::post("/delete-user", "delete_user"),
            AuthRoute::get("/delete-user/callback", "delete_user_callback"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/change-email") => {
                Ok(Some(self.handle_change_email(req, ctx).await?))
            }
            (HttpMethod::Post, "/delete-user") => {
                Ok(Some(self.handle_delete_user(req, ctx).await?))
            }
            (HttpMethod::Get, "/delete-user/callback") => {
                Ok(Some(self.handle_delete_user_callback(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

pub(super) fn append_clear_session_cookies(
    response: &mut AuthResponse,
    config: &alibi_core::AuthConfig,
) -> AuthResult<()> {
    response.headers.append(
        "Set-Cookie",
        alibi_core::utils::cookie_utils::create_clear_session_cookie(config)?,
    );
    response.headers.append(
        "Set-Cookie",
        alibi_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "session_data"),
            config,
        )?,
    );
    response.headers.append(
        "Set-Cookie",
        alibi_core::utils::cookie_utils::create_clear_cookie(
            &related_cookie_name(config, "dont_remember"),
            config,
        )?,
    );
    if config.account.store_account_cookie {
        response.headers.append(
            "Set-Cookie",
            alibi_core::utils::cookie_utils::create_clear_cookie(
                &related_cookie_name(config, "account_data"),
                config,
            )?,
        );
    }
    Ok(())
}

pub(crate) fn append_session_cookie(
    response: &mut AuthResponse,
    req: &AuthRequest,
    token: &str,
    config: &alibi_core::AuthConfig,
) -> AuthResult<()> {
    use alibi_core::utils::cookie_utils::{
        create_session_cookie_with_max_age, verify_cookie_value,
    };
    let dont_remember =
        super::helpers::get_cookie(req, &related_cookie_name(config, "dont_remember"))
            .and_then(|value| verify_cookie_value(&value, config.current_secret()))
            .is_some_and(|value| !value.is_empty());
    response.headers.append(
        "Set-Cookie",
        create_session_cookie_with_max_age(
            Some(token),
            (!dont_remember).then(|| config.session.expires_in.num_seconds()),
            config,
        )?,
    );
    Ok(())
}

fn related_cookie_name(config: &alibi_core::AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map_or_else(
            || format!("better-auth.{suffix}"),
            |prefix| format!("{prefix}{suffix}"),
        )
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;
    use alibi_core::{AccountConfig, CreateUser};
    use async_trait::async_trait;
    use chrono::Duration;
    use std::collections::HashMap;
    use std::sync::Arc;

    // -- change email tests ────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_change_email_success() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (mut ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        ctx.email_provider = Some(Arc::new(alibi_core::email::ConsoleEmailProvider));

        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = plugin.handle_change_email(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_change_email_same_email() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let body = serde_json::json!({ "newEmail": "test@example.com" });
        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_change_email_unauthenticated() {
        let plugin = UserManagementPlugin::new().change_email_enabled(true);
        let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/change-email",
            None,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let err = plugin.handle_change_email(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_change_email_immediate_when_update_without_verification() {
        let plugin = UserManagementPlugin::new()
            .change_email_enabled(true)
            .update_without_verification(true);
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(false),
            Duration::hours(24),
        )
        .await;

        // Initiate change -- should update immediately, no verification token
        let body = serde_json::json!({ "newEmail": "new@example.com" });
        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/change-email",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin.handle_change_email(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Email should be updated immediately
        let updated_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_user.email.as_deref(), Some("new@example.com"));
        // email_verified should be false (no verification was performed)
        assert!(!updated_user.email_verified);

        // No verification token should have been created
        let identifier = format!("change_email:{}:new@example.com", user.id);
        let verification = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap();
        assert!(
            verification.is_none(),
            "no verification token should be created when update_without_verification=true"
        );
    }

    // -- delete user tests ─────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_delete_user_immediate() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false);
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // User should be gone
        let deleted_user = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(deleted_user.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.ts :: deleteUser calls `deleteSessionCookie(ctx)`, which clears the account_data cookie when account.storeAccountCookie is enabled.
    #[tokio::test]
    async fn test_delete_user_immediate_clears_account_cookie_when_enabled() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false);
        let config = test_helpers::create_test_config().account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        });
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let (_user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("account-cookie@test.com")
                .with_name("Account Cookie")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "delete-user should clear the account_data cookie when store_account_cookie is enabled"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_delete_user_with_verification() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(true);
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        // 1. Request deletion -- should return pending status
        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = plugin.handle_delete_user(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // User should still exist
        let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(still_exists.is_some());

        // 2. Seed and confirm the callback token
        let token = "delete-token-123";
        ctx.database
            .create_verification(alibi_core::CreateVerification {
                identifier: format!("delete-account-{token}"),
                value: user.id.clone(),
                expires_at: chrono::Utc::now() + Duration::hours(24),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_owned(), token.to_owned());
        let req_2 = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/delete-user/callback",
            Some(&session.token),
            None,
            query,
        );
        let response_2 = plugin
            .handle_delete_user_callback(&req_2, &ctx)
            .await
            .unwrap();
        assert_eq!(response_2.status, 200);

        // User should now be gone
        let deleted = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(deleted.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.ts :: deleteUserCallback calls `deleteSessionCookie(ctx)`, which clears the account_data cookie when account.storeAccountCookie is enabled.
    #[tokio::test]
    async fn test_delete_user_callback_clears_account_cookie_when_enabled() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(true);
        let config = test_helpers::create_test_config().account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        });
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let (user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("callback-cookie@test.com")
                .with_name("Callback Cookie")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let token = "delete-cookie-token";
        ctx.database
            .create_verification(alibi_core::CreateVerification {
                identifier: format!("delete-account-{token}"),
                value: user.id.clone(),
                expires_at: chrono::Utc::now() + Duration::hours(24),
            })
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_owned(), token.to_owned());
        query.insert(
            "callbackURL".to_owned(),
            "https://example.com/goodbye".to_owned(),
        );
        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/delete-user/callback",
            Some(&session.token),
            None,
            query,
        );

        let response = plugin
            .handle_delete_user_callback(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "delete-user callback should clear the account_data cookie when store_account_cookie is enabled"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_delete_user_unauthenticated() {
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false);
        let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            None,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_delete_user_verify_invalid_token() {
        let plugin = UserManagementPlugin::new().delete_user_enabled(true);
        let (ctx, _user, fixture_session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let mut query = HashMap::new();
        query.insert("token".to_owned(), "invalid-token".to_owned());
        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/delete-user/callback",
            Some(&fixture_session.token),
            None,
            query,
        );

        let err = plugin
            .handle_delete_user_callback(&req, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 404);
    }

    // Upstream reference: packages/better-auth/src/api/routes/update-user.test.ts :: describe("updateUser") and packages/better-auth/src/api/routes/update-user.ts; adapted to the Rust user-management plugin.
    #[tokio::test]
    async fn test_delete_user_before_hook_abort() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct AbortHook;

        #[async_trait]
        impl BeforeDeleteUser for AbortHook {
            async fn before_delete(&self, _user: &UserInfo) -> AuthResult<()> {
                Err(AuthError::forbidden("Deletion blocked by policy"))
            }
        }

        struct AfterHook(Arc<AtomicBool>);

        #[async_trait]
        impl AfterDeleteUser for AfterHook {
            async fn after_delete(&self, _user: &UserInfo) -> AuthResult<()> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = std::sync::Arc::clone(&called);

        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .require_delete_verification(false)
            .before_delete(Arc::new(AbortHook))
            .after_delete(Arc::new(AfterHook(called_clone)));
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request(
            HttpMethod::Post,
            "/delete-user",
            Some(&session.token),
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let err = plugin.handle_delete_user(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 403);

        // User should still exist
        let still_exists = ctx.database.get_user_by_id(&user.id).await.unwrap();
        assert!(still_exists.is_some());

        // after_delete should NOT have been called
        assert!(!called.load(Ordering::SeqCst));
    }

    // The full-document SDK owner verifies default registration. This authenticated
    // native boundary independently proves disabled handlers cannot mutate storage.
    #[tokio::test]
    async fn disabled_user_management_rejects_authenticated_mutations() {
        let plugin = UserManagementPlugin::new();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User")
                .with_email_verified(true),
            Duration::hours(24),
        )
        .await;
        for (path, body, status) in [
            (
                "/change-email",
                serde_json::json!({"newEmail":"changed@example.com"}),
                400,
            ),
            ("/delete-user", serde_json::json!({}), 404),
        ] {
            let req = test_helpers::create_auth_request(
                HttpMethod::Post,
                path,
                Some(&session.token),
                Some(body.to_string().into_bytes()),
                HashMap::new(),
            );
            let result = plugin.on_request(&req, &ctx).await;
            match result {
                Ok(Some(response)) => assert_eq!(response.status, status),
                Err(error) => assert_eq!(error.status_code(), status),
                other => panic!("registered disabled handler did not reject: {other:?}"),
            }
            let stored = ctx
                .database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.email, user.email);
            assert!(
                ctx.database
                    .get_session(&session.token)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}
// LCOV_EXCL_STOP
