mod set_password;
pub use set_password::set_password;

pub(super) mod handlers;

pub(super) mod types;

use super::StatusResponse;
use async_trait::async_trait;
use better_auth_core::RequestMeta;
use better_auth_core::utils::password::PasswordHasher;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
use handlers::{
    change_password_core, request_password_reset_core, reset_password_core,
    reset_password_token_core, verify_password_core,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use types::{
    ChangePasswordRequest, RequestPasswordResetRequest, ResetPasswordRequest,
    ResetPasswordTokenQuery, ResetPasswordTokenResult, VerifyPasswordRequest,
};

/// Type alias for the async password-reset callback to keep Clippy happy.
pub type OnPasswordResetCallback =
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>> + Send + Sync;

/// Trait for sending password reset emails.
///
/// This callback powers `POST /request-password-reset` and is required to
/// enable that route. The user is provided as a serialized `serde_json::Value`
/// since `AuthUser` is not object-safe.
#[async_trait]
pub trait SendResetPassword: Send + Sync {
    /// Send a password reset notification.
    ///
    /// * `user` - The initialized user schema as a serialized JSON value
    /// * `url` - The full reset URL including the token
    /// * `token` - The raw reset token
    async fn send(&self, user: &serde_json::Value, url: &str, token: &str) -> AuthResult<()>;
}

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

impl std::fmt::Debug for PasswordManagementPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementPlugin")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasswordManagementPlugin")]
pub struct PasswordManagementConfig {
    #[config(default = 1)]
    pub reset_token_expiry_hours: i64,
    /// Overrides the legacy hour setting with a precise reset-token duration.
    /// Zero retains the default expiry, matching the upstream option.
    #[config(default = None)]
    pub reset_token_expiry: Option<chrono::Duration>,
    #[config(default = true)]
    pub require_current_password: bool,
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// When true, all existing sessions are revoked on password reset (default: false).
    #[config(default = false)]
    pub revoke_sessions_on_password_reset: bool,
    /// Password reset email sender for `POST /request-password-reset`.
    /// This route is disabled when no sender is configured.
    #[config(default = None)]
    pub send_reset_password: Option<Arc<dyn SendResetPassword>>,
    /// Callback invoked after a password is successfully reset.
    /// The initialized user schema is provided as a serialized JSON value.
    /// Errors propagate after the credential write and before session revocation.
    #[config(default = None)]
    pub on_password_reset: Option<Arc<OnPasswordResetCallback>>,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    /// Resetting a password inherits an initialized email/password hasher first.
    #[config(default = None)]
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl std::fmt::Debug for PasswordManagementConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementConfig")
            .field("reset_token_expiry_hours", &self.reset_token_expiry_hours)
            .field("reset_token_expiry", &self.reset_token_expiry)
            .field("require_current_password", &self.require_current_password)
            .field("send_email_notifications", &self.send_email_notifications)
            .field(
                "revoke_sessions_on_password_reset",
                &self.revoke_sessions_on_password_reset,
            )
            .field(
                "send_reset_password",
                &self.send_reset_password.as_ref().map(|_| "custom"),
            )
            .field(
                "on_password_reset",
                &self.on_password_reset.as_ref().map(|_| "custom"),
            )
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for PasswordManagementPlugin {
    fn name(&self) -> &'static str {
        "password-management"
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/request-password-reset", "request_password_reset"),
            AuthRoute::post("/reset-password", "reset_password"),
            AuthRoute::get("/reset-password/{token}", "reset_password_token"),
            AuthRoute::post("/change-password", "change_password"),
            AuthRoute::post("/verify-password", "verify_password"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/request-password-reset") => {
                Ok(Some(self.handle_request_password_reset(req, ctx).await?))
            }
            (HttpMethod::Post, "/reset-password") => {
                Ok(Some(self.handle_reset_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/change-password") => {
                Ok(Some(self.handle_change_password(req, ctx).await?))
            }
            (HttpMethod::Post, "/verify-password") => {
                Ok(Some(self.handle_verify_password(req, ctx).await?))
            }
            (HttpMethod::Get, path) if path.starts_with("/reset-password/") => {
                let token = path.get(16..).unwrap_or(""); // Remove "/reset-password/" prefix
                Ok(Some(
                    self.handle_reset_password_token(token, req, ctx).await?,
                ))
            }
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl PasswordManagementPlugin {
    async fn handle_request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: RequestPasswordResetRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = request_password_reset_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut body: ResetPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        if body.token.as_ref().is_none_or(String::is_empty) {
            body.token = req.query.get("token").cloned();
        }
        let response = reset_password_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_change_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: ChangePasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (user, _session) = ctx
            .require_authoritative_session_record(req)
            .await
            .map_err(|error| {
                if matches!(
                    error,
                    AuthError::Unauthenticated
                        | AuthError::SessionNotFound
                        | AuthError::UserNotFound
                ) {
                    AuthError::Upstream {
                        status: 401,
                        code: "UNAUTHORIZED",
                        message: "Unauthorized",
                    }
                } else {
                    error
                }
            })?;
        let meta = RequestMeta::from_request(req);

        let (response, new_token) =
            change_password_core(&body, &user, &self.config, &meta, ctx).await?;

        let auth_response = AuthResponse::json(200, &response)?;

        // Set session cookie if a new session was created
        if let Some(token) = new_token {
            use better_auth_core::utils::cookie_utils::{
                create_session_cookie_with_max_age, create_session_like_cookie,
                related_cookie_name, sign_cookie_value, verify_cookie_value,
            };
            let preference = related_cookie_name(&ctx.config, "dont_remember");
            let dont_remember = super::helpers::get_cookie(req, &preference)
                .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
                .is_some_and(|value| !value.is_empty());
            let cookie_header = create_session_cookie_with_max_age(
                Some(&token),
                (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            );
            let mut response = auth_response.with_header("Set-Cookie", cookie_header);
            if dont_remember {
                response.headers.append(
                    "Set-Cookie",
                    create_session_like_cookie(
                        &preference,
                        &sign_cookie_value("true", &ctx.config.secret),
                        None,
                        &ctx.config,
                    ),
                );
            }
            Ok(response)
        } else {
            Ok(auth_response)
        }
    }

    async fn handle_verify_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyPasswordRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let user = self.get_current_user(req, ctx).await?;
        let Some(user) = user else {
            // better-call's default body for a session-gated endpoint hit
            // without a session, which upstream returns verbatim.
            return Ok(
                AuthError::AuthenticationFailed("Unauthorized".to_owned()).to_auth_response()
            );
        };
        let response = verify_password_core(&body, &user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password_token(
        &self,
        token: &str,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let query = ResetPasswordTokenQuery {
            callback_url: req.query.get("callbackURL").cloned(),
        };
        match reset_password_token_core(token, &query, ctx).await? {
            ResetPasswordTokenResult::Redirect(url) => {
                let mut headers = better_auth_core::Headers::new();
                drop(headers.insert("Location".to_owned(), url));
                drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));
                Ok(AuthResponse {
                    status: 302,
                    headers,
                    body: Vec::new(),
                })
            }
        }
    }

    async fn get_current_user<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<S::User>> {
        let session_manager = ctx.session_manager();

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
        {
            return ctx.session_user(&session).await;
        }

        Ok(None)
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::types::RequestPasswordResetResponse;
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::AuthContext;
    use better_auth_core::config::{AuthConfig, PasswordConfig};
    use better_auth_core::utils::password::{hash_password, verify_password};
    use better_auth_core::wire::{SessionView, UserView};
    use better_auth_core::{CreateAccount, CreateUser, CreateVerification};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    const PASSWORD_RESET_SUCCESS_MESSAGE: &str =
        "If this email exists in our system, check your email for the reset link";

    struct NoopResetSender;

    #[async_trait::async_trait]
    impl SendResetPassword for NoopResetSender {
        async fn send(
            &self,
            _user: &serde_json::Value,
            _url: &str,
            _token: &str,
        ) -> AuthResult<()> {
            Ok(())
        }
    }

    fn plugin_with_reset_sender() -> PasswordManagementPlugin {
        PasswordManagementPlugin::new().send_reset_password(Arc::new(NoopResetSender))
    }

    async fn create_test_context_with_user() -> (AuthContext<TestSchema>, UserView, SessionView) {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        config.password = PasswordConfig {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
        };

        let ctx = test_helpers::create_test_context_with_config(config).await;

        // Create test user with hashed password
        let password_hash = hash_password(None, "Password123!").await.unwrap();

        let create_user = CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User");
        let user = test_helpers::create_user(&ctx, create_user).await;
        drop(
            ctx.database
                .create_account(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user.id.clone(),
                    account_id: user.id.clone(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash),
                })
                .await
                .unwrap(),
        );
        let session =
            test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

        (ctx, user, session)
    }

    async fn create_test_context_with_oauth_only_user()
    -> (AuthContext<TestSchema>, UserView, SessionView) {
        let (ctx, user, session) = create_test_context_with_user().await;

        let existing_accounts = ctx.database.get_user_accounts(&user.id).await.unwrap();
        for account in existing_accounts {
            ctx.database.delete_account(&account.id).await.unwrap();
        }

        drop(
            ctx.database
                .create_account(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user.id.clone(),
                    account_id: "google-account-id".to_owned(),
                    provider_id: "google".to_owned(),
                    access_token: Some("oauth-access-token".to_owned()),
                    refresh_token: Some("oauth-refresh-token".to_owned()),
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: Some("email profile".to_owned()),
                    password: None,
                })
                .await
                .unwrap(),
        );

        (ctx, user, session)
    }

    /// Helper: create a reset-password verification token for the given user
    /// and store it in the database. Returns the token string.
    async fn create_reset_token(
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        user_id: &str,
    ) -> String {
        let reset_token = uuid::Uuid::new_v4().simple().to_string();
        let create_verification = CreateVerification {
            identifier: format!("reset-password:{reset_token}"),
            value: user_id.to_owned(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();
        reset_token
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_request_password_reset_success() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000/reset"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin
            .handle_request_password_reset(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_request_password_reset_unknown_email() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "email": "unknown@example.com"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin
            .handle_request_password_reset(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);

        // Verify password was updated
        let accounts = ctx.database.get_user_accounts(&user.id).await.unwrap();
        let stored_hash = accounts
            .iter()
            .find(|account| account.provider_id == "credential")
            .and_then(|account| account.password.as_deref())
            .unwrap();
        assert!(
            verify_password(None, "NewPassword123!", stored_hash)
                .await
                .is_ok()
        );

        let verification_check = ctx
            .database
            .get_verification_by_identifier(&format!("reset-password:{reset_token}"))
            .await
            .unwrap();
        assert!(verification_check.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": "invalid_token"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_weak_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "weak",
            "token": reset_token
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": "false"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_null()
        ); // No new token when not revoking sessions

        // Verify password was updated by checking the database directly
        let user_id = (*(*(response_data)
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap();
        let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
        let stored_hash = accounts
            .iter()
            .find(|account| account.provider_id == "credential")
            .and_then(|account| account.password.as_deref())
            .unwrap();
        assert!(
            verify_password(None, "NewPassword123!", stored_hash)
                .await
                .is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_with_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": "true"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_string()
        ); // New token when revoking sessions
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_sets_cookie_on_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is present
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_some(),
            "Set-Cookie header must be set when revokeOtherSessions is true"
        );

        let cookie_value = set_cookie.unwrap();
        assert!(
            cookie_value.contains(&ctx.config.session.cookie_name),
            "Cookie must contain the session cookie name"
        );
        assert!(
            cookie_value.contains("Path=/"),
            "Cookie must contain Path=/"
        );
        assert!(
            cookie_value.contains("Max-Age=604800"),
            "Cookie must retain the configured session lifetime"
        );
        assert!(
            !cookie_value.contains("Expires="),
            "Source does not synthesize Expires from Max-Age"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_no_cookie_without_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is NOT present when not revoking sessions
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_none(),
            "Set-Cookie header must not be set when revokeOtherSessions is not true"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_revoke_with_boolean() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Send revokeOtherSessions as a boolean (as better-auth TS SDK does)
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_string(),
            "New token must be returned when revokeOtherSessions is boolean true"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_wrong_current_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "WrongPassword123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_unauthorized() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
    // a valid session and the correct credential password succeeds.
    #[tokio::test]
    async fn test_verify_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
    // a bad password returns BAD_REQUEST / Invalid password.
    #[tokio::test]
    async fn test_verify_password_invalid_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "wrong-password"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.to_string(), "Invalid password");
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.ts :: verifyPassword returns
    // Invalid password when the signed-in user does not have a credential account.
    #[tokio::test]
    async fn test_verify_password_oauth_only_user_returns_invalid_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_oauth_only_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.to_string(), "Invalid password");
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword
    // requires an authenticated session.
    #[tokio::test]
    async fn test_verify_password_requires_session() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        // Upstream returns better-call's default 401 body rather than an empty one.
        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("code").unwrap_or(&serde_json::Value::Null)),
            "UNAUTHORIZED"
        );
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Unauthorized"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_redirects_with_callback_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );

        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains("http://localhost:3000/reset"),
            "redirect must preserve the callback URL"
        );
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains(&format!("token={reset_token}")),
            "redirect must contain the reset token"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_with_callback() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );

        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);

        // Check redirect URL
        let location_header = response
            .headers
            .iter()
            .find(|(key, _)| *key == "Location")
            .map(|(_, value)| value);
        assert!(location_header.is_some());
        assert!(
            location_header
                .unwrap()
                .contains("http://localhost:3000/reset")
        );
        assert!(location_header.unwrap().contains(&reset_token));
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );
        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token("invalid_token", &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains("error=INVALID_TOKEN")
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = PasswordManagementPlugin::new();
        let routes = AuthPlugin::<
            better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::routes(&plugin);

        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/request-password-reset" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password/{token}" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/verify-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/change-password" && r.method == HttpMethod::Post)
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({"email": "test@example.com"});
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);

        // Test change password
        let body_2 = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });
        let req_2 = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body_2.to_string().into_bytes()),
        );
        let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap();
        assert!(response_2.is_some());
        assert_eq!(response_2.unwrap().status, 200);

        // Test invalid route
        let req_3 = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/invalid-route",
            None,
            None,
        );
        let response_3 = plugin.on_request(&req_3, &ctx).await.unwrap();
        assert!(response_3.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_configuration() {
        let config = PasswordManagementConfig {
            reset_token_expiry_hours: 48,
            require_current_password: false,
            send_email_notifications: false,
            ..Default::default()
        };

        let plugin = PasswordManagementPlugin::with_config(config);
        assert_eq!(plugin.config.reset_token_expiry_hours, 48);
        assert!(!plugin.config.require_current_password);
        assert!(!plugin.config.send_email_notifications);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_send_reset_password_custom_sender() {
        use better_auth_core::{BackgroundTaskCompletion, BackgroundTaskHandler};
        use std::sync::{
            Mutex,
            atomic::{AtomicU32, Ordering},
        };

        struct Sender {
            calls: Arc<AtomicU32>,
            fail: bool,
            token: Arc<Mutex<Option<String>>>,
        }
        #[async_trait::async_trait]
        impl SendResetPassword for Sender {
            async fn send(&self, _: &serde_json::Value, _: &str, token: &str) -> AuthResult<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self.token.lock().unwrap() = Some(token.to_owned());
                if self.fail {
                    Err(AuthError::internal("Email queue unavailable"))
                } else {
                    Ok(())
                }
            }
        }
        #[derive(Default)]
        struct Observer(Mutex<Option<BackgroundTaskCompletion>>);
        impl BackgroundTaskHandler for Observer {
            fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
                *self.0.lock().unwrap() = Some(completion);
                Ok(())
            }
        }
        for (fail, background) in [(false, false), (true, false), (true, true)] {
            let calls = Arc::new(AtomicU32::new(0));
            let token = Arc::new(Mutex::new(None));
            let plugin = PasswordManagementPlugin::new().send_reset_password(Arc::new(Sender {
                calls: Arc::clone(&calls),
                fail,
                token: Arc::clone(&token),
            }));
            let (mut ctx, user, _) = create_test_context_with_user().await;
            let observer = Arc::new(Observer::default());
            if background {
                Arc::make_mut(&mut ctx.config).background_tasks = Some(observer.clone());
            }
            let req = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                "/request-password-reset",
                None,
                Some(serde_json::json!({"email":"test@example.com"})),
            );
            let result = plugin.handle_request_password_reset(&req, &ctx).await;
            if fail && !background {
                assert_eq!(result.unwrap_err().status_code(), 500);
            } else {
                assert_eq!(result.unwrap().status, 200);
            }
            if background {
                let completion = observer.0.lock().unwrap().take().unwrap();
                completion.await.unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let token = token.lock().unwrap().take().unwrap();
            let proof = ctx
                .database
                .get_verification_by_identifier(&format!("reset-password:{token}"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.value, user.id);
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_on_password_reset_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let callback_called = Arc::new(AtomicBool::new(false));
        let called_clone = std::sync::Arc::clone(&callback_called);

        let callback: Arc<OnPasswordResetCallback> = Arc::new(move |_user_value| {
            let called = std::sync::Arc::clone(&called_clone);
            Box::pin(async move {
                called.store(true, Ordering::SeqCst);
                Ok(())
            })
        });

        let plugin = PasswordManagementPlugin::new().on_password_reset(callback);
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // The on_password_reset callback should have been called
        assert!(
            callback_called.load(Ordering::SeqCst),
            "on_password_reset callback should be invoked after password reset"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_revoke_sessions_on_password_reset_false() {
        let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(false);
        let (ctx, user, session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Session should still exist since revoke_sessions_on_password_reset=false
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(
            !sessions.is_empty(),
            "Sessions should remain when revoke_sessions_on_password_reset=false"
        );
        assert!(
            sessions.iter().any(|s| s.token == session.token),
            "The original session should still exist"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_revoke_sessions_on_password_reset_true() {
        let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(true);
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Sessions should be revoked since revoke_sessions_on_password_reset=true (default)
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(
            sessions.is_empty(),
            "Sessions should be revoked when revoke_sessions_on_password_reset=true"
        );
    }
}
// LCOV_EXCL_STOP
