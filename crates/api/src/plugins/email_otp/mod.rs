//! Passwordless email authentication and verification using single-use codes.
//!
//! [`EmailOtpPlugin::create_verification_otp`] and
//! [`EmailOtpPlugin::get_verification_otp`] are server-only operations. Neither
//! operation registers an HTTP endpoint.

mod handlers;

mod helpers;

mod storage;

mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use better_auth_core::{AuthContext, AuthRequest, AuthResponse, AuthResult};
use chrono::Duration;
use std::sync::Arc;
pub use storage::{EmailOtpCodec, EmailOtpStorage};
pub use types::{EmailOtpDelivery, EmailOtpType, OtpResendStrategy};

/// Delivers a code to its intended mailbox. The default notification policy
/// awaits and logs callback errors while retaining the issued verification.
#[async_trait]
pub trait SendEmailOtp: Send + Sync {
    async fn send(&self, delivery: &EmailOtpDelivery) -> AuthResult<()>;
}

/// Optional application code generator. Returning `None` selects the default
/// cryptographically random numeric generator.
#[async_trait]
pub trait EmailOtpGenerator: Send + Sync {
    async fn generate(&self, email: &str, otp_type: EmailOtpType) -> AuthResult<Option<String>>;
}

/// Configuration for email OTP verification, login, password reset and email change.
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct EmailOtpConfig {
    pub send_verification_otp: Option<Arc<dyn SendEmailOtp>>,
    pub generate_otp: Option<Arc<dyn EmailOtpGenerator>>,
    pub otp_length: usize,
    pub expires_in: Duration,
    pub allowed_attempts: usize,
    pub storage: EmailOtpStorage,
    pub resend_strategy: OtpResendStrategy,
    pub disable_sign_up: bool,
    pub send_verification_on_sign_up: bool,
    pub override_default_email_verification: bool,
    pub change_email_enabled: bool,
    pub verify_current_email: bool,
    pub auto_sign_in_after_verification: bool,
    pub before_email_verification: Option<super::email_verification::EmailVerificationHook>,
    pub after_email_verification: Option<super::email_verification::EmailVerificationHook>,
    pub password_hasher: Option<Arc<dyn better_auth_core::PasswordHasher>>,
    pub max_password_length: usize,
    pub revoke_sessions_on_password_reset: bool,
    pub on_password_reset: Option<Arc<super::password_management::OnPasswordResetCallback>>,
}

impl std::fmt::Debug for EmailOtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpConfig").finish_non_exhaustive()
    }
}

impl Default for EmailOtpConfig {
    fn default() -> Self {
        Self {
            send_verification_otp: None,
            generate_otp: None,
            otp_length: 6,
            expires_in: Duration::seconds(300),
            allowed_attempts: 3,
            storage: EmailOtpStorage::Plain,
            resend_strategy: OtpResendStrategy::Rotate,
            disable_sign_up: false,
            send_verification_on_sign_up: false,
            override_default_email_verification: false,
            change_email_enabled: false,
            verify_current_email: false,
            auto_sign_in_after_verification: false,
            before_email_verification: None,
            after_email_verification: None,
            password_hasher: None,
            max_password_length: 128,
            revoke_sessions_on_password_reset: false,
            on_password_reset: None,
        }
    }
}

#[derive(Clone)]
pub struct EmailOtpPlugin {
    config: EmailOtpConfig,
}

impl std::fmt::Debug for EmailOtpPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpPlugin").finish_non_exhaustive()
    }
}

impl EmailOtpPlugin {
    #[must_use]
    pub const fn new(config: EmailOtpConfig) -> Self {
        Self { config }
    }

    fn verification_settings(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> VerificationSettings {
        let inherited = ctx
            .extensions
            .get::<super::email_verification::EmailVerificationConfig>();
        VerificationSettings {
            before: inherited
                .as_ref()
                .and_then(|config| config.before_email_verification.clone())
                .or_else(|| self.config.before_email_verification.clone()),
            after: inherited
                .as_ref()
                .and_then(|config| config.after_email_verification.clone())
                .or_else(|| self.config.after_email_verification.clone()),
            auto_sign_in: inherited
                .as_ref()
                .is_some_and(|config| config.auto_sign_in_after_verification)
                || self.config.auto_sign_in_after_verification,
        }
    }

    fn password_settings(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> PasswordSettings {
        let passwords = ctx
            .extensions
            .get::<super::email_password::EmailPasswordConfig>();
        let resets = ctx
            .extensions
            .get::<super::password_management::PasswordManagementConfig>();
        PasswordSettings {
            minimum: passwords
                .as_ref()
                .map_or(ctx.config.password.min_length, |config| {
                    config.password_min_length
                }),
            maximum: passwords
                .as_ref()
                .map_or(self.config.max_password_length, |config| {
                    config.password_max_length
                }),
            hasher: resets
                .as_ref()
                .and_then(|config| config.password_hasher.clone())
                .or_else(|| {
                    let config = passwords.as_ref()?;
                    config.password_hasher.clone()
                })
                .or_else(|| self.config.password_hasher.clone()),
            on_reset: resets
                .as_ref()
                .and_then(|config| config.on_password_reset.clone())
                .or_else(|| self.config.on_password_reset.clone()),
            revoke_sessions: resets
                .as_ref()
                .is_some_and(|config| config.revoke_sessions_on_password_reset)
                || self.config.revoke_sessions_on_password_reset,
        }
    }

    /// Create and persist a code without delivering it or checking whether the
    /// mailbox has an account. This operation is available only to server code.
    ///
    /// # Errors
    ///
    /// Returns an error if OTP generation, encoding, or persistence fails.
    pub async fn create_verification_otp(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        email: &str,
        otp_type: EmailOtpType,
    ) -> AuthResult<String> {
        self.issue_code(ctx, &email.to_lowercase(), otp_type, None)
            .await
    }

    /// Retrieve a live plaintext/decryptable code without consuming it.
    /// Hashed storage rejects this operation, since a hash cannot reveal a code.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or the configured OTP representation cannot be recovered.
    pub async fn get_verification_otp(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        email: &str,
        otp_type: EmailOtpType,
    ) -> AuthResult<Option<String>> {
        let identifier = types::identifier(otp_type, &email.to_lowercase());
        let Some(value) =
            super::authentication_helpers::find_verification(ctx, &identifier).await?
        else {
            return Ok(None);
        };
        if value.is_expired() {
            return Ok(None);
        }
        let (stored, _) = types::split_value(value.value()?);
        self.config
            .storage
            .retrieve(stored, &ctx.config.secret)
            .await
    }
}

struct VerificationSettings {
    before: Option<super::email_verification::EmailVerificationHook>,
    after: Option<super::email_verification::EmailVerificationHook>,
    auto_sign_in: bool,
}

struct PasswordSettings {
    minimum: usize,
    maximum: usize,
    hasher: Option<Arc<dyn better_auth_core::PasswordHasher>>,
    on_reset: Option<Arc<super::password_management::OnPasswordResetCallback>>,
    revoke_sessions: bool,
}

better_auth_core::impl_auth_plugin! {
    EmailOtpPlugin, "email-otp";
    routes {
        post "/email-otp/send-verification-otp" => send_verification, "sendEmailVerificationOTP";
        post "/email-otp/check-verification-otp" => check_verification, "verifyEmailWithOTP";
        post "/email-otp/verify-email" => verify_email, "verifyEmailOTP";
        post "/sign-in/email-otp" => sign_in, "signInWithEmailOTP";
        post "/email-otp/request-password-reset" => request_password_reset, "requestPasswordResetWithEmailOTP";
        post "/forget-password/email-otp" => request_password_reset, "forgetPasswordWithEmailOTP";
        post "/email-otp/reset-password" => reset_password, "resetPasswordWithEmailOTP";
        post "/email-otp/request-email-change" => request_email_change, "requestEmailChangeWithEmailOTP";
        post "/email-otp/change-email" => change_email, "changeEmailWithEmailOTP";
    }
    extra {
        async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
            ctx.set_metadata("email-otp.enabled", serde_json::json!(true));
            if self.config.override_default_email_verification {
                ctx.set_email_verification_override(Arc::new(self.clone()));
            }
            Ok(())
        }

        async fn after_request(
            &self,
            req: &AuthRequest,
            ctx: &AuthContext<S>,
            response: AuthResponse,
        ) -> AuthResult<AuthResponse> {
            if response.status < 400 && req.path().starts_with("/sign-up")
                && self.config.send_verification_on_sign_up
                && !self.config.override_default_email_verification
            {
                let value: serde_json::Value = serde_json::from_slice(&response.body)?;
                if let Some(email) = value.get("user").and_then(|user| user.get("email")).and_then(serde_json::Value::as_str) {
                    let otp = self.issue_code(ctx, email, EmailOtpType::EmailVerification, None).await?;
                    self.deliver(email, otp, EmailOtpType::EmailVerification).await?;
                }
            }
            Ok(response)
        }
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> better_auth_core::VerificationEmailOverride<S>
    for EmailOtpPlugin
{
    async fn send(
        &self,
        user: &better_auth_core::wire::UserView,
        _request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        let Some(email) = user.email.as_deref() else {
            return Ok(());
        };
        let body = serde_json::json!({"email":email,"type":"email-verification"});
        let mut req = AuthRequest::new(
            better_auth_core::HttpMethod::Post,
            "/email-otp/send-verification-otp",
        );
        req.body = Some(serde_json::to_vec(&body)?);
        drop(self.send_verification(&req, ctx).await?);
        Ok(())
    }

    async fn send_in_transaction(
        &self,
        user: &better_auth_core::wire::UserView,
        _request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        tx: &dyn better_auth_core::store::AuthTransaction<S>,
    ) -> AuthResult<()> {
        let Some(email) = user.email.as_deref() else {
            return Ok(());
        };
        let email = crate::plugins::authentication_helpers::parse_email(email)?;
        let (otp, value) = self
            .prepare_code(ctx, &email, EmailOtpType::EmailVerification, None)
            .await?;
        drop(ctx.verifications().create_in_transaction(tx, value).await?);
        self.deliver(&email, otp, EmailOtpType::EmailVerification)
            .await
    }
}
