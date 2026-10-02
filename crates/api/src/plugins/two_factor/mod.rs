mod backup_storage;

mod otp_storage;

mod otp;

#[cfg(test)]
mod tests;

use super::StatusResponse;
use crate::plugins::helpers::{
    SessionIssueError, get_cookie, get_credential_password_hash, issue_user_session,
    issue_user_session_with_overrides,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
pub use backup_storage::{TwoFactorBackupCipher, TwoFactorBackupStorage};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::entity::{AuthSession, AuthTwoFactor, AuthUser, AuthVerification};
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie, create_session_cookie_with_max_age,
    create_session_like_cookie, related_cookie_name,
};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateTwoFactor,
    CreateVerification, RequestMeta, TwoFactor, UpdateTwoFactor, UpdateUser,
};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
pub use otp_storage::{TwoFactorOtpCipher, TwoFactorOtpHasher, TwoFactorOtpStorage};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt::Write;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use validator::Validate;

const TWO_FACTOR_COOKIE_SUFFIX: &str = "two_factor";

const TRUST_DEVICE_COOKIE_SUFFIX: &str = "trust_device";

const DONT_REMEMBER_COOKIE_SUFFIX: &str = "dont_remember";

const METADATA_ENABLED: &str = "two_factor.enabled";

const METADATA_OTP_ENABLED: &str = "two_factor.otp_enabled";

const METADATA_TWO_FACTOR_COOKIE_MAX_AGE: &str = "two_factor.two_factor_cookie_max_age";

const METADATA_TRUST_DEVICE_MAX_AGE: &str = "two_factor.trust_device_max_age";

const METADATA_TOTP_DISABLED: &str = "two_factor.totp_disabled";

const DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS: f64 = 600.0;

const DEFAULT_TRUST_DEVICE_MAX_AGE_SECS: f64 = 2_592_000.0;

#[derive(Clone, Copy)]
struct TwoFactorCookiePolicy {
    challenge_max_age: f64,
    trust_max_age: f64,
}

const DEFAULT_TOTP_PERIOD_SECS: u64 = 30;

const DEFAULT_TOTP_DIGITS: usize = 6;

const ENCRYPTION_INFO: &[u8] = b"better-auth-two-factor-encryption";

type HmacSha256 = Hmac<Sha256>;

/// Callback used by the two-factor plugin to deliver a one-time password.
#[async_trait]
pub trait SendTwoFactorOtp: Send + Sync {
    /// Send a one-time password to the given user.
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()>;
}

/// Two-factor authentication plugin providing TOTP, OTP, and backup code flows.
#[derive(Clone)]
pub struct TwoFactorPlugin {
    config: TwoFactorConfig,
}

/// Consecutive failed sign-in verifications across factors and challenges.
#[derive(Debug, Clone)]
pub struct AccountLockoutConfig {
    pub enabled: bool,
    pub max_failed_attempts: f64,
    pub duration_seconds: f64,
}

impl Default for AccountLockoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 10.0,
            duration_seconds: 900.0,
        }
    }
}

/// Public configuration for the two-factor plugin.
#[derive(Clone, better_auth_core::PluginConfig)]
#[plugin(name = "TwoFactorPlugin")]
pub struct TwoFactorConfig {
    /// Allow omission of passwords for users without a stored credential hash.
    #[config(default = false)]
    pub allow_passwordless: bool,
    /// Override the global passwordless policy for existing TOTP URI retrieval.
    #[config(default = None)]
    pub totp_allow_passwordless: Option<bool>,
    /// Override the global passwordless policy for backup regeneration.
    #[config(default = None)]
    pub backup_allow_passwordless: Option<bool>,
    /// Number of generated backup codes, using JS array-length coercion.
    #[config(default = 10.0)]
    pub backup_code_amount: f64,
    /// Generated characters per code, before the separator after character five.
    #[config(default = 10.0)]
    pub backup_code_length: f64,
    /// Optional synchronous generator. Its strings are persisted unchanged.
    #[config(default = None, skip)]
    pub custom_backup_codes_generate:
        Option<Arc<dyn Fn() -> AuthResult<Vec<String>> + Send + Sync>>,
    #[config(default = TwoFactorBackupStorage::default(), skip)]
    pub backup_storage: TwoFactorBackupStorage,
    #[config(default = AccountLockoutConfig::default())]
    pub account_lockout: AccountLockoutConfig,
    /// Override the issuer embedded in enrollment TOTP URIs.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Skip the enrollment verification step and enable 2FA immediately.
    #[config(default = false)]
    pub skip_verification_on_enable: bool,
    /// Pending challenge lifetime in seconds, including fractions and explicit zero.
    #[config(default = DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)]
    pub two_factor_cookie_max_age: f64,
    /// Trusted proof lifetime in seconds; negative values omit cookie Max-Age.
    #[config(default = DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)]
    pub trust_device_max_age: f64,
    /// TOTP period in seconds.
    #[config(default = DEFAULT_TOTP_PERIOD_SECS)]
    pub totp_period: u64,
    /// TOTP digit count.
    #[config(default = DEFAULT_TOTP_DIGITS)]
    pub totp_digits: usize,
    /// Issuer used when retrieving an existing authenticator URI.
    #[config(default = None)]
    pub totp_issuer: Option<String>,
    /// Reject TOTP enrollment, URI retrieval, verification and server generation.
    #[config(default = false)]
    pub totp_disabled: bool,
    /// Optional OTP sender callback. When absent, `/two-factor/send-otp` is disabled.
    #[config(default = None, skip)]
    pub send_otp: Option<Arc<dyn SendTwoFactorOtp>>,
    /// Number of decimal digits in delivered OTPs, following JS numeric length.
    #[config(default = 6.0)]
    pub otp_digits: f64,
    /// OTP lifetime in minutes; zero selects the pinned three-minute default.
    #[config(default = 3.0)]
    pub otp_period_minutes: f64,
    /// Failed OTP budget; zero selects the pinned five-attempt default.
    #[config(default = 5.0)]
    pub otp_allowed_attempts: f64,
    #[config(default = TwoFactorOtpStorage::default(), skip)]
    pub otp_storage: TwoFactorOtpStorage,
}

impl std::fmt::Debug for TwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorConfig")
            .field("allow_passwordless", &self.allow_passwordless)
            .field("totp_allow_passwordless", &self.totp_allow_passwordless)
            .field("backup_allow_passwordless", &self.backup_allow_passwordless)
            .field("backup_code_amount", &self.backup_code_amount)
            .field("backup_code_length", &self.backup_code_length)
            .field(
                "custom_backup_codes_generate",
                &self.custom_backup_codes_generate.is_some(),
            )
            .field("backup_storage", &self.backup_storage)
            .field("account_lockout", &self.account_lockout)
            .field("issuer", &self.issuer)
            .field(
                "skip_verification_on_enable",
                &self.skip_verification_on_enable,
            )
            .field("two_factor_cookie_max_age", &self.two_factor_cookie_max_age)
            .field("trust_device_max_age", &self.trust_device_max_age)
            .field("totp_period", &self.totp_period)
            .field("totp_digits", &self.totp_digits)
            .field("totp_issuer", &self.totp_issuer)
            .field("totp_disabled", &self.totp_disabled)
            .field("send_otp", &self.send_otp.as_ref().map(|_| "custom"))
            .field("otp_digits", &self.otp_digits)
            .field("otp_period_minutes", &self.otp_period_minutes)
            .field("otp_allowed_attempts", &self.otp_allowed_attempts)
            .field("otp_storage", &self.otp_storage)
            .finish()
    }
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct EnableRequest {
    password: Option<String>,
    #[serde(default)]
    method: EnableMethod,
    issuer: Option<String>,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum EnableMethod {
    Otp,
    #[default]
    Totp,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct DisableRequest {
    password: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct GetTotpUriRequest {
    password: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct VerifyTotpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Deserialize)]
struct SendOtpRequest {
    #[serde(rename = "trustDevice")]
    _trust_device: Option<bool>,
}

impl crate::plugins::authentication_helpers::RequestBody for SendOtpRequest {
    const FIELDS: &'static [crate::plugins::authentication_helpers::JsonField] =
        &[crate::plugins::authentication_helpers::JsonField {
            name: "trustDevice",
            kind: crate::plugins::authentication_helpers::JsonFieldKind::Boolean,
            required: false,
        }];
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct VerifyOtpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct GenerateBackupCodesRequest {
    password: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct VerifyBackupCodeRequest {
    code: String,
    #[serde(rename = "disableSession")]
    disable_session: Option<bool>,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub(in crate::plugins) enum EnableResponse {
    Otp,
    Totp {
        #[serde(rename = "totpURI")]
        totp_uri: String,
        #[serde(rename = "backupCodes")]
        backup_codes: Vec<String>,
    },
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct TotpUriResponse {
    #[serde(rename = "totpURI")]
    totp_uri: String,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct SessionTokenResponse<U> {
    token: String,
    user: U,
}

#[derive(Debug, Serialize)]
struct BackupVerificationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    user: UserView,
}

impl From<SessionTokenResponse<UserView>> for BackupVerificationResponse {
    fn from(response: SessionTokenResponse<UserView>) -> Self {
        Self {
            token: Some(response.token),
            user: response.user,
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct BackupCodesResponse {
    status: bool,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct TwoFactorRedirectResponse {
    #[serde(rename = "twoFactorRedirect")]
    two_factor_redirect: bool,
    /// Second factors this user can actually complete, so the client knows
    /// which challenge to present.
    #[serde(rename = "twoFactorMethods")]
    two_factor_methods: Vec<&'static str>,
}

struct PendingTwoFactorState<S: better_auth_core::AuthSchema> {
    user: S::User,
    verification: S::Verification,
    key: String,
    dont_remember: bool,
}

enum ResolvedTwoFactorState<S: better_auth_core::AuthSchema> {
    Session {
        user: better_auth_core::AuthenticatedUser<S>,
        session: Box<better_auth_core::wire::SessionView>,
        key: String,
    },
    Pending(PendingTwoFactorState<S>),
}

pub(in crate::plugins) struct SignInTwoFactorRedirect {
    pub response: TwoFactorRedirectResponse,
    pub set_cookie_headers: Vec<String>,
}

pub(in crate::plugins) struct TrustedDeviceCheck {
    pub trusted: bool,
    pub set_cookie_headers: Vec<String>,
}

impl TwoFactorPlugin {
    /// Install a custom OTP sender.
    #[must_use]
    pub fn custom_send_otp(mut self, sender: Arc<dyn SendTwoFactorOtp>) -> Self {
        self.config.send_otp = Some(sender);
        self
    }

    /// Generate a current TOTP from an application-owned UTF-8 secret.
    ///
    /// This corresponds to `auth.api.generateTOTP`; it has no public HTTP route.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret cannot be decoded or the TOTP configuration is invalid.
    pub fn generate_totp(&self, secret: &str) -> AuthResult<String> {
        require_totp_enabled(&self.config)?;
        build_totp(&self.config, secret)?
            .generate_current()
            .map_err(|error| AuthError::internal(format!("Failed to generate TOTP: {error}")))
    }

    /// Read the currently stored backup codes for a user.
    ///
    /// This is the Rust server-side equivalent of the TypeScript
    /// `auth.api.viewBackupCodes` capability. It is intentionally not exposed
    /// as a public HTTP route.
    ///
    /// # Errors
    ///
    /// Returns an error if backup codes are unavailable, cannot be decrypted, or cannot be loaded.
    pub async fn view_backup_codes<S: better_auth_core::AuthSchema>(
        &self,
        user_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Vec<String>> {
        view_backup_codes_core(user_id, &self.config, ctx).await
    }
}

better_auth_core::impl_auth_plugin! {
    TwoFactorPlugin, "two-factor";
    routes {
        post "/two-factor/enable" => handle_enable, "enable_two_factor";
        post "/two-factor/disable" => handle_disable, "disable_two_factor";
        post "/two-factor/get-totp-uri" => handle_get_totp_uri, "get_totp_uri";
        post "/two-factor/verify-totp" => handle_verify_totp, "verify_totp";
        post "/two-factor/send-otp" => handle_send_otp, "send_otp";
        post "/two-factor/verify-otp" => handle_verify_otp, "verify_otp";
        post "/two-factor/generate-backup-codes" => handle_generate_backup_codes, "generate_backup_codes";
        post "/two-factor/verify-backup-code" => handle_verify_backup_code, "verify_backup_code";
    }
    extra {
        async fn on_init(
            &self,
            ctx: &mut better_auth_core::AuthInitContext<S>,
        ) -> AuthResult<()> {
            let default = |mut input: better_auth_core::CreateUser| {
                _ = input.two_factor_enabled.get_or_insert(false);
                Ok(input)
            };
            if ctx.config.user_validation.is_some() {ctx.register_user_creation_adapter_default(default);}
            else {ctx.register_user_create_transform(default);}
            ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
            ctx.set_metadata(METADATA_TOTP_DISABLED, serde_json::Value::Bool(self.config.totp_disabled));
            ctx.set_metadata(
                METADATA_OTP_ENABLED,
                serde_json::Value::Bool(self.config.send_otp.is_some()),
            );
            ctx.set_metadata(
                METADATA_TWO_FACTOR_COOKIE_MAX_AGE,
                serde_json::Number::from_f64(self.config.two_factor_cookie_max_age)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number),
            );
            ctx.set_metadata(
                METADATA_TRUST_DEVICE_MAX_AGE,
                serde_json::Number::from_f64(self.config.trust_device_max_age)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number),
            );
            ctx.extensions.insert(TwoFactorCookiePolicy {
                challenge_max_age: self.config.two_factor_cookie_max_age,
                trust_max_age: self.config.trust_device_max_age,
            });
            Ok(())
        }
    }
}

impl TwoFactorPlugin {
    async fn handle_enable(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: EnableRequest =
            match parse_password_body(req, self.config.allow_passwordless, true) {
                Ok(body) => body,
                Err(response) => return Ok(response),
            };
        let (user, session) = super::helpers::ordinary_session(req, ctx).await?;

        let (response, set_cookie_headers) =
            match enable_core(&body, &user, &session, &self.config, ctx).await {
                Ok(result) => result,
                Err(
                    BackupOperationError::Auth(AuthError::SessionCreationCancelled)
                    | BackupOperationError::InvalidGeneration,
                ) => {
                    return Ok(AuthResponse::new(500));
                }
                Err(BackupOperationError::Auth(error)) => return Err(error),
            };
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_disable(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DisableRequest =
            match parse_password_body(req, self.config.allow_passwordless, false) {
                Ok(v) => v,
                Err(resp) => return Ok(resp),
            };
        let (user, session) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated | AuthError::SessionNotFound => AuthError::Upstream {
                    status: 401,
                    code: "UNAUTHORIZED",
                    message: "Unauthorized",
                },
                other @ (AuthError::Api { .. }
                | AuthError::Upstream { .. }
                | AuthError::BadRequest(_)
                | AuthError::InvalidRequest(_)
                | AuthError::Validation(_)
                | AuthError::InvalidCredentials
                | AuthError::AuthenticationFailed(_)
                | AuthError::Forbidden(_)
                | AuthError::UserCreationCancelled
                | AuthError::SessionCreationCancelled
                | AuthError::BannedUser(_)
                | AuthError::Unauthorized
                | AuthError::UserNotFound
                | AuthError::NotFound(_)
                | AuthError::Conflict(_)
                | AuthError::MethodNotAllowed(_)
                | AuthError::PayloadTooLarge(_)
                | AuthError::UnprocessableEntity(_)
                | AuthError::RateLimited
                | AuthError::NotImplemented(_)
                | AuthError::Config(_)
                | AuthError::Database(_)
                | AuthError::Serialization(_)
                | AuthError::Plugin { .. }
                | AuthError::CallbackFailure(_)
                | AuthError::Internal(_)
                | AuthError::PasswordHash(_)
                | AuthError::Jwt(_)) => other,
            })?;

        let (response, set_cookie_headers) =
            disable_core(&body, &user, &session, req, &self.config, ctx).await?;
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_get_totp_uri(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let allow_passwordless = self
            .config
            .totp_allow_passwordless
            .unwrap_or(self.config.allow_passwordless);
        let body: GetTotpUriRequest = match parse_password_body(req, allow_passwordless, false) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = get_totp_uri_core(&body, &user, &self.config, ctx).await?;
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_totp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyTotpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            match verify_totp_core(req, &body, &self.config, ctx).await {
                Ok(result) => result,
                Err(error) => return verification_error_response(error, ctx),
            };
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_send_otp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) =
            crate::plugins::authentication_helpers::parse_body::<SendOtpRequest>(req)
        {
            return Ok(response);
        }
        let response = match send_otp_core(req, &self.config, ctx).await {
            Ok(response) => response,
            Err(SendOtpError::NonpositiveLength) => return Ok(AuthResponse::new(500)),
            Err(SendOtpError::Auth(error)) => return Err(error),
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_otp(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyOtpRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            match verify_otp_core(req, &body, &self.config, ctx).await {
                Ok(result) => result,
                Err(ExistingSessionFactorError::SessionCreationCancelled) => {
                    return Ok(AuthResponse::new(500));
                }
                // OTP's own code budget does not expire the pending-factor cookie.
                Err(ExistingSessionFactorError::Auth(
                    error @ AuthError::Upstream {
                        code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
                        ..
                    },
                )) => return Err(error),
                Err(ExistingSessionFactorError::Auth(error)) => {
                    return verification_error_response(error, ctx);
                }
            };
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }

    async fn handle_generate_backup_codes(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let allow_passwordless = self
            .config
            .backup_allow_passwordless
            .unwrap_or(self.config.allow_passwordless);
        let body: GenerateBackupCodesRequest =
            match parse_password_body(req, allow_passwordless, false) {
                Ok(v) => v,
                Err(resp) => return Ok(resp),
            };

        let response = match generate_backup_codes_core(&body, &user, &self.config, ctx).await {
            Ok(response) => response,
            Err(BackupOperationError::InvalidGeneration) => return Ok(AuthResponse::new(500)),
            Err(BackupOperationError::Auth(error)) => return Err(error),
        };
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    async fn handle_verify_backup_code(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyBackupCodeRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            match verify_backup_code_core(req, &body, &self.config, ctx).await {
                Ok(result) => result,
                Err(error) => return verification_error_response(error, ctx),
            };
        let mut auth_response = AuthResponse::json(200, &response)?;
        for cookie in set_cookie_headers {
            auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
        }
        Ok(auth_response)
    }
}

enum SendOtpError {
    Auth(AuthError),
    // The pinned random-string generator throws before storage or delivery.
    NonpositiveLength,
}

impl From<AuthError> for SendOtpError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

struct FactorAttempt {
    identifier: String,
    count: f64,
    expires_at: chrono::DateTime<Utc>,
}

// Only an explicitly cancelled session creation is distinguished. The same
// AuthError from user updates or other operations retains its default response.
enum ExistingSessionFactorError {
    Auth(AuthError),
    SessionCreationCancelled,
}

impl From<AuthError> for ExistingSessionFactorError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl ExistingSessionFactorError {
    fn into_auth_error(self) -> AuthError {
        match self {
            Self::Auth(error) => error,
            Self::SessionCreationCancelled => AuthError::SessionCreationCancelled,
        }
    }
}

enum BackupOperationError {
    Auth(AuthError),
    InvalidGeneration,
}

impl From<AuthError> for BackupOperationError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl<S: better_auth_core::AuthSchema> ResolvedTwoFactorState<S> {
    fn user(&self) -> better_auth_core::AuthenticatedUser<S> {
        match self {
            Self::Session { user, .. } => user.clone(),
            Self::Pending(pending) => {
                better_auth_core::AuthenticatedUser::Stored(pending.user.clone())
            }
        }
    }

    fn key(&self) -> &str {
        match self {
            Self::Session { key, .. } => key,
            Self::Pending(pending) => &pending.key,
        }
    }
}

impl std::fmt::Debug for TwoFactorPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorPlugin").finish_non_exhaustive()
    }
}

pub(in crate::plugins) fn is_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
    ctx.get_metadata(METADATA_ENABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn inspect_trusted_device(
    req: &AuthRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TrustedDeviceCheck> {
    let cookie_name = related_cookie_name(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    let clear_header = create_clear_cookie(&cookie_name, &ctx.config);
    let Some(signed_value) = verify_trusted_device_cookie_value(&ctx.config.secret, &raw_cookie)
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: Vec::new(),
        });
    };

    // The source tests outer payload truthiness before expiring a cookie,
    // then destructures only the first two components and ignores the rest.
    let mut components = signed_value.split('!');
    let token = components.next().unwrap_or_default();
    let trust_identifier = components.next().unwrap_or_default();
    if token.is_empty() || trust_identifier.is_empty() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    let expected_token = sign_value(
        &ctx.config.secret,
        &format!("{}!{}", user.id(), trust_identifier),
    )?;
    if token != expected_token {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    let Some(verification) =
        super::authentication_helpers::find_verification(ctx, trust_identifier).await?
    else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    if verification.value() != user.id().as_ref() || verification.expires_at() <= Utc::now() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    ctx.database
        .delete_verification(verification.id().as_ref())
        .await?;

    let rotated_cookie = create_trust_device_cookie_header(user, ctx).await?;
    Ok(TrustedDeviceCheck {
        trusted: true,
        set_cookie_headers: vec![rotated_cookie],
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn begin_sign_in_challenge(
    user: &impl AuthUser,
    remember_me: Option<bool>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInTwoFactorRedirect> {
    let identifier = format!("2fa-{}", uuid::Uuid::new_v4());
    let expires_at = cookie_expiry(two_factor_cookie_max_age(ctx))?;
    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );
    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier: format!("2fa-attempts-{identifier}"),
                value: "0".to_owned(),
                expires_at,
            })
            .await?,
    );

    let incoming = better_auth_core::hooks::current_request_hook_context()
        .map(|request| request.headers.clone())
        .unwrap_or_default();
    let mut headers =
        better_auth_core::cache::runtime::session_cleanup_headers(&ctx.config, &incoming, true)?;
    headers.retain(|cookie| {
        !cookie.starts_with(&format!(
            "{}=",
            related_cookie_name(&ctx.config, DONT_REMEMBER_COOKIE_SUFFIX)
        ))
    });
    headers.push(create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TWO_FACTOR_COOKIE_SUFFIX,
        &identifier,
        Some(two_factor_cookie_max_age(ctx)),
    )?);

    if remember_me == Some(false) {
        headers.push(create_signed_cookie_header(
            &ctx.config.secret,
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
            "true",
            None,
        )?);
    }

    // TOTP is per-user: only offered once the user has a stored secret. OTP is
    // server-level: offered whenever a sender is configured.
    let mut two_factor_methods = Vec::new();
    if !ctx
        .get_metadata(METADATA_TOTP_DISABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && ctx
            .database
            .get_two_factor_by_user_id(user.id().as_ref())
            .await?
            .is_some_and(|factor| factor.verified() != Some(false))
    {
        two_factor_methods.push("totp");
    }
    if ctx
        .get_metadata(METADATA_OTP_ENABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        two_factor_methods.push("otp");
    }

    Ok(SignInTwoFactorRedirect {
        response: TwoFactorRedirectResponse {
            two_factor_redirect: true,
            two_factor_methods,
        },
        set_cookie_headers: headers,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep factor enrollment, backup generation, and session replacement in their callback order"
)]
async fn enable_core(
    body: &EnableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(EnableResponse, Vec<String>), BackupOperationError> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
    )
    .await?;
    if body.method == EnableMethod::Otp {
        if config.send_otp.is_none() {
            return Err(AuthError::Upstream {
                status: 400,
                code: "OTP_NOT_CONFIGURED",
                message: "OTP is not available",
            }
            .into());
        }
        let updated_user = ctx
            .database
            .update_user(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides(
            ctx,
            updated_user.id().as_ref(),
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
            current_session,
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        return Ok((
            EnableResponse::Otp,
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "TOTP is not available",
        }
        .into());
    }

    let existing = ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?;
    if existing
        .as_ref()
        .is_some_and(|factor| factor.verified() != Some(false))
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_ALREADY_ENABLED",
            message: "TOTP is already enabled",
        }
        .into());
    }

    let secret = generate_secret();
    let encrypted_secret = encrypt_value(&ctx.config.secret, &secret)?;
    let (backup_codes, encrypted_backup_codes) =
        generate_backup_codes(config, &ctx.config.secret).await?;

    let mut set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
        let updated_user = ctx
            .database
            .update_user(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides(
            ctx,
            updated_user.id().as_ref(),
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
            current_session,
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        set_cookie_headers.push(create_session_cookie(issued.session.token(), &ctx.config));
    }

    if let Some(existing) = existing {
        drop(
            ctx.database
                .update_two_factor(
                    existing.id().as_ref(),
                    UpdateTwoFactor {
                        secret: Some(encrypted_secret),
                        backup_codes: Some(encrypted_backup_codes),
                        verified: Some(config.skip_verification_on_enable),
                    },
                )
                .await?,
        );
    } else {
        drop(
            ctx.database
                .create_two_factor(CreateTwoFactor {
                    user_id: user.id().to_string(),
                    secret: encrypted_secret,
                    backup_codes: encrypted_backup_codes,
                    verified: Some(config.skip_verification_on_enable),
                    ..Default::default()
                })
                .await?,
        );
    }

    let issuer = body
        .issuer
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| config.issuer.as_deref().filter(|value| !value.is_empty()))
        .unwrap_or(&ctx.config.app_name);
    let totp_uri = totp_uri(
        config,
        &secret,
        issuer,
        user.email().unwrap_or("user"),
        true,
    );
    Ok((
        EnableResponse::Totp {
            totp_uri,
            backup_codes,
        },
        set_cookie_headers,
    ))
}

async fn disable_core(
    body: &DisableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
    )
    .await?;

    let updated_user = ctx
        .database
        .update_user(
            user.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    ctx.database.delete_two_factor(user.id().as_ref()).await?;

    let issued = issue_user_session_with_overrides(
        ctx,
        updated_user.id().as_ref(),
        current_session.ip_address().map(str::to_owned),
        current_session.user_agent().map(str::to_owned),
        current_session,
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    ctx.database.delete_session(current_session.token()).await?;

    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)
        .is_some_and(|value| !value.is_empty());
    let mut set_cookie_headers = vec![create_session_cookie_for_dont_remember(
        issued.session.token(),
        dont_remember,
        &ctx.config,
    )];
    if dont_remember {
        set_cookie_headers.push(create_signed_cookie_header(
            &ctx.config.secret,
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
            "true",
            None,
        )?);
    }

    if let Some(trust_cookie) = read_signed_cookie(req, TRUST_DEVICE_COOKIE_SUFFIX, ctx)
        && !trust_cookie.is_empty()
    {
        if let Some(trust_identifier) = trust_cookie.split('!').nth(1)
            && !trust_identifier.is_empty()
        {
            ctx.database
                .delete_verifications_by_identifier(trust_identifier)
                .await?;
        }
        set_cookie_headers.push(clear_cookie_header(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX));
    }

    Ok((StatusResponse { status: true }, set_cookie_headers))
}

async fn get_totp_uri_core(
    body: &GetTotpUriRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TotpUriResponse> {
    require_totp_enabled(config)?;
    let two_factor = load_two_factor_record(user, ctx).await?;
    let secret = decrypt_value(&ctx.config.secret, two_factor.secret())?;
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .totp_allow_passwordless
            .unwrap_or(config.allow_passwordless),
    )
    .await?;
    let issuer = config
        .totp_issuer
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&ctx.config.app_name);
    Ok(TotpUriResponse {
        totp_uri: totp_uri(
            config,
            &secret,
            issuer,
            user.email().unwrap_or("user"),
            false,
        ),
    })
}

async fn verify_totp_core(
    req: &AuthRequest,
    body: &VerifyTotpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    require_totp_enabled(config)?;
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(&state.user(), ctx).await?;
    let pending = matches!(state, ResolvedTwoFactorState::Pending(_));
    if pending && two_factor.verified() == Some(false) {
        return Err(AuthError::bad_request("TOTP not enabled"));
    }
    if pending {
        assert_account_not_locked(config, &two_factor, ctx).await?;
    }
    let attempt = begin_factor_attempt(&state, ctx).await?;
    let checked = (|| {
        let secret = decrypt_value(&ctx.config.secret, two_factor.secret())?;
        build_totp(config, &secret)?
            .check_current(&body.code)
            .map_err(|error| AuthError::internal(format!("Failed to verify TOTP: {error}")))
    })();
    let valid = match checked {
        Ok(valid) => valid,
        Err(error) => {
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(error);
        }
    };

    if !valid {
        rearm_factor_attempt(attempt.as_ref(), true, ctx).await;
        if pending {
            record_account_failure(config, &two_factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code"));
    }
    if pending {
        reset_account_failures(config, &two_factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            let result = verify_existing_session_factor(
                user,
                *session,
                two_factor.verified() != Some(true),
                false,
                ctx,
            )
            .await
            .map_err(ExistingSessionFactorError::into_auth_error)?;
            mark_factor_verified(&two_factor, ctx).await?;
            Ok(result)
        }
        ResolvedTwoFactorState::Pending(pending_2) => {
            mark_factor_verified(&two_factor, ctx).await?;
            finalize_pending_two_factor(
                pending_2,
                req,
                body.trust_device.unwrap_or(false),
                true,
                ctx,
            )
            .await
        }
    }
}

async fn mark_factor_verified(
    two_factor: &TwoFactor,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if two_factor.verified() != Some(true) {
        drop(
            ctx.database
                .update_two_factor(
                    two_factor.id().as_ref(),
                    UpdateTwoFactor {
                        verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?,
        );
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
async fn send_otp_core(
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<StatusResponse, SendOtpError> {
    let sender = config
        .send_otp
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("otp isn't configured"))?;
    let state = resolve_two_factor_state(req, ctx).await?;

    // The upstream random-string loop produces ceil(digits) decimal characters.
    let digits = config.otp_digits;
    if digits <= 0.0 {
        return Err(SendOtpError::NonpositiveLength);
    }
    if digits > 32768.5 || digits.is_infinite() {
        return Err(AuthError::internal("Invalid two-factor OTP length").into());
    }
    let otp: String = (0..digits.ceil() as usize)
        .map(|_| char::from(b'0' + rand::thread_rng().gen_range(0..10u8)))
        .collect();
    let stored_otp = config.otp_storage.store(&otp, &ctx.config.secret).await?;
    let identifier = otp_verification_identifier(state.key());
    let period = if config.otp_period_minutes == 0.0 || config.otp_period_minutes.is_nan() {
        3.0
    } else {
        config.otp_period_minutes
    };
    let milliseconds = Utc::now().timestamp_millis() as f64 + period * 60000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(AuthError::internal("Invalid two-factor OTP expiry").into());
    }
    let expires_at = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or_else(|| AuthError::internal("Invalid two-factor OTP expiry"))?;

    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier,
                value: format!("{stored_otp}:0"),
                expires_at,
            })
            .await?,
    );

    otp::deliver(
        Arc::clone(sender),
        ctx.user_view(&state.user()),
        otp,
        ctx.config.background_tasks.clone(),
    )
    .await?;

    Ok(StatusResponse { status: true })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OTP ownership, attempt limits, and successful factor consumption in protocol order"
)]
async fn verify_otp_core(
    req: &AuthRequest,
    body: &VerifyOtpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), ExistingSessionFactorError> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let factor = if matches!(state, ResolvedTwoFactorState::Pending(_)) {
        let factor = ctx
            .database
            .get_two_factor_by_user_id(state.user().id().as_ref())
            .await?;
        if let Some(factor) = &factor {
            assert_account_not_locked(config, factor, ctx).await?;
        }
        factor
    } else {
        None
    };
    let identifier = otp_verification_identifier(state.key());
    let Some(verification) = ctx
        .database
        .consume_verification_by_identifier(&identifier)
        .await?
    else {
        return Err(AuthError::bad_request("OTP has expired").into());
    };

    let mut parts = verification.value().split(':');
    let stored_otp = parts.next().unwrap_or_default();
    let counter = parts.next().unwrap_or_default();
    // parseInt(counter, 10) accepts a signed decimal prefix and ignores its suffix.
    let trimmed = counter.trim_start_matches(|c: char| {
        matches!(
            c,
            '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    });
    let prefix_length = trimmed
        .char_indices()
        .take_while(|(index, c)| c.is_ascii_digit() || (*index == 0 && (*c == '+' || *c == '-')))
        .last()
        .map_or(0, |(index, c)| index + c.len_utf8());
    let attempts = trimmed
        .get(..prefix_length)
        .unwrap_or_default()
        .parse::<f64>()
        .unwrap_or(0.0);
    let allowed_attempts =
        if config.otp_allowed_attempts == 0.0 || config.otp_allowed_attempts.is_nan() {
            5.0
        } else {
            config.otp_allowed_attempts
        };
    if attempts >= allowed_attempts {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            message: "Too many attempts. Please request a new code.",
        }
        .into());
    }

    let is_valid = config
        .otp_storage
        .verify(stored_otp, &body.code, &ctx.config.secret)
        .await?;

    if !is_valid {
        let next_count = attempts + 1.0;
        let next_counter = if next_count.is_infinite() {
            if next_count.is_sign_negative() {
                "-Infinity".into()
            } else {
                "Infinity".into()
            }
        } else {
            better_auth_core::utils::json::number_to_string(
                &serde_json::Number::from_f64(next_count)
                    .ok_or_else(|| AuthError::internal("Invalid OTP counter"))?,
            )
            .map_err(AuthError::from)?
        };
        let next_value = format!("{stored_otp}:{next_counter}");
        let expires_at = verification.expires_at();
        let verification_identifier = verification.identifier().to_owned();
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: verification_identifier,
                    value: next_value,
                    expires_at,
                })
                .await?,
        );
        if let Some(factor) = &factor {
            record_account_failure(config, factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code").into());
    }

    if let Some(factor) = &factor {
        reset_account_failures(config, factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, *session, true, true, ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
                .map_err(ExistingSessionFactorError::Auth)
        }
    }
}

async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    user: &impl AuthUser,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<BackupCodesResponse, BackupOperationError> {
    if !user.two_factor_enabled() {
        return Err(AuthError::bad_request("Two factor isn't enabled").into());
    }

    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config
            .backup_allow_passwordless
            .unwrap_or(config.allow_passwordless),
    )
    .await?;
    let factor = ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Two factor isn't enabled"))?;

    let (backup_codes, encrypted) = generate_backup_codes(config, &ctx.config.secret).await?;
    drop(
        ctx.database
            .update_two_factor(
                factor.id().as_ref(),
                UpdateTwoFactor {
                    backup_codes: Some(encrypted),
                    ..Default::default()
                },
            )
            .await?,
    );

    Ok(BackupCodesResponse {
        status: true,
        backup_codes,
    })
}

async fn verify_backup_code_core(
    req: &AuthRequest,
    body: &VerifyBackupCodeRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(BackupVerificationResponse, Vec<String>)> {
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(state.user().id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let pending = matches!(state, ResolvedTwoFactorState::Pending(_));
    if pending {
        assert_account_not_locked(config, &two_factor, ctx).await?;
    }
    let attempt = begin_factor_attempt(&state, ctx).await?;

    let codes = match config
        .backup_storage
        .load_codes(two_factor.backup_codes(), &ctx.config.secret)
        .await
    {
        Ok(codes) => codes,
        Err(error) => {
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(error);
        }
    };
    let Some(mut backup_codes) = codes.filter(|codes| codes.contains(&body.code)) else {
        rearm_factor_attempt(attempt.as_ref(), true, ctx).await;
        if pending {
            record_account_failure(config, &two_factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    backup_codes.retain(|candidate| candidate != &body.code);

    let encrypted = config
        .backup_storage
        .store_codes(&backup_codes, &ctx.config.secret)
        .await?;
    if !ctx
        .database
        .compare_and_swap_two_factor_backup_codes(
            two_factor.id().as_ref(),
            two_factor.backup_codes(),
            &encrypted,
        )
        .await?
    {
        return Err(AuthError::conflict(
            "Failed to verify backup code. Please try again.",
        ));
    }
    if pending {
        reset_account_failures(config, &two_factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            if body.disable_session.unwrap_or(false) {
                Ok((
                    BackupVerificationResponse {
                        token: Some(session.token().to_owned()),
                        user: ctx.user_view(&user),
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(user, *session, false, false, ctx)
                    .await
                    .map(|(response, headers)| (response.into(), headers))
                    .map_err(ExistingSessionFactorError::into_auth_error)
            }
        }
        ResolvedTwoFactorState::Pending(pending_2) => {
            if body.disable_session.unwrap_or(false) {
                return Ok((
                    BackupVerificationResponse {
                        token: None,
                        user: ctx.user_view(&pending_2.user),
                    },
                    Vec::new(),
                ));
            }
            finalize_pending_two_factor(
                pending_2,
                req,
                body.trust_device.unwrap_or(false),
                true,
                ctx,
            )
            .await
            .map(|(response, headers)| (response.into(), headers))
        }
    }
}

async fn view_backup_codes_core<S: better_auth_core::AuthSchema>(
    user_id: &str,
    config: &TwoFactorConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<Vec<String>> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let Some(backup_codes) = config
        .backup_storage
        .load_codes(two_factor.backup_codes(), &ctx.config.secret)
        .await?
    else {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    Ok(backup_codes)
}

async fn resolve_two_factor_state<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<ResolvedTwoFactorState<S>> {
    if let Ok((user, session)) = ctx.require_cached_session(req).await {
        let key = format!("{}!{}", user.id(), session.id());
        return Ok(ResolvedTwoFactorState::Session {
            user,
            session: Box::new(session),
            key,
        });
    }

    let identifier = read_signed_cookie(req, TWO_FACTOR_COOKIE_SUFFIX, ctx)
        .filter(|identifier| !identifier.is_empty())
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    // Preserve the newest lookup snapshot across optional global cleanup.
    // Expiry is enforced by the later atomic attempt/challenge consumption,
    // after the source's user lookup and factor-specific checks.
    let verification = super::authentication_helpers::find_verification(ctx, &identifier)
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;

    let user = ctx
        .database
        .get_user_by_id(verification.value())
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)
        .is_some_and(|value| !value.is_empty());

    Ok(ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user,
        verification,
        key: identifier,
        dont_remember,
    }))
}

async fn begin_factor_attempt<S: better_auth_core::AuthSchema>(
    state: &ResolvedTwoFactorState<S>,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<FactorAttempt>> {
    let ResolvedTwoFactorState::Pending(pending) = state else {
        return Ok(None);
    };
    let identifier = format!("2fa-attempts-{}", pending.key);
    let consumed = ctx
        .database
        .consume_verification_by_identifier(&identifier)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let parsed = attempt_number(consumed.value());
    let count = if parsed.is_finite() && parsed.fract() == 0.0 && parsed >= 0.0 {
        parsed
    } else {
        5.0
    };
    if count >= 5.0 {
        if ctx
            .database
            .consume_verification_by_identifier(&pending.key)
            .await
            .is_err()
        {
            return Err(AuthError::Upstream {
                status: 500,
                code: "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE",
                message: "Failed to invalidate two-factor challenge",
            });
        }
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            message: "Too many attempts. Please request a new code.",
        });
    }
    Ok(Some(FactorAttempt {
        identifier,
        count,
        expires_at: pending.verification.expires_at(),
    }))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn attempt_number(value: &str) -> f64 {
    let value = value.trim_matches(|character| {
        matches!(
            character,
            '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    });
    if value.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(value) = value.strip_prefix(prefix) {
            return u64::from_str_radix(value, radix).map_or(f64::NAN, |count| count as f64);
        }
    }
    value.parse().unwrap_or(f64::NAN)
}

async fn rearm_factor_attempt(
    attempt: Option<&FactorAttempt>,
    failed: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) {
    if let Some(attempt) = attempt {
        drop(
            ctx.database
                .create_verification(CreateVerification {
                    identifier: attempt.identifier.clone(),
                    value: (attempt.count + if failed { 1.0 } else { 0.0 }).to_string(),
                    expires_at: attempt.expires_at,
                })
                .await,
        );
    }
}

async fn assert_account_not_locked(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if !config.account_lockout.enabled {
        return Ok(());
    }
    if let Some(until) = factor.locked_until() {
        let now = Utc::now();
        if until.timestamp_millis() > now.timestamp_millis() {
            return Err(AuthError::Upstream {
                status: 429,
                code: "ACCOUNT_TEMPORARILY_LOCKED",
                message: "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
            });
        }
        drop(
            ctx.database
                .clear_expired_two_factor_lock(factor.id().as_ref(), now)
                .await?,
        );
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
async fn record_account_failure(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if !config.account_lockout.enabled {
        return Ok(());
    }
    let incremented = ctx
        .database
        .increment_two_factor_failure(factor.id().as_ref())
        .await?;
    let count = incremented
        .and_then(|factor_2| factor_2.failed_verification_count())
        .unwrap_or(0.0);
    if count >= config.account_lockout.max_failed_attempts {
        let milliseconds = config
            .account_lockout
            .duration_seconds
            .mul_add(1000.0, Utc::now().timestamp_millis() as f64);
        // JavaScript Date TimeClip rejects nonfinite/out-of-range values and
        // truncates toward zero; nullable/zero settings remain supported.
        if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
            return Err(AuthError::internal("Invalid two-factor lock date"));
        }
        let until = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
            .ok_or_else(|| AuthError::internal("Invalid two-factor lock date"))?;
        drop(
            ctx.database
                .set_two_factor_lock_if_count_at_least(
                    factor.id().as_ref(),
                    config.account_lockout.max_failed_attempts,
                    until,
                )
                .await?,
        );
    }
    Ok(())
}

async fn reset_account_failures(
    config: &TwoFactorConfig,
    factor: &TwoFactor,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if config.account_lockout.enabled {
        ctx.database
            .reset_two_factor_failures(factor.id().as_ref())
            .await?;
    }
    Ok(())
}

fn verification_error_response(
    error: AuthError,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    if matches!(
        &error,
        AuthError::Upstream {
            code: "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
                | "FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE"
                | "INVALID_TWO_FACTOR_COOKIE",
            ..
        }
    ) {
        Ok(error.to_auth_response().with_appended_header(
            "Set-Cookie",
            clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX),
        ))
    } else {
        Err(error)
    }
}

async fn verify_existing_session_factor(
    user: impl AuthUser,
    session: impl AuthSession,
    enable_two_factor_if_needed: bool,
    return_updated_snapshot: bool,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), ExistingSessionFactorError> {
    if enable_two_factor_if_needed && !user.two_factor_enabled() {
        let updated_user = ctx
            .database
            .update_user(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides(
            ctx,
            updated_user.id().as_ref(),
            session.ip_address().map(str::to_owned),
            session.user_agent().map(str::to_owned),
            &session,
        )
        .await
        .map_err(|error| match error.into_auth_error() {
            AuthError::SessionCreationCancelled => {
                ExistingSessionFactorError::SessionCreationCancelled
            }
            error @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::InvalidCredentials
            | AuthError::Unauthenticated
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::BannedUser(_)
            | AuthError::Unauthorized
            | AuthError::UserNotFound
            | AuthError::NotFound(_)
            | AuthError::Conflict(_)
            | AuthError::MethodNotAllowed(_)
            | AuthError::PayloadTooLarge(_)
            | AuthError::UnprocessableEntity(_)
            | AuthError::RateLimited
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::PasswordHash(_)
            | AuthError::UserCreationCancelled
            | AuthError::Jwt(_)) => ExistingSessionFactorError::Auth(error),
        })?;
        ctx.database.delete_session(session.token()).await?;
        return Ok((
            SessionTokenResponse {
                token: if return_updated_snapshot {
                    issued.session.token().to_owned()
                } else {
                    session.token().to_owned()
                },
                // TOTP retains its original response snapshot; OTP returns the
                // updated user and newly issued token.
                user: if return_updated_snapshot {
                    ctx.user_view(&updated_user)
                } else {
                    ctx.user_view(&user)
                },
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }

    Ok((
        SessionTokenResponse {
            token: session.token().to_owned(),
            user: ctx.user_view(&user),
        },
        Vec::new(),
    ))
}

async fn finalize_pending_two_factor<S: better_auth_core::AuthSchema>(
    pending: PendingTwoFactorState<S>,
    req: &AuthRequest,
    trust_device: bool,
    set_session_cookie: bool,
    ctx: &AuthContext<S>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
    let consumed = ctx
        .database
        .consume_verification_by_identifier(&pending.key)
        .await?;
    if consumed.is_none_or(|verification| verification.value() != pending.user.id().as_ref()) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TWO_FACTOR_COOKIE",
            message: "Invalid two factor cookie",
        });
    }
    let meta = RequestMeta::from_request(req);
    let mut config = (*ctx.config).clone();
    if pending.dont_remember {
        config.session.expires_in = Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: Arc::new(config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let issued = issue_user_session(
        &issuing_context,
        pending.user.id().as_ref(),
        meta.ip_address,
        meta.user_agent,
    )
    .await
    .map_err(|error| match error {
        SessionIssueError::Auth(AuthError::SessionCreationCancelled) => AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_CREATE_SESSION",
            message: "failed to create session",
        },
        error @ (SessionIssueError::Auth(_) | SessionIssueError::Banned { .. }) => {
            error.into_auth_error()
        }
    })?;

    let mut set_cookie_headers = vec![clear_cookie_header(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)];
    if set_session_cookie {
        set_cookie_headers.push(create_session_cookie_for_dont_remember(
            issued.session.token(),
            pending.dont_remember,
            &ctx.config,
        ));
        if pending.dont_remember {
            set_cookie_headers.push(create_signed_cookie_header(
                &ctx.config.secret,
                &ctx.config,
                DONT_REMEMBER_COOKIE_SUFFIX,
                "true",
                None,
            )?);
        }
    }
    if trust_device {
        set_cookie_headers.push(create_trust_device_cookie_header(&issued.user, ctx).await?);
        set_cookie_headers.push(clear_cookie_header(
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
        ));
    }

    Ok((
        SessionTokenResponse {
            token: issued.session.token().to_owned(),
            user: ctx.user_view(&issued.user),
        },
        set_cookie_headers,
    ))
}

async fn load_two_factor_record(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TwoFactor> {
    ctx.database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?
        .ok_or_else(|| AuthError::bad_request("TOTP not enabled"))
}

const fn require_totp_enabled(config: &TwoFactorConfig) -> AuthResult<()> {
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "totp isn't configured",
        });
    }
    Ok(())
}

const fn totp_digits(config: &TwoFactorConfig) -> usize {
    if config.totp_digits == 0 {
        DEFAULT_TOTP_DIGITS
    } else {
        config.totp_digits
    }
}

const fn totp_period(config: &TwoFactorConfig) -> u64 {
    if config.totp_period == 0 {
        DEFAULT_TOTP_PERIOD_SECS
    } else {
        config.totp_period
    }
}

fn build_totp(config: &TwoFactorConfig, secret: &str) -> AuthResult<TOTP> {
    let digits = totp_digits(config);
    if !(1..=8).contains(&digits) || secret.is_empty() {
        return Err(AuthError::internal("Invalid TOTP HMAC input"));
    }
    // The upstream UTF-8 HMAC accepts short nonempty keys. Validate the runtime
    // constraints before bypassing the library's stronger 128-bit key policy.
    Ok(TOTP::new_unchecked(
        Algorithm::SHA1,
        digits,
        1,
        totp_period(config),
        secret.as_bytes().to_vec(),
        None,
        String::new(),
    ))
}

fn uri_component(value: &str) -> String {
    urlencoding::encode(value)
        .replace("%21", "!")
        .replace("%27", "'")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%2A", "*")
}

fn totp_uri(
    config: &TwoFactorConfig,
    secret: &str,
    issuer: &str,
    email: &str,
    enrollment: bool,
) -> String {
    let secret = totp_rs::Secret::Raw(secret.as_bytes().to_vec())
        .to_encoded()
        .to_string();
    let digits = totp_digits(config).to_string();
    // Enrollment forwards the configured period directly; the authenticator
    // provider and generator use the upstream truthy default for zero.
    let period = if enrollment {
        config.totp_period
    } else {
        totp_period(config)
    }
    .to_string();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &secret)
        .append_pair("issuer", issuer)
        .append_pair("digits", &digits)
        .append_pair("period", &period)
        .finish();
    format!(
        "otpauth://totp/{}:{}?{query}",
        uri_component(issuer),
        uri_component(email)
    )
}

async fn verify_user_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
    password: Option<&str>,
    allow_passwordless: bool,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user).await?;
    if allow_passwordless && stored_hash.as_deref().is_none_or(str::is_empty) {
        return Ok(());
    }
    let password = password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    let password_config = ctx
        .extensions
        .get::<super::email_password::EmailPasswordConfig>();
    let maximum = password_config
        .as_ref()
        .map_or(128, |config| config.password_max_length);
    if password.encode_utf16().count() > maximum {
        return Err(AuthError::bad_request("Password too long"));
    }
    let stored_hash = stored_hash
        .filter(|hash| !hash.is_empty())
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    let hasher = password_config
        .as_ref()
        .and_then(|config| config.password_hasher.as_ref());
    match better_auth_core::verify_password(hasher, password, &stored_hash).await {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

fn parse_password_body<T: serde::de::DeserializeOwned + 'static>(
    req: &AuthRequest,
    allow_passwordless: bool,
    include_issuer: bool,
) -> Result<T, AuthResponse> {
    use super::authentication_helpers::{JsonField, JsonFieldKind, parse_body_with_fields};
    let fields = [
        JsonField::string("password", !allow_passwordless),
        JsonField {
            name: "method",
            kind: JsonFieldKind::OneOf(&["otp", "totp"]),
            required: false,
        },
        JsonField::string("issuer", false),
    ];
    parse_body_with_fields(
        req,
        if include_issuer {
            &fields[..]
        } else {
            &fields[..1]
        },
    )
}

fn generate_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
async fn generate_backup_codes(
    config: &TwoFactorConfig,
    secret: &str,
) -> Result<(Vec<String>, String), BackupOperationError> {
    let codes = if let Some(generate) = &config.custom_backup_codes_generate {
        generate()?
    } else {
        let amount = config.backup_code_amount;
        let count = if amount.is_nan() || amount <= 0.0 {
            0
        } else {
            if amount.is_infinite() || amount > 32768.5 {
                return Err(BackupOperationError::InvalidGeneration);
            }
            amount.floor() as usize
        };
        (0..count)
            .map(|_| {
                let length = config.backup_code_length;
                if length <= 0.0
                    || (length > 0.0 && length < 0.5)
                    || length.is_infinite()
                    || length > 32768.5
                {
                    return Err(BackupOperationError::InvalidGeneration);
                }
                let code: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(length.ceil() as usize)
                    .map(char::from)
                    .collect();
                let split = code.len().min(5);
                let (prefix, suffix) = code
                    .split_at_checked(split)
                    .ok_or(BackupOperationError::InvalidGeneration)?;
                Ok(format!("{prefix}-{suffix}"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let stored = config.backup_storage.store_codes(&codes, secret).await?;
    Ok((codes, stored))
}

fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{key}")
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn cookie_expiry(seconds: f64) -> AuthResult<chrono::DateTime<Utc>> {
    let milliseconds = seconds.mul_add(1000.0, Utc::now().timestamp_millis() as f64);
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(AuthError::internal("Invalid two-factor cookie expiry"));
    }
    chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or_else(|| AuthError::internal("Invalid two-factor cookie expiry"))
}

fn two_factor_cookie_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> f64 {
    ctx.extensions
        .get::<TwoFactorCookiePolicy>()
        .map(|policy| policy.challenge_max_age)
        .or_else(|| {
            ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
                .and_then(serde_json::Value::as_f64)
        })
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> f64 {
    ctx.extensions
        .get::<TwoFactorCookiePolicy>()
        .map(|policy| policy.trust_max_age)
        .or_else(|| {
            ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
                .and_then(serde_json::Value::as_f64)
        })
        .unwrap_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)
}

fn create_session_cookie_for_dont_remember(
    token: &str,
    dont_remember: bool,
    config: &better_auth_core::AuthConfig,
) -> String {
    if dont_remember {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

fn clear_cookie_header(config: &better_auth_core::AuthConfig, suffix: &str) -> String {
    create_clear_cookie(&related_cookie_name(config, suffix), config)
}

async fn create_trust_device_cookie_header(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    let identifier = format!("trust-device-{}", uuid::Uuid::new_v4());
    let token = sign_value(&ctx.config.secret, &format!("{}!{}", user.id(), identifier))?;
    let value = format!("{token}!{identifier}");
    let expires_at = cookie_expiry(trust_device_max_age(ctx))?;
    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );
    create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn create_signed_cookie_header(
    secret: &str,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<f64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value);
    // The pinned cookie serializer floors nonnegative Max-Age, omits negative
    // values and does not synthesize an Expires attribute from Max-Age.
    let mut header = create_session_like_cookie(&cookie_name, &signed_value, None, config);
    if let Some(seconds) = max_age_seconds.filter(|seconds| *seconds >= 0.0) {
        if seconds > 34_560_000.0 {
            return Err(AuthError::internal(
                "Two-factor cookie lifetime exceeds 400 days",
            ));
        }
        _ = write!(header, "; Max-Age={}", seconds.floor() as u32);
    }
    Ok(header)
}

fn read_signed_cookie<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> Option<String> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let raw_cookie = get_cookie(req, &cookie_name)?;
    verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)
}

// Better Call requires a nonempty payload and a 44-character padded outer
// signature, while its atob accepts unused trailing Base64 bits. Keep this
// source-specific decoder local to trusted proofs; other cookie owners retain
// their shared decoder. HMAC verification remains constant-time.
fn verify_trusted_device_cookie_value(secret: &str, signed_value: &str) -> Option<String> {
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};

    let decoded = urlencoding::decode(signed_value).ok()?;
    let (payload, signature) = decoded.rsplit_once('.')?;
    if payload.is_empty() || signature.len() != 44 || !signature.ends_with('=') {
        return None;
    }
    let signature = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
    .decode(signature)
    .ok()?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).ok()?;
    Some(payload.to_owned())
}

fn sign_cookie_value(secret: &str, value: &str) -> String {
    better_auth_core::utils::cookie_utils::sign_cookie_value(value, secret)
}

fn verify_signed_cookie_value(secret: &str, signed_value: &str) -> Option<String> {
    better_auth_core::utils::cookie_utils::verify_cookie_value(signed_value, secret)
}

fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {error}")))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn derive_encryption_key(secret: &str) -> AuthResult<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut okm).map_err(|error| {
        AuthError::internal(format!("Failed to derive encryption key: {error}"))
    })?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

fn encrypt_value(secret: &str, plaintext: &str) -> AuthResult<String> {
    super::token_crypto::encrypt(plaintext, secret)
}

fn decrypt_value(secret: &str, encrypted: &str) -> AuthResult<String> {
    // New factor rows use the pinned runtime's XChaCha/hex encoding. Installed
    // Rust rows retain an authenticated AES/HKDF reader; legacy writes are gone.
    super::token_crypto::decrypt(encrypted, secret)
        .or_else(|_| decrypt_legacy_value(secret, encrypted))
}

fn decrypt_legacy_value(secret: &str, encrypted: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let bytes = URL_SAFE_NO_PAD.decode(encrypted).map_err(|error| {
        AuthError::internal(format!(
            "Failed to decode encrypted two-factor data: {error}"
        ))
    })?;
    if bytes.len() < 12 {
        return Err(AuthError::internal(
            "Encrypted two-factor payload is missing the nonce",
        ));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|error| {
            AuthError::internal(format!("Failed to decrypt two-factor data: {error}"))
        })?;
    String::from_utf8(plaintext).map_err(|error| {
        AuthError::internal(format!("Two-factor plaintext is not valid UTF-8: {error}"))
    })
}
