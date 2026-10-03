mod backup_storage;
mod endpoint;

mod otp_storage;

mod otp;

use super::StatusResponse;
use crate::plugins::helpers::{
    SessionIssueError, get_cookie, get_credential_password_hash, issue_user_session_record,
    issue_user_session_with_overrides_record,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
pub use backup_storage::{TwoFactorBackupCipher, TwoFactorBackupStorage};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::entity::{AuthSession, AuthTwoFactor, AuthUser};
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
pub use endpoint::{BackupCodesOutput, TotpOutput};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
pub use otp_storage::{TwoFactorOtpCipher, TwoFactorOtpHasher, TwoFactorOtpStorage};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt::Write;
use std::sync::Arc;
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

const DEFAULT_TOTP_PERIOD_SECS: f64 = 30.0;

const DEFAULT_TOTP_DIGITS: f64 = 6.0;

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
    /// TOTP period in seconds, retaining Source fractional and signed counters.
    #[config(default = DEFAULT_TOTP_PERIOD_SECS)]
    pub totp_period: f64,
    /// Raw TOTP digits. Fractional values retain Source decimal-remainder output.
    #[config(default = DEFAULT_TOTP_DIGITS)]
    pub totp_digits: f64,
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
    user: better_auth_core::AdapterRecord<S::User>,
    verification: better_auth_core::verification::VerificationSnapshot,
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
        generate_totp_at(&self.config, secret, totp_counter(&self.config), 0.0)
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
        fn rate_limits(&self) -> Vec<better_auth_core::PluginRateLimit> {
            vec![better_auth_core::PluginRateLimit { matches: |path| path.starts_with("/two-factor/"), limit: better_auth_core::EndpointRateLimit { window_seconds: 10.0, max_requests: 3.0 } }]
        }
        fn server_endpoints(&self) -> Vec<better_auth_core::endpoint::EndpointDefinition> { endpoint::definitions() }

        fn validate_endpoint(&self, call: &better_auth_core::endpoint::EndpointCall, _ctx: &AuthContext<S>) -> AuthResult<better_auth_core::endpoint::EndpointInput> { endpoint::validate(call) }

        async fn on_endpoint(&self, call: &better_auth_core::endpoint::EndpointCall, ctx: &AuthContext<S>) -> AuthResult<better_auth_core::endpoint::EndpointResponse> { self.call_endpoint(call, ctx).await }

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
                | AuthError::Encryption(_)
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
                Err(
                    TotpVerificationError::InvalidGeneration
                    | TotpVerificationError::SessionCreationCancelled,
                ) => return Ok(AuthResponse::new(500)),
                Err(TotpVerificationError::Auth(error)) => {
                    return verification_error_response(error, ctx);
                }
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
            Err(SendOtpError::InvalidGeneration) => return Ok(AuthResponse::new(500)),
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

enum TotpVerificationError {
    Auth(AuthError),
    InvalidGeneration,
    SessionCreationCancelled,
}
impl From<AuthError> for TotpVerificationError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

enum SendOtpError {
    Auth(AuthError),
    // The pinned random-string generator throws before storage or delivery.
    InvalidGeneration,
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
    let Some(signed_value) =
        verify_trusted_device_cookie_value(ctx.config.current_secret(), &raw_cookie)
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
        ctx.config.current_secret(),
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

    if verification.value()? != user.id().as_ref() || verification.expires_at()? <= Utc::now() {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    }

    ctx.verifications().delete(trust_identifier).await?;

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
        ctx.verifications()
            .create(CreateVerification {
                identifier: identifier.clone(),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );
    drop(
        ctx.verifications()
            .create(CreateVerification {
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
        ctx.config.current_secret(),
        &ctx.config,
        TWO_FACTOR_COOKIE_SUFFIX,
        &identifier,
        Some(two_factor_cookie_max_age(ctx)),
    )?);

    if remember_me == Some(false) {
        headers.push(create_signed_cookie_header(
            ctx.config.current_secret(),
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
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
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
    let encrypted_secret = encrypt_value(&ctx.config, &secret)?;
    let (backup_codes, encrypted_backup_codes) = generate_backup_codes(config, &ctx.config).await?;

    let mut set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
        let updated_user = ctx
            .database
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
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
        .update_user_record(
            user.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    ctx.database.delete_two_factor(user.id().as_ref()).await?;

    let issued = issue_user_session_with_overrides_record(
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
            ctx.config.current_secret(),
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
            ctx.verifications().delete(trust_identifier).await?;
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
    let secret = decrypt_value(&ctx.config, two_factor.secret())?;
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
) -> Result<(SessionTokenResponse<UserView>, Vec<String>), TotpVerificationError> {
    require_totp_enabled(config)?;
    let state = resolve_two_factor_state(req, ctx).await?;
    let two_factor = load_two_factor_record(&state.user(), ctx).await?;
    let pending = matches!(state, ResolvedTwoFactorState::Pending(_));
    if pending && two_factor.verified() == Some(false) {
        return Err(AuthError::bad_request("TOTP not enabled").into());
    }
    if pending {
        assert_account_not_locked(config, &two_factor, ctx).await?;
    }
    let attempt = begin_factor_attempt(&state, ctx).await?;
    let checked = (|| {
        let secret = decrypt_value(&ctx.config, two_factor.secret())?;
        let counter = totp_counter(config);
        let mut matched = false;
        // Source evaluates every window entry even after a match.
        for offset in [-1.0, 0.0, 1.0] {
            let expected = generate_totp_at(config, &secret, counter, offset)
                .map_err(|_error| TotpVerificationError::InvalidGeneration)?;
            matched |= constant_time_totp_equal(&body.code, &expected);
        }
        Ok::<_, TotpVerificationError>(matched)
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
        return Err(AuthError::authentication_failed("Invalid code").into());
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
            .map_err(|error| match error {
                ExistingSessionFactorError::SessionCreationCancelled => {
                    TotpVerificationError::SessionCreationCancelled
                }
                ExistingSessionFactorError::Auth(error) => TotpVerificationError::Auth(error),
            })?;
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
            .map_err(TotpVerificationError::from)
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

    let otp =
        generate_numeric_string(config.otp_digits, true).ok_or(SendOtpError::InvalidGeneration)?;
    let stored_otp = config.otp_storage.store(&otp, &ctx.config).await?;
    let identifier = otp_verification_identifier(state.key());
    let period = if config.otp_period_minutes == 0.0 || config.otp_period_minutes.is_nan() {
        3.0
    } else {
        config.otp_period_minutes
    };
    let milliseconds = Utc::now().timestamp_millis() as f64 + period * 60.0 * 1000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(SendOtpError::InvalidGeneration);
    }
    let expires_at = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
        .ok_or(SendOtpError::InvalidGeneration)?;

    drop(
        ctx.verifications()
            .create(CreateVerification {
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
    let Some(verification) = ctx.verifications().consume(&identifier).await? else {
        return Err(AuthError::bad_request("OTP has expired").into());
    };

    let mut parts = verification.value()?.split(':');
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
        .verify(stored_otp, &body.code, &ctx.config)
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
        let expires_at = verification.expires_at()?;
        let verification_identifier = otp_verification_identifier(state.key());
        drop(
            ctx.verifications()
                .create(CreateVerification {
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

    let (backup_codes, encrypted) = generate_backup_codes(config, &ctx.config).await?;
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
        .load_value(two_factor.backup_codes(), &ctx.config)
        .await
    {
        Ok(codes) => codes,
        Err(error) => {
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(error);
        }
    };
    let codes = match codes {
        Some(serde_json::Value::Array(codes)) => Some(codes),
        None | Some(serde_json::Value::Null | serde_json::Value::Bool(false)) => None,
        Some(serde_json::Value::Number(number)) if number.as_f64() == Some(0.0) => None,
        Some(serde_json::Value::String(value)) if value.is_empty() => None,
        Some(_) => {
            // Source's includes/filter calls throw for truthy non-arrays inside
            // the decode-stage try/catch. Do not turn corrupted storage into
            // a failed proof or spend the pending challenge's attempt budget.
            rearm_factor_attempt(attempt.as_ref(), false, ctx).await;
            return Err(AuthError::Encryption(
                "Backup code JSON is not an array".into(),
            ));
        }
    };
    let Some(mut backup_codes) = codes.filter(|codes| {
        codes
            .iter()
            .any(|code| code.as_str() == Some(body.code.as_str()))
    }) else {
        rearm_factor_attempt(attempt.as_ref(), true, ctx).await;
        if pending {
            record_account_failure(config, &two_factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid backup code"));
    };
    backup_codes.retain(|candidate| candidate.as_str() != Some(body.code.as_str()));

    let encrypted = config
        .backup_storage
        .store_json(serde_json::to_string(&backup_codes)?, &ctx.config)
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
        .load_codes(two_factor.backup_codes(), &ctx.config)
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
        .get_user_by_id_record(verification.value()?)
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
        .verifications()
        .consume(&identifier)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let parsed = attempt_number(consumed.value()?);
    let count = if parsed.is_finite() && parsed.fract() == 0.0 && parsed >= 0.0 {
        parsed
    } else {
        5.0
    };
    if count >= 5.0 {
        if ctx.verifications().consume(&pending.key).await.is_err() {
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
        expires_at: pending.verification.expires_at()?,
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
            ctx.verifications()
                .create(CreateVerification {
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
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
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
            | AuthError::Encryption(_)
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
    let consumed = ctx.verifications().consume(&pending.key).await?;
    if consumed.is_none_or(|verification| {
        !verification
            .value()
            .is_ok_and(|value| value == pending.user.id().as_ref())
    }) {
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
    let issued = issue_user_session_record(
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
                ctx.config.current_secret(),
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

fn totp_digits(config: &TwoFactorConfig) -> f64 {
    truthy_number(config.totp_digits, DEFAULT_TOTP_DIGITS)
}

fn totp_period(config: &TwoFactorConfig) -> f64 {
    truthy_number(config.totp_period, DEFAULT_TOTP_PERIOD_SECS)
}

fn truthy_number(value: f64, default: f64) -> f64 {
    if value == 0.0 || value.is_nan() {
        default
    } else {
        value
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Source Date.now is an IEEE754 millisecond number"
)]
fn totp_counter(config: &TwoFactorConfig) -> f64 {
    (Utc::now().timestamp_millis() as f64 / (totp_period(config) * 1000.0)).floor()
}

#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "Guarded IEEE754 counter/length conversion; SHA1 is 20 bytes and every truncated digest index is in 0..=19"
)]
fn generate_totp_at(
    config: &TwoFactorConfig,
    secret: &str,
    counter: f64,
    offset: f64,
) -> AuthResult<String> {
    let digits = totp_digits(config);
    let counter = counter + offset;
    if !(1.0..=8.0).contains(&digits) || secret.is_empty() || !counter.is_finite() {
        return Err(AuthError::internal("Invalid TOTP HMAC input"));
    }
    // setBigUint64 wraps the integer BigInt modulo 2^64, including negatives.
    // Taking the signed remainder before conversion avoids f64 rounding of
    // negative small counters when adding 2^64.
    let remainder = counter % 18_446_744_073_709_551_616.0;
    let counter = if remainder < 0.0 {
        (remainder.abs() as u64).wrapping_neg()
    } else {
        remainder as u64
    };
    let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_error| AuthError::internal("Invalid TOTP HMAC input"))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let truncated = u32::from_be_bytes([
        digest[offset] & 127,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    let value = f64::from(truncated) % 10.0_f64.powf(digits);
    let code = js_number_string(value);
    let padding = (digits.trunc() as usize).saturating_sub(code.len());
    Ok(format!("{}{code}", "0".repeat(padding)))
}

fn js_number_string(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value == f64::INFINITY {
        "Infinity".into()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".into()
    } else {
        ryu_js::Buffer::new().format(value).to_owned()
    }
}

fn constant_time_totp_equal(input: &str, expected: &str) -> bool {
    // Source compares UTF-16 code units and includes the original lengths.
    let mut input_units = input.encode_utf16();
    let mut difference = input_units.clone().count() ^ expected.encode_utf16().count();
    for unit in expected.encode_utf16() {
        difference |= usize::from(input_units.next().unwrap_or_default() ^ unit);
    }
    difference == 0
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
    let digits = js_number_string(totp_digits(config));
    // Enrollment forwards the configured period directly; the authenticator
    // provider and generator use the upstream truthy default for zero.
    let period = js_number_string(if enrollment {
        config.totp_period
    } else {
        totp_period(config)
    });
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
    secret: &better_auth_core::AuthConfig,
) -> Result<(Vec<String>, String), BackupOperationError> {
    let codes = if let Some(generate) = &config.custom_backup_codes_generate {
        generate()?
    } else {
        let amount = config.backup_code_amount;
        let count = if amount.is_nan() || amount <= 0.0 {
            0
        } else {
            // Array.from creates an ordinary JS array, with a 32-bit length.
            if !amount.is_finite() || amount.floor() > f64::from(u32::MAX) {
                return Err(BackupOperationError::InvalidGeneration);
            }
            amount.floor() as usize
        };
        let mut codes = Vec::new();
        codes
            .try_reserve_exact(count)
            .map_err(|_error| BackupOperationError::InvalidGeneration)?;
        for _ in 0..count {
            let code = generate_numeric_string(config.backup_code_length, false)
                .ok_or(BackupOperationError::InvalidGeneration)?;
            let split = code.len().min(5);
            let (prefix, suffix) = code
                .split_at_checked(split)
                .ok_or(BackupOperationError::InvalidGeneration)?;
            codes.push(format!("{prefix}-{suffix}"));
        }
        codes
    };
    let stored = config.backup_storage.store_codes(&codes, secret).await?;
    Ok((codes, stored))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "Finite JS random lengths round up before checked native allocation"
)]
fn generate_numeric_string(length: f64, decimal: bool) -> Option<String> {
    if length.is_nan() {
        return Some(String::new());
    }
    // Sub-half-character Source buffers are empty and never terminate.
    // The native API rejects them instead of reproducing that infinite loop.
    if !length.is_finite() || length < 0.5 || length.ceil() >= usize::MAX as f64 {
        return None;
    }
    let count = length.ceil() as usize;
    let mut code = String::new();
    code.try_reserve_exact(count).ok()?;
    let mut random = rand::thread_rng();
    for _ in 0..count {
        code.push(if decimal {
            char::from(b'0' + random.gen_range(0..10u8))
        } else {
            char::from(random.sample(Alphanumeric))
        });
    }
    Some(code)
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
    let token = sign_value(
        ctx.config.current_secret(),
        &format!("{}!{}", user.id(), identifier),
    )?;
    let value = format!("{token}!{identifier}");
    let expires_at = cookie_expiry(trust_device_max_age(ctx))?;
    drop(
        ctx.verifications()
            .create(CreateVerification {
                identifier: identifier.clone(),
                value: user.id().to_string(),
                expires_at,
            })
            .await?,
    );
    create_signed_cookie_header(
        ctx.config.current_secret(),
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
    verify_signed_cookie_value(ctx.config.current_secret(), &raw_cookie)
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

fn encrypt_value(secret: &better_auth_core::AuthConfig, plaintext: &str) -> AuthResult<String> {
    super::token_crypto::encrypt_with_config(plaintext, secret)
}

fn decrypt_value(secret: &better_auth_core::AuthConfig, encrypted: &str) -> AuthResult<String> {
    // New factor rows use the pinned runtime's XChaCha/hex encoding. Installed
    // Rust rows retain an authenticated AES/HKDF reader; legacy writes are gone.
    super::token_crypto::decrypt_with_config(encrypted, secret).or_else(|error| {
        if secret.managed_secrets.is_some() {
            return Err(error);
        }
        decrypt_legacy_value(secret.current_secret(), encrypted)
    })
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use better_auth_core::wire::{SessionView, UserView};
    use better_auth_core::{AuthPlugin, AuthVerification};
    use better_auth_core::{CreateAccount, CreateUser, HttpMethod};
    use chrono::Duration;
    use cookie::Cookie;

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn skip_enrollment_hooks_retain_factor_generation_and_current_token_on_rejection() {
        use better_auth_core::{AuthConfig, CreateSession};
        use better_auth_seaorm::{
            Database, DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore,
        };
        struct PolicyHook {
            cancel_session: bool,
            session_forbidden: bool,
            observed: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        }
        #[async_trait]
        impl DatabaseHooks<TestSchema, SeaOrmBackend> for PolicyHook {
            async fn before_update_user(
                &self,
                id: &str,
                update: &mut UpdateUser,
                context: &SeaOrmHookContext<'_>,
            ) -> AuthResult<HookControl> {
                if context
                    .request
                    .as_ref()
                    .is_some_and(|request| request.path.ends_with("/two-factor/enable"))
                {
                    self.observed
                        .lock()
                        .unwrap()
                        .push(("user".into(), id.into()));
                    assert_eq!(update.two_factor_enabled, Some(true));
                    if !self.cancel_session {
                        return Err(AuthError::Upstream {
                            status: 400,
                            code: "USER_UPDATE_DENIED",
                            message: "Configured user update denied",
                        });
                    }
                }
                Ok(HookControl::Continue)
            }
            async fn before_create_session(
                &self,
                session: &mut CreateSession,
                context: &SeaOrmHookContext<'_>,
            ) -> AuthResult<HookControl> {
                if context
                    .request
                    .as_ref()
                    .is_some_and(|request| request.path.ends_with("/two-factor/enable"))
                {
                    self.observed
                        .lock()
                        .unwrap()
                        .push(("session".into(), session.user_id.clone()));
                    assert_eq!(
                        session.active_organization_id.as_deref(),
                        Some("retained-org")
                    );
                    assert_eq!(session.active_team_id.as_deref(), Some("retained-team"));
                    assert_eq!(session.impersonated_by.as_deref(), Some("retained-admin"));
                    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.9"));
                    assert_eq!(session.user_agent.as_deref(), Some("retained-agent"));
                    return if self.session_forbidden {
                        Err(AuthError::forbidden(
                            "session creation cancelled by database hook",
                        ))
                    } else {
                        Ok(HookControl::Cancel)
                    };
                }
                Ok(HookControl::Continue)
            }
        }
        let password_hash = better_auth_core::hash_password(None, "password123")
            .await
            .unwrap();
        for (cancel_session, session_forbidden) in [(false, false), (true, false), (true, true)] {
            for existing in [false, true] {
                let db = Database::connect("sqlite::memory:").await.unwrap();
                better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
                    .await
                    .unwrap();
                let config = Arc::new(AuthConfig::new("skip-hook-secret-at-least-32-characters"));
                let mut ctx = AuthContext::new(
                    Arc::clone(&config),
                    Arc::new(SeaOrmStore::<TestSchema>::new(
                        Arc::clone(&config),
                        db.clone(),
                    )),
                );
                let user = ctx
                    .database
                    .create_user(
                        CreateUser::new()
                            .with_name("Hook Owner")
                            .with_email("hook-owner@fixture.test"),
                    )
                    .await
                    .unwrap();
                drop(
                    ctx.database
                        .create_account(CreateAccount {
                            additional_fields: Default::default(),
                            user_id: user.id.clone(),
                            account_id: user.id.clone(),
                            provider_id: "credential".into(),
                            password: Some(password_hash.clone()),
                            access_token: None,
                            refresh_token: None,
                            id_token: None,
                            access_token_expires_at: None,
                            refresh_token_expires_at: None,
                            scope: None,
                        })
                        .await
                        .unwrap(),
                );
                let session = ctx
                    .database
                    .create_session(CreateSession {
                        token: None,
                        user_id: user.id.clone(),
                        expires_at: Utc::now() + ctx.config.session.expires_in,
                        active_organization_id: Some("retained-org".into()),
                        active_team_id: Some("retained-team".into()),
                        impersonated_by: Some("retained-admin".into()),
                        ip_address: Some("127.0.0.9".into()),
                        user_agent: Some("retained-agent".into()),
                        additional_fields: better_auth_core::field_policy::FieldValues::default(),
                    })
                    .await
                    .unwrap();
                let factor = if existing {
                    Some(
                        ctx.database
                            .create_two_factor(CreateTwoFactor {
                                user_id: user.id.clone(),
                                secret: encrypt_value(&ctx.config, "historical-secret").unwrap(),
                                backup_codes: encrypt_value(&ctx.config, "[\"historical-backup\"]")
                                    .unwrap(),
                                verified: Some(false),
                                failed_verification_count: Some(0.5),
                                locked_until: Some(Utc::now() + Duration::minutes(1)),
                            })
                            .await
                            .unwrap(),
                    )
                } else {
                    None
                };
                let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
                ctx.database = Arc::new(
                    SeaOrmStore::<TestSchema>::new(config, db.clone()).with_hooks(vec![Arc::new(
                        PolicyHook {
                            cancel_session,
                            session_forbidden,
                            observed: Arc::clone(&observed),
                        },
                    )]),
                );
                let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    ..Default::default()
                });
                let mut init = better_auth_core::AuthInitContext::new(
                    Arc::clone(&ctx.config),
                    Arc::clone(&ctx.database),
                );
                plugin.on_init(&mut init).await.unwrap();
                crate::plugins::OrganizationPlugin::with_config(
                    crate::plugins::organization::OrganizationConfig {
                        teams: crate::plugins::organization::TeamsConfig {
                            enabled: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .on_init(&mut init)
                .await
                .unwrap();
                crate::plugins::AdminPlugin::new()
                    .on_init(&mut init)
                    .await
                    .unwrap();
                ctx.database = init.database_with_registered_transforms();
                let parts = init.into_parts();
                ctx.metadata = parts.metadata;
                ctx.extensions = parts.extensions;
                let cookie = create_session_cookie(&session.token, &ctx.config);
                let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
                drop(
                    request
                        .headers
                        .insert("cookie".into(), cookie.split(';').next().unwrap().into()),
                );
                request.body = Some(br#"{"password":"password123"}"#.to_vec());
                let result = better_auth_core::with_request_hook_context(
                    &request,
                    plugin.on_request(&request, &ctx),
                )
                .await;
                if cancel_session && !session_forbidden {
                    let response = result.unwrap().unwrap();
                    assert_eq!(response.status, 500);
                    assert_eq!(response.body.len(), 0);
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.status_code(), if cancel_session { 403 } else { 400 });
                    if session_forbidden {
                        assert!(matches!(error, AuthError::Forbidden(_)));
                    }
                }
                let expected = if cancel_session {
                    vec![
                        ("user".into(), user.id.clone()),
                        ("session".into(), user.id.clone()),
                    ]
                } else {
                    vec![("user".into(), user.id.clone())]
                };
                assert_eq!(*observed.lock().unwrap(), expected);
                assert_eq!(
                    serde_json::to_value(
                        ctx.database
                            .get_two_factor_by_user_id(&user.id)
                            .await
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::to_value(factor).unwrap()
                );
                let stored_user = ctx
                    .database
                    .get_user_by_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(stored_user.two_factor_enabled(), cancel_session);
                let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
                assert_eq!(sessions.len(), 1);
                assert_eq!(
                    serde_json::to_value(
                        (sessions)
                            .first()
                            .expect("fixture contains the requested index")
                    )
                    .unwrap(),
                    serde_json::to_value(&session).unwrap()
                );
                let (current_user, current_session) = ctx.require_session(&request).await.unwrap();
                assert_eq!(current_user.id, user.id);
                assert_eq!(current_session.token, session.token);
                db.close().await.unwrap();
            }
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn two_factor_password_checks_use_configured_native_hasher_and_utf16_maximum() {
        use better_auth_core::{PasswordHasher, ScryptHasher, UpdateAccount};
        struct PrefixedHasher {
            received: std::sync::Mutex<Vec<(String, String)>>,
        }
        #[async_trait]
        impl PasswordHasher for PrefixedHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                ScryptHasher
                    .hash(&format!("provider-prefix:{password}"))
                    .await
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                self.received
                    .lock()
                    .unwrap()
                    .push((hash.into(), password.into()));
                ScryptHasher
                    .verify(hash, &format!("provider-prefix:{password}"))
                    .await
            }
        }
        let (mut ctx, user, session) =
            create_test_context_with_credential_user("native-provider@fixture.test", false).await;
        let provider = Arc::new(PrefixedHasher {
            received: std::sync::Mutex::new(Vec::new()),
        });
        let hash = provider.hash("password123").await.unwrap();
        let account = ctx
            .database
            .get_user_accounts(&user.id)
            .await
            .unwrap()
            .into_iter()
            .find(|account| account.provider_id == "credential")
            .unwrap();
        drop(
            ctx.database
                .update_account(
                    &account.id,
                    UpdateAccount {
                        password: Some(hash.clone()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        );
        let plugin = TwoFactorPlugin::new();
        let mut init = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        crate::plugins::EmailPasswordPlugin::new()
            .password_max_length(13)
            .password_hasher(Arc::<PrefixedHasher>::clone(&provider))
            .on_init(&mut init)
            .await
            .unwrap();
        plugin.on_init(&mut init).await.unwrap();
        let parts = init.into_parts();
        ctx.extensions = parts.extensions;
        ctx.metadata = parts.metadata;
        let cookie = create_session_cookie(&session.token, &ctx.config);
        let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
        drop(
            request
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into()),
        );
        request.body = Some(br#"{"password":"password123"}"#.to_vec());
        let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let factor = ctx
            .database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        request.path = "/two-factor/get-totp-uri".into();
        request.body = Some(br#"{"password":"wrong-password"}"#.to_vec());
        let wrong = plugin.on_request(&request, &ctx).await.unwrap_err();
        assert_eq!(
            wrong.error_payload().1.as_deref(),
            Some("PASSWORD_TOO_LONG")
        );
        // A different valid-length password must reach the configured real verifier.
        request.body = Some(br#"{"password":"wrong-pass"}"#.to_vec());
        let wrong_2 = plugin.on_request(&request, &ctx).await.unwrap_err();
        assert_eq!(
            wrong_2.error_payload().1.as_deref(),
            Some("INVALID_PASSWORD")
        );
        request.body =
            Some(serde_json::to_vec(&serde_json::json!({"password":"🍵".repeat(7)})).unwrap());
        let long = plugin.on_request(&request, &ctx).await.unwrap_err();
        assert_eq!(long.error_payload().1.as_deref(), Some("PASSWORD_TOO_LONG"));
        assert_eq!(
            *provider.received.lock().unwrap(),
            vec![
                (hash.clone(), "password123".into()),
                (hash, "wrong-pass".into())
            ]
        );
        assert_eq!(
            serde_json::to_value(
                ctx.database
                    .get_two_factor_by_user_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(factor).unwrap()
        );
        assert!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn signed_empty_factor_challenge_cannot_read_a_seeded_empty_identifier() {
        let (ctx, user, _) =
            create_test_context_with_credential_user("empty-challenge@fixture.test", true).await;
        let seeded = ctx
            .database
            .create_verification(CreateVerification {
                identifier: String::new(),
                value: user.id.clone(),
                expires_at: Utc::now() + Duration::minutes(5),
            })
            .await
            .unwrap();
        let signed =
            better_auth_core::utils::cookie_utils::sign_cookie_value("", &ctx.config.secret);
        assert_eq!(
            better_auth_core::utils::cookie_utils::verify_cookie_value(&signed, &ctx.config.secret),
            Some(String::new())
        );
        let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-otp");
        drop(req.headers.insert(
            "cookie".into(),
            format!(
                "{}={signed}",
                related_cookie_name(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)
            ),
        ));
        let error = resolve_two_factor_state(&req, &ctx)
            .await
            .err()
            .expect("An empty signed challenge must be rejected");
        assert_eq!(error.status_code(), 401);
        let untouched = ctx
            .database
            .get_verification_by_identifier("")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(untouched.id(), seeded.id());
        assert_eq!(untouched.value(), seeded.value());
        assert_eq!(untouched.expires_at(), seeded.expires_at());
        assert_eq!(
            ctx.database
                .get_user_sessions(&user.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn pending_factor_preferences_authenticate_the_first_cookie_and_preserve_issued_expiry() {
        let (ctx, user, _) =
            create_test_context_with_credential_user("preferences@fixture.test", true).await;
        let preference_name = related_cookie_name(&ctx.config, DONT_REMEMBER_COOKIE_SUFFIX);
        let empty =
            better_auth_core::utils::cookie_utils::sign_cookie_value("", &ctx.config.secret);
        let signed =
            better_auth_core::utils::cookie_utils::sign_cookie_value("true", &ctx.config.secret);
        let foreign =
            better_auth_core::utils::cookie_utils::sign_cookie_value("true", "foreign-secret");
        for (preference, temporary) in [
            (empty.clone(), false),
            (signed.clone(), true),
            (foreign, false),
            ("true".to_owned(), false),
            (format!("{empty}; {preference_name}={signed}"), false),
            (format!("{signed}; {preference_name}={empty}"), true),
        ] {
            let challenge = begin_sign_in_challenge(&user, None, &ctx).await.unwrap();
            let challenge_cookie = challenge
                .set_cookie_headers
                .iter()
                .find(|header| {
                    header.starts_with(&format!(
                        "{}=",
                        related_cookie_name(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)
                    ))
                })
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-otp");
            drop(req.headers.insert(
                "cookie".into(),
                format!("{challenge_cookie}; {preference_name}={preference}"),
            ));
            let ResolvedTwoFactorState::Pending(pending) =
                resolve_two_factor_state(&req, &ctx).await.unwrap()
            else {
                panic!("A signed pending challenge must resolve without a session cookie");
            };
            assert_eq!(pending.dont_remember, temporary);
            let (completed, headers) =
                finalize_pending_two_factor(pending, &req, false, true, &ctx)
                    .await
                    .unwrap();
            let before = ctx
                .database
                .get_session(&completed.token)
                .await
                .unwrap()
                .unwrap();
            let lifetime = before.expires_at() - before.created_at();
            assert!(
                (lifetime - Duration::days(if temporary { 1 } else { 7 }))
                    .num_milliseconds()
                    .abs()
                    < 1000
            );
            let mut read = AuthRequest::new(HttpMethod::Get, "/get-session");
            let cookies = headers
                .iter()
                .filter(|header| !header.contains("Max-Age=0"))
                .map(|header| header.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            drop(read.headers.insert("cookie".into(), cookies));
            let (authenticated_user, authenticated_session) =
                ctx.require_session(&read).await.unwrap();
            assert_eq!(authenticated_user.id(), user.id);
            assert_eq!(authenticated_session.token, completed.token);
            assert_eq!(authenticated_session.expires_at, before.expires_at());
            let after = ctx
                .database
                .get_session(&completed.token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.expires_at(), before.expires_at());
            assert_eq!(after.updated_at(), before.updated_at());
        }
    }

    async fn create_test_context_with_credential_user(
        email: &str,
        two_factor_enabled: bool,
    ) -> (AuthContext<TestSchema>, UserView, SessionView) {
        let mut ctx = test_helpers::create_test_context().await;
        let mut init = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        TwoFactorPlugin::new().on_init(&mut init).await.unwrap();
        ctx.database = init.database_with_registered_transforms();
        let parts = init.into_parts();
        ctx.metadata = parts.metadata;
        ctx.extensions = parts.extensions;
        let user = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email(email)
                .with_name("Two Factor Tester"),
        )
        .await;

        let password_hash = better_auth_core::hash_password(None, "password123")
            .await
            .unwrap();
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

        let user = if two_factor_enabled {
            UserView::from(
                &ctx.database
                    .update_user(
                        &user.id,
                        UpdateUser {
                            two_factor_enabled: Some(true),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap(),
            )
        } else {
            user
        };

        let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(1)).await;
        (ctx, user, session)
    }

    fn cookie_value(header: &str) -> String {
        Cookie::parse(header)
            .expect("Set-Cookie header should parse")
            .value()
            .to_owned()
    }

    #[test]
    fn test_signed_cookie_round_trip_and_tamper_rejection() {
        let signed = sign_cookie_value("secret-value", "payload-value");
        let verified = verify_signed_cookie_value("secret-value", &signed);
        assert_eq!(verified.as_deref(), Some("payload-value"));

        let tampered = signed.replacen("payload-value", "other-value", 1);
        let tampered_verified = verify_signed_cookie_value("secret-value", &tampered);
        assert!(tampered_verified.is_none());
    }

    #[tokio::test]
    async fn test_begin_sign_in_challenge_sets_pending_cookie_and_remember_choice() {
        let (ctx, user, _session) =
            create_test_context_with_credential_user("challenge@example.com", true).await;

        let challenge = begin_sign_in_challenge(&user, Some(false), &ctx)
            .await
            .unwrap();
        assert!(challenge.response.two_factor_redirect);

        let two_factor_cookie = challenge
            .set_cookie_headers
            .iter()
            .find(|header| header.starts_with("better-auth.two_factor="))
            .cloned()
            .expect("challenge should set the two-factor cookie");
        let dont_remember_cookie = challenge
            .set_cookie_headers
            .iter()
            .find(|header| header.starts_with("better-auth.dont_remember="))
            .cloned()
            .expect("challenge should set the remember-choice cookie");

        let two_factor_req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/two-factor/verify-otp",
            None,
            None,
        );
        let mut req = two_factor_req;
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.two_factor={}; better-auth.dont_remember={}",
                cookie_value(&two_factor_cookie),
                cookie_value(&dont_remember_cookie)
            ),
        );

        let identifier = read_signed_cookie(&req, TWO_FACTOR_COOKIE_SUFFIX, &ctx)
            .expect("signed cookie should verify");
        let verification = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .expect("challenge should persist a pending verification");
        assert_eq!(verification.value(), user.id);
    }

    #[tokio::test]
    async fn test_inspect_trusted_device_rotates_server_state() {
        let (ctx, user, _session) =
            create_test_context_with_credential_user("trusted@example.com", true).await;

        let trust_cookie = create_trust_device_cookie_header(&user, &ctx)
            .await
            .unwrap();
        let mut req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-in/email",
            None,
            None,
        );
        req.headers.insert(
            "cookie".to_owned(),
            format!("better-auth.trust_device={}", cookie_value(&trust_cookie)),
        );

        let original_cookie = read_signed_cookie(&req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
            .expect("trust cookie should verify");
        let original_identifier = original_cookie
            .split_once('!')
            .expect("trust cookie should include the identifier")
            .1
            .to_owned();

        let result = inspect_trusted_device(&req, &user, &ctx).await.unwrap();
        assert!(result.trusted);
        assert_eq!(result.set_cookie_headers.len(), 1);

        let rotated_cookie = (*(result.set_cookie_headers)
            .first()
            .expect("fixture contains the requested index"))
        .clone();
        let mut rotated_req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-in/email",
            None,
            None,
        );
        rotated_req.headers.insert(
            "cookie".to_owned(),
            format!("better-auth.trust_device={}", cookie_value(&rotated_cookie)),
        );
        let rotated_value = read_signed_cookie(&rotated_req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
            .expect("rotated trust cookie should verify");
        let rotated_identifier = rotated_value
            .split_once('!')
            .expect("rotated cookie should include the identifier")
            .1
            .to_owned();

        assert_ne!(original_identifier, rotated_identifier);
        assert!(
            ctx.database
                .get_verification_by_identifier(&original_identifier)
                .await
                .unwrap()
                .is_none(),
            "the previous trust-device record should be deleted during rotation",
        );
        assert!(
            ctx.database
                .get_verification_by_identifier(&rotated_identifier)
                .await
                .unwrap()
                .is_some(),
            "the rotated trust-device record should be persisted",
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn totp_enrollment_and_real_verification_apply_user_hooks_and_preserve_rotation_owner() {
        let (mut ctx, user, session) =
            create_test_context_with_credential_user("reissue@example.com", false).await;
        ctx.database.delete_session(&session.token).await.unwrap();
        let session = ctx
            .database
            .create_session(better_auth_core::CreateSession {
                token: None,
                user_id: user.id.clone(),
                expires_at: session.expires_at,
                ip_address: Some("127.0.0.7".into()),
                user_agent: Some("configured-agent".into()),
                active_organization_id: Some("configured-organization".into()),
                active_team_id: Some("configured-team".into()),
                impersonated_by: Some("configured-admin".into()),
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
            })
            .await
            .unwrap();
        let plugin = TwoFactorPlugin::new();
        let mut configured = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        plugin.on_init(&mut configured).await.unwrap();
        crate::plugins::OrganizationPlugin::with_config(
            crate::plugins::organization::OrganizationConfig {
                teams: crate::plugins::organization::TeamsConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .on_init(&mut configured)
        .await
        .unwrap();
        crate::plugins::AdminPlugin::new()
            .on_init(&mut configured)
            .await
            .unwrap();
        ctx.metadata = configured.into_parts().metadata;
        let cookie = create_session_cookie(&session.token, &ctx.config);
        let mut enrollment = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
        drop(
            enrollment
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into()),
        );
        enrollment.body = Some(br#"{"password":"password123"}"#.to_vec());
        let enabled = plugin.on_request(&enrollment, &ctx).await.unwrap().unwrap();
        assert_eq!(enabled.status, 200);
        let factor = ctx
            .database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(factor.verified, Some(false));

        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&captured);
        let mut init = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        init.register_user_update_transform(move |id, mut update| {
            observed
                .lock()
                .unwrap()
                .push((id.to_owned(), update.two_factor_enabled));
            if update.two_factor_enabled == Some(true) {
                update.name = Some("Hook Updated Owner".into());
            }
            Ok(update)
        });
        ctx.database = init.database_with_registered_transforms();
        let plaintext = decrypt_value(&ctx.config, &factor.secret).unwrap();
        let code = plugin.generate_totp(&plaintext).unwrap();
        let mut verification = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-totp");
        verification.headers = enrollment.headers;
        verification.body = Some(serde_json::to_vec(&serde_json::json!({"code":code})).unwrap());
        let response = plugin
            .on_request(&verification, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        let payload: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(*(payload).get("user").unwrap_or(&serde_json::Value::Null))
                .get("twoFactorEnabled")
                .unwrap_or(&serde_json::Value::Null)),
            false
        );
        // Upstream returns the old snapshot while rotating the browser cookie.
        assert_eq!(
            (*(payload).get("token").unwrap_or(&serde_json::Value::Null)),
            session.token
        );
        let set_cookie_headers = response.headers.get_all("Set-Cookie").collect::<Vec<_>>();
        let rotated = better_auth_core::utils::cookie_utils::verify_cookie_value(
            &cookie_value(
                (set_cookie_headers)
                    .first()
                    .expect("fixture contains the requested index"),
            ),
            &ctx.config.secret,
        )
        .expect("the session cookie must authenticate its token");
        assert_ne!(rotated, session.token);
        assert_eq!(set_cookie_headers.len(), 1);
        assert!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .is_none(),
            "the original session should be deleted after re-issuing",
        );
        assert!(
            ctx.database.get_session(&rotated).await.unwrap().is_some(),
            "the new session token should be persisted",
        );
        assert_eq!(
            *captured.lock().unwrap(),
            vec![(user.id.clone(), Some(true))]
        );
        let stored_user = ctx
            .database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_user.two_factor_enabled, Some(true));
        assert_eq!(stored_user.name.as_deref(), Some("Hook Updated Owner"));
        let verified_factor = ctx
            .database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified_factor.id, factor.id);
        assert_eq!(verified_factor.secret, factor.secret);
        assert_eq!(verified_factor.backup_codes, factor.backup_codes);
        assert_eq!(verified_factor.verified, Some(true));
        let mut browser = AuthRequest::new(HttpMethod::Get, "/get-session");
        drop(
            browser.headers.insert(
                "cookie".into(),
                (*(set_cookie_headers)
                    .first()
                    .expect("fixture contains the requested index"))
                .split(';')
                .next()
                .unwrap()
                .into(),
            ),
        );
        let (current_user, current_session) = ctx.require_session(&browser).await.unwrap();
        assert_eq!(current_user.id, user.id);
        assert_eq!(current_user.name.as_deref(), Some("Hook Updated Owner"));
        assert_eq!(current_session.token, rotated);
        assert_eq!(current_session.ip_address, session.ip_address);
        assert_eq!(current_session.user_agent, session.user_agent);
        assert_eq!(
            current_session.active_organization_id,
            session.active_organization_id
        );
        assert_eq!(current_session.active_team_id, session.active_team_id);
        assert_eq!(current_session.impersonated_by, session.impersonated_by);
    }

    #[tokio::test]
    async fn test_view_backup_codes_returns_decrypted_codes() {
        let plugin = TwoFactorPlugin::new();
        let (ctx, user, _session) =
            create_test_context_with_credential_user("view-codes@example.com", true).await;

        let expected_codes = vec!["ABCDE-12345".to_owned(), "FGHIJ-67890".to_owned()];
        let encrypted = encrypt_value(
            &ctx.config,
            &serde_json::to_string(&expected_codes).unwrap(),
        )
        .unwrap();
        drop(
            ctx.database
                .create_two_factor(CreateTwoFactor {
                    user_id: user.id.clone(),
                    secret: encrypt_value(&ctx.config, "totp-secret").unwrap(),
                    backup_codes: encrypted,
                    ..Default::default()
                })
                .await
                .unwrap(),
        );

        let backup_codes = plugin.view_backup_codes(&user.id, &ctx).await.unwrap();
        assert_eq!(backup_codes, expected_codes);
    }

    #[tokio::test]
    async fn test_view_backup_codes_rejects_invalid_stored_json() {
        let plugin = TwoFactorPlugin::new();
        let (ctx, user, _session) =
            create_test_context_with_credential_user("invalid-view-codes@example.com", true).await;

        drop(
            ctx.database
                .create_two_factor(CreateTwoFactor {
                    user_id: user.id.clone(),
                    secret: encrypt_value(&ctx.config, "totp-secret").unwrap(),
                    backup_codes: encrypt_value(&ctx.config, "\"not-an-array\"").unwrap(),
                    ..Default::default()
                })
                .await
                .unwrap(),
        );

        let err = plugin.view_backup_codes(&user.id, &ctx).await.unwrap_err();
        assert_eq!(err.to_string(), "Invalid backup code");
    }

    #[test]
    fn test_routes_do_not_expose_view_backup_codes() {
        let plugin = TwoFactorPlugin::new();
        assert!(
            <TwoFactorPlugin as AuthPlugin<TestSchema>>::routes(&plugin)
                .iter()
                .all(|route| route.path != "/two-factor/view-backup-codes"),
            "view-backup-codes must stay server-only",
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn disable_preserves_persisted_extensions_and_removes_all_matching_trust_records() {
        let (mut ctx, user, first_session) =
            create_test_context_with_credential_user("disable-extensions@fixture.test", true).await;
        let mut init = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        crate::plugins::admin::AdminPlugin::new()
            .on_init(&mut init)
            .await
            .unwrap();
        crate::plugins::organization::OrganizationPlugin::with_config(
            crate::plugins::organization::OrganizationConfig {
                teams: crate::plugins::organization::TeamsConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .on_init(&mut init)
        .await
        .unwrap();
        ctx.metadata.extend(init.into_parts().metadata);
        ctx.database
            .delete_session(&first_session.token)
            .await
            .unwrap();
        let current = ctx
            .database
            .create_session(better_auth_core::CreateSession {
                token: None,
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: Some("192.0.2.45".to_owned()),
                user_agent: Some("fixture-agent".to_owned()),
                impersonated_by: Some("trusted-impersonator".to_owned()),
                active_organization_id: Some("trusted-organization".to_owned()),
                active_team_id: Some("trusted-team".to_owned()),
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
            })
            .await
            .unwrap();
        ctx.database
            .create_two_factor(CreateTwoFactor {
                user_id: user.id.clone(),
                secret: "stored-secret".to_owned(),
                backup_codes: "stored-codes".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        for _ in 0..2 {
            ctx.database
                .create_verification(CreateVerification {
                    identifier: "trusted-device-record".to_owned(),
                    value: user.id.clone(),
                    expires_at: Utc::now() + Duration::days(30),
                })
                .await
                .unwrap();
        }
        let session_cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
            current.token(),
            &ctx.config.secret,
        );
        let trust_cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
            "trust-token!trusted-device-record",
            &ctx.config.secret,
        );
        let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/disable");
        req.body =
            Some(serde_json::to_vec(&serde_json::json!({"password":"password123"})).unwrap());
        drop(req.headers.insert(
            "cookie".to_owned(),
            format!(
                "{}={session_cookie}; {}={trust_cookie}",
                ctx.config.session.cookie_name,
                related_cookie_name(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX)
            ),
        ));
        let response = TwoFactorPlugin::new()
            .on_request(&req, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        let stored = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(stored.len(), 1);
        let replacement = (stored)
            .first()
            .expect("fixture contains the requested index");
        assert_ne!(replacement.token(), current.token());
        assert_eq!(
            replacement.active_organization_id(),
            Some("trusted-organization")
        );
        assert_eq!(replacement.active_team_id(), Some("trusted-team"));
        assert_eq!(replacement.impersonated_by(), Some("trusted-impersonator"));
        assert_eq!(replacement.ip_address(), current.ip_address());
        assert_eq!(replacement.user_agent(), current.user_agent());
        assert!(
            ctx.database
                .get_session(current.token())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !ctx.database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .two_factor_enabled()
        );
        assert!(
            ctx.database
                .get_two_factor_by_user_id(&user.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_verification_by_identifier("trusted-device-record")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn otp_async_codec_failures_consume_only_their_stage_and_delivery_rejection_retains_rotation_state()
     {
        struct Callback {
            fail_store: bool,
            fail_compare: bool,
            observations: Arc<std::sync::Mutex<Vec<String>>>,
            delivered: Arc<std::sync::Mutex<Option<String>>>,
        }
        #[async_trait]
        impl TwoFactorOtpHasher for Callback {
            async fn hash(&self, otp: &str) -> AuthResult<String> {
                let mut observations = self.observations.lock().unwrap();
                observations.push(format!("hash:{otp}"));
                if self.fail_store || (self.fail_compare && observations.len() > 2) {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "CODEC_REJECTED",
                        message: "Configured codec rejected",
                    });
                }
                drop(observations);

                Ok(format!("stored-{otp}"))
            }
        }
        #[async_trait]
        impl SendTwoFactorOtp for Callback {
            async fn send(&self, _user: &UserView, otp: &str) -> AuthResult<()> {
                self.observations
                    .lock()
                    .unwrap()
                    .push(format!("send:{otp}"));
                *self.delivered.lock().unwrap() = Some(otp.to_owned());
                Err(AuthError::bad_request("Configured async delivery rejected"))
            }
        }
        for (fail_store, fail_compare) in [(true, false), (false, true), (false, false)] {
            let (mut ctx, user, original) =
                create_test_context_with_credential_user("codec@fixture.test", false).await;
            ctx.database.delete_session(&original.token).await.unwrap();
            let session = ctx
                .database
                .create_session(better_auth_core::CreateSession {
                    additional_fields: better_auth_core::field_policy::FieldValues::default(),
                    token: None,
                    user_id: user.id.clone(),
                    expires_at: original.expires_at,
                    ip_address: Some("127.0.0.8".into()),
                    user_agent: Some("otp-agent".into()),
                    active_organization_id: Some("otp-org".into()),
                    active_team_id: Some("otp-team".into()),
                    impersonated_by: Some("otp-admin".into()),
                })
                .await
                .unwrap();
            let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
            let delivered = Arc::new(std::sync::Mutex::new(None));
            let callback = Arc::new(Callback {
                fail_store,
                fail_compare,
                observations: Arc::clone(&observations),
                delivered: Arc::clone(&delivered),
            });
            let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                send_otp: Some(Arc::<Callback>::clone(&callback)),
                otp_storage: TwoFactorOtpStorage::CustomHash(callback),
                ..Default::default()
            });
            let mut init = better_auth_core::AuthInitContext::new(
                Arc::clone(&ctx.config),
                Arc::clone(&ctx.database),
            );
            plugin.on_init(&mut init).await.unwrap();
            crate::plugins::OrganizationPlugin::with_config(
                crate::plugins::organization::OrganizationConfig {
                    teams: crate::plugins::organization::TeamsConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .on_init(&mut init)
            .await
            .unwrap();
            crate::plugins::AdminPlugin::new()
                .on_init(&mut init)
                .await
                .unwrap();

            init.register_user_update_transform(|_, mut update| {
                if update.two_factor_enabled == Some(true) {
                    update.name = Some("OTP Hook Owner".into());
                }
                Ok(update)
            });
            ctx.database = init.database_with_registered_transforms();
            let parts = init.into_parts();
            ctx.metadata = parts.metadata;
            ctx.extensions = parts.extensions;

            let identifier = format!("2fa-otp-{}!{}", user.id, session.id);
            let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/send-otp");
            request.headers.insert(
                "cookie".into(),
                create_session_cookie(&session.token, &ctx.config)
                    .split(';')
                    .next()
                    .unwrap()
                    .into(),
            );
            request.body = Some(b"{}".to_vec());
            let result = plugin.on_request(&request, &ctx).await;
            if fail_store {
                assert!(matches!(
                    result,
                    Err(AuthError::Upstream {
                        code: "CODEC_REJECTED",
                        ..
                    })
                ));
                assert!(delivered.lock().unwrap().is_none());
                assert!(
                    ctx.database
                        .get_latest_verification_by_identifier(&identifier)
                        .await
                        .unwrap()
                        .is_none()
                );
            } else {
                assert_eq!(
                    result.unwrap().unwrap().status,
                    200,
                    "async delivery failure must retain issued state"
                );
                let otp = delivered
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("actual callback delivery");
                let stored = ctx
                    .database
                    .get_latest_verification_by_identifier(&identifier)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(stored.value, format!("stored-{otp}:0"));
                request.path = "/two-factor/verify-otp".into();
                request.body = Some(serde_json::to_vec(&serde_json::json!({"code":otp})).unwrap());
                let result_2 = plugin.on_request(&request, &ctx).await;
                assert!(
                    ctx.database
                        .get_latest_verification_by_identifier(&identifier)
                        .await
                        .unwrap()
                        .is_none()
                );
                if fail_compare {
                    assert!(matches!(
                        result_2,
                        Err(AuthError::Upstream {
                            code: "CODEC_REJECTED",
                            ..
                        })
                    ));
                    assert!(
                        !ctx.database
                            .get_user_by_id(&user.id)
                            .await
                            .unwrap()
                            .unwrap()
                            .two_factor_enabled()
                    );
                    assert!(
                        ctx.database
                            .get_session(&session.token)
                            .await
                            .unwrap()
                            .is_some()
                    );
                } else {
                    let response = result_2.unwrap().unwrap();
                    assert_eq!(response.status, 200);
                    let payload: serde_json::Value =
                        serde_json::from_slice(&response.body).unwrap();
                    assert_eq!(
                        (*(*(payload).get("user").unwrap_or(&serde_json::Value::Null))
                            .get("name")
                            .unwrap_or(&serde_json::Value::Null)),
                        "OTP Hook Owner"
                    );
                    assert_eq!(
                        (*(*(payload).get("user").unwrap_or(&serde_json::Value::Null))
                            .get("twoFactorEnabled")
                            .unwrap_or(&serde_json::Value::Null)),
                        true
                    );
                    let token = (*(payload).get("token").unwrap_or(&serde_json::Value::Null))
                        .as_str()
                        .unwrap();
                    assert_ne!(token, session.token);
                    let new = ctx.database.get_session(token).await.unwrap().unwrap();
                    assert_eq!(new.user_id, session.user_id);
                    assert_eq!(new.ip_address, session.ip_address);
                    assert_eq!(new.user_agent, session.user_agent);
                    assert_eq!(new.active_organization_id, session.active_organization_id);
                    assert_eq!(new.active_team_id, session.active_team_id);
                    assert_eq!(new.impersonated_by, session.impersonated_by);
                    assert!(
                        ctx.database
                            .get_session(&session.token)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    let header = response.headers.get_all("Set-Cookie").next().unwrap();
                    assert_eq!(
                        better_auth_core::utils::cookie_utils::verify_cookie_value(
                            &cookie_value(header),
                            &ctx.config.secret
                        )
                        .as_deref(),
                        Some(token)
                    );
                }
                assert_eq!(
                    observations.lock().unwrap().as_slice(),
                    &[
                        format!("hash:{otp}"),
                        format!("send:{otp}"),
                        format!("hash:{otp}")
                    ]
                );
            }
            assert!(
                ctx.database
                    .get_two_factor_by_user_id(&user.id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn otp_enable_without_delivery_checks_password_then_rejects_without_mutating_the_owner() {
        let (ctx, user, session) =
            create_test_context_with_credential_user("disabled-otp@fixture.test", false).await;
        let plugin = TwoFactorPlugin::new();
        let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
        request.headers.insert(
            "cookie".into(),
            create_session_cookie(&session.token, &ctx.config)
                .split(';')
                .next()
                .unwrap()
                .into(),
        );
        request.body = Some(br#"{"password":"wrong","method":"otp"}"#.to_vec());
        let wrong = plugin.on_request(&request, &ctx).await.unwrap_err();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&wrong.to_auth_response().body).unwrap(),
            serde_json::json!({"message":"Invalid password","code":"INVALID_PASSWORD"})
        );
        request.body = Some(br#"{"password":"password123","method":"otp"}"#.to_vec());
        assert!(matches!(
            plugin.on_request(&request, &ctx).await,
            Err(AuthError::Upstream {
                status: 400,
                code: "OTP_NOT_CONFIGURED",
                message: "OTP is not available"
            })
        ));
        assert!(
            !ctx.database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .two_factor_enabled()
        );
        assert!(
            ctx.database
                .get_two_factor_by_user_id(&user.id)
                .await
                .unwrap()
                .is_none()
        );
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            (sessions)
                .first()
                .expect("fixture contains the requested index")
                .token,
            session.token
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn installed_legacy_factor_reads_authenticates_and_consumes_backups_without_rewriting_secret()
     {
        // Fixed independent WebCrypto HKDF/AES-GCM vectors for the previous Rust
        // persistence format. The producer under test does not generate this row.
        let legacy_secret =
            "AAECAwQFBgcICQoL9NYPdhHpe_5gn4m4X_opqjMmxni2EyB3YCXHFEgQIyla3Fd0gf3_j1wgttJLPrPp";
        let legacy_codes =
            "DA0ODxAREhMUFRYXMc-xHuks-lR5NpeRiTHkuDgsOlsOZwvsxoEufAsjDonqpW0x_ZMYlL0UMdsH";
        let plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
        let plugin = TwoFactorPlugin::new();
        let (ctx, user, session) =
            create_test_context_with_credential_user("legacy-factor@fixture.test", true).await;
        let installed = ctx
            .database
            .create_two_factor(CreateTwoFactor {
                user_id: user.id.clone(),
                secret: legacy_secret.into(),
                backup_codes: legacy_codes.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            plugin.view_backup_codes(&user.id, &ctx).await.unwrap(),
            ["ABCDE-12345", "FGHIJ-67890"]
        );
        let request = |path: &str, body: serde_json::Value| {
            let mut request = AuthRequest::new(HttpMethod::Post, path);
            let cookie = create_session_cookie(&session.token, &ctx.config);
            request
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into());
            request.body = Some(serde_json::to_vec(&body).unwrap());
            request
        };
        let uri = plugin
            .on_request(
                &request(
                    "/two-factor/get-totp-uri",
                    serde_json::json!({"password":"password123"}),
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(uri.status, 200);
        let verified = plugin
            .on_request(
                &request(
                    "/two-factor/verify-totp",
                    serde_json::json!({"code": plugin.generate_totp(plaintext).unwrap()}),
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified.status, 200);
        let consumed = plugin
            .on_request(
                &request(
                    "/two-factor/verify-backup-code",
                    serde_json::json!({"code":"ABCDE-12345"}),
                ),
                &ctx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed.status, 200);
        assert_eq!(
            plugin.view_backup_codes(&user.id, &ctx).await.unwrap(),
            ["FGHIJ-67890"]
        );
        let after = ctx
            .database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.id, installed.id);
        assert_eq!(after.secret, legacy_secret);
        assert_ne!(after.backup_codes, legacy_codes);
        assert!(after.backup_codes.len().is_multiple_of(2));
        assert!(
            after
                .backup_codes
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let stored = after.backup_codes.clone();
        let replay = plugin
            .on_request(
                &request(
                    "/two-factor/verify-backup-code",
                    serde_json::json!({"code":"ABCDE-12345"}),
                ),
                &ctx,
            )
            .await
            .unwrap_err();
        assert_eq!(replay.to_string(), "Invalid backup code");
        assert_eq!(
            ctx.database
                .get_two_factor_by_user_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .backup_codes,
            stored
        );
        assert_eq!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .unwrap()
                .user_id,
            user.id
        );
        let tampered = format!(
            "{}A",
            (legacy_secret)
                .get(..legacy_secret.len() - 1)
                .expect("fixture range is on a UTF-8 boundary")
        );
        ctx.database
            .update_two_factor(
                &installed.id,
                UpdateTwoFactor {
                    secret: Some(tampered.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let rejected = plugin
            .on_request(
                &request(
                    "/two-factor/get-totp-uri",
                    serde_json::json!({"password":"password123"}),
                ),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(matches!(rejected, AuthError::Internal(_)));
        let rejected_row = ctx
            .database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rejected_row.secret, tampered);
        assert_eq!(rejected_row.backup_codes, stored);
        assert!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn configured_backup_callback_errors_preserve_factor_user_and_current_session() {
        // This guards Rust callback error identity, which the cross-runtime happy-path
        // cipher fixture cannot exercise. Pinned runtime independently preserves both
        // 400 and 403 callback errors with this cancellation-like message.
        type Observed = Arc<std::sync::Mutex<Vec<(String, String)>>>;
        fn denied(status: u16) -> AuthError {
            AuthError::Upstream {
                status,
                code: "BACKUP_CALLBACK_DENIED",
                message: "session creation cancelled by database hook",
            }
        }
        struct RejectingCipher {
            status: u16,
            observed: Observed,
        }
        #[async_trait]
        impl TwoFactorBackupCipher for RejectingCipher {
            async fn encrypt(&self, json: &str) -> AuthResult<String> {
                self.observed
                    .lock()
                    .unwrap()
                    .push(("encrypt".into(), json.into()));
                Err(denied(self.status))
            }
            async fn decrypt(&self, _stored: &str) -> AuthResult<String> {
                panic!("enrollment and regeneration must not decode an existing factor")
            }
        }
        for phase in ["generate", "encrypt"] {
            for status in [400, 403] {
                let (ctx, user, session) =
                    create_test_context_with_credential_user("backup-callback@fixture.test", false)
                        .await;
                let observed: Observed = Arc::default();
                let generator_observed = Arc::clone(&observed);
                let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                    skip_verification_on_enable: true,
                    custom_backup_codes_generate: Some(Arc::new(move || {
                        generator_observed
                            .lock()
                            .unwrap()
                            .push(("generate".into(), String::new()));
                        if phase == "generate" {
                            Err(denied(status))
                        } else {
                            Ok(vec!["callback-code".into(), "callback-code".into()])
                        }
                    })),
                    backup_storage: TwoFactorBackupStorage::CustomCipher(Arc::new(
                        RejectingCipher {
                            status,
                            observed: Arc::clone(&observed),
                        },
                    )),
                    ..Default::default()
                });
                let cookie = create_session_cookie(&session.token, &ctx.config);
                let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
                drop(
                    request
                        .headers
                        .insert("cookie".into(), cookie.split(';').next().unwrap().into()),
                );
                request.body = Some(br#"{"password":"password123"}"#.to_vec());
                // Resolve the short-lived native fixture session before observing
                // callback effects; this performs the ordinary expiry refresh.
                drop(ctx.require_session(&request).await.unwrap());
                let before_sessions =
                    serde_json::to_value(ctx.database.get_user_sessions(&user.id).await.unwrap())
                        .unwrap();
                let error = plugin.on_request(&request, &ctx).await.unwrap_err();
                assert!(
                    matches!(error, AuthError::Upstream { status: actual, code: "BACKUP_CALLBACK_DENIED", .. } if actual == status)
                );
                assert!(
                    ctx.database
                        .get_two_factor_by_user_id(&user.id)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    !ctx.database
                        .get_user_by_id(&user.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .two_factor_enabled()
                );
                assert_eq!(
                    serde_json::to_value(ctx.database.get_user_sessions(&user.id).await.unwrap())
                        .unwrap(),
                    before_sessions
                );
                let expected = if phase == "generate" {
                    vec![("generate".into(), String::new())]
                } else {
                    vec![
                        ("generate".into(), String::new()),
                        (
                            "encrypt".into(),
                            "[\"callback-code\",\"callback-code\"]".into(),
                        ),
                    ]
                };
                assert_eq!(*observed.lock().unwrap(), expected);

                drop(
                    ctx.database
                        .update_user(
                            &user.id,
                            UpdateUser {
                                two_factor_enabled: Some(true),
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap(),
                );
                let factor = ctx
                    .database
                    .create_two_factor(CreateTwoFactor {
                        user_id: user.id.clone(),
                        secret: "installed-factor-secret".into(),
                        backup_codes: "installed-factor-codes".into(),
                        verified: Some(true),
                        failed_verification_count: Some(2.5),
                        locked_until: Some(Utc::now() + Duration::minutes(1)),
                    })
                    .await
                    .unwrap();
                let before_user =
                    serde_json::to_value(ctx.database.get_user_by_id(&user.id).await.unwrap())
                        .unwrap();
                observed.lock().unwrap().clear();
                let mut regeneration =
                    AuthRequest::new(HttpMethod::Post, "/two-factor/generate-backup-codes");
                regeneration.headers.clone_from(&request.headers);
                regeneration.body.clone_from(&request.body);
                let error_2 = plugin.on_request(&regeneration, &ctx).await.unwrap_err();
                assert!(
                    matches!(error_2, AuthError::Upstream { status: actual, code: "BACKUP_CALLBACK_DENIED", .. } if actual == status)
                );
                assert_eq!(*observed.lock().unwrap(), expected);
                assert_eq!(
                    serde_json::to_value(
                        ctx.database
                            .get_two_factor_by_user_id(&user.id)
                            .await
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::json!(factor)
                );
                assert_eq!(
                    serde_json::to_value(ctx.database.get_user_by_id(&user.id).await.unwrap())
                        .unwrap(),
                    before_user
                );
                assert_eq!(
                    serde_json::to_value(ctx.database.get_user_sessions(&user.id).await.unwrap())
                        .unwrap(),
                    before_sessions
                );
                assert_eq!(
                    ctx.require_session(&regeneration).await.unwrap().1.token,
                    session.token
                );
            }
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn pending_backup_cipher_errors_restore_only_decode_stage_attempts() {
        type Observed = Arc<std::sync::Mutex<Vec<(String, String)>>>;
        struct Cipher {
            phase: &'static str,
            rejected: Arc<std::sync::atomic::AtomicBool>,
            observed: Observed,
        }
        #[async_trait]
        impl TwoFactorBackupCipher for Cipher {
            async fn encrypt(&self, json: &str) -> AuthResult<String> {
                self.observed
                    .lock()
                    .unwrap()
                    .push(("encrypt".into(), json.into()));
                if self.phase == "encrypt"
                    && self.rejected.load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "BACKUP_CALLBACK_DENIED",
                        message: "Callback denied",
                    });
                }
                Ok(format!("backup-{json}"))
            }
            async fn decrypt(&self, stored: &str) -> AuthResult<String> {
                self.observed
                    .lock()
                    .unwrap()
                    .push(("decrypt".into(), stored.into()));
                if self.phase == "decrypt"
                    && self.rejected.load(std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "BACKUP_CALLBACK_DENIED",
                        message: "Callback denied",
                    });
                }
                Ok(stored.strip_prefix("backup-").unwrap().into())
            }
        }
        for phase in ["decrypt", "encrypt"] {
            let (ctx, user, session) = create_test_context_with_credential_user(
                "backup-pending-callback@fixture.test",
                true,
            )
            .await;
            ctx.database.delete_session(&session.token).await.unwrap();
            let factor = ctx
                .database
                .create_two_factor(CreateTwoFactor {
                    user_id: user.id.clone(),
                    secret: "installed-factor-secret".into(),
                    backup_codes: "backup-[\"same\",\"same\",\"remaining\"]".into(),
                    verified: Some(true),
                    failed_verification_count: Some(2.5),
                    locked_until: None,
                })
                .await
                .unwrap();
            let challenge = begin_sign_in_challenge(&user, None, &ctx).await.unwrap();
            let cookie_name = related_cookie_name(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX);
            let cookie = challenge
                .set_cookie_headers
                .iter()
                .find(|header| header.starts_with(&format!("{cookie_name}=")))
                .unwrap();
            let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-backup-code");
            request
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into());
            request.body =
                Some(br#"{"code":"same","disableSession":true,"trustDevice":true}"#.to_vec());
            let key = read_signed_cookie(&request, TWO_FACTOR_COOKIE_SUFFIX, &ctx).unwrap();
            let attempt_id = format!("2fa-attempts-{key}");
            let before_challenge = serde_json::to_value(
                ctx.database
                    .get_verification_by_identifier(&key)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let before_user =
                serde_json::to_value(ctx.database.get_user_by_id(&user.id).await.unwrap()).unwrap();
            let rejected = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let observed: Observed = Arc::default();
            let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                backup_storage: TwoFactorBackupStorage::CustomCipher(Arc::new(Cipher {
                    phase,
                    rejected: Arc::clone(&rejected),
                    observed: Arc::clone(&observed),
                })),
                ..Default::default()
            });
            let error = plugin.on_request(&request, &ctx).await.unwrap_err();
            assert!(matches!(
                error,
                AuthError::Upstream {
                    status: 400,
                    code: "BACKUP_CALLBACK_DENIED",
                    ..
                }
            ));
            assert_eq!(
                serde_json::to_value(
                    ctx.database
                        .get_two_factor_by_user_id(&user.id)
                        .await
                        .unwrap()
                )
                .unwrap(),
                serde_json::json!(factor)
            );
            assert_eq!(
                serde_json::to_value(
                    ctx.database
                        .get_verification_by_identifier(&key)
                        .await
                        .unwrap()
                )
                .unwrap(),
                before_challenge
            );
            assert_eq!(
                serde_json::to_value(ctx.database.get_user_by_id(&user.id).await.unwrap()).unwrap(),
                before_user
            );
            assert_eq!(
                ctx.database
                    .get_user_sessions(&user.id)
                    .await
                    .unwrap()
                    .len(),
                0
            );
            let attempts = ctx
                .database
                .get_verification_by_identifier(&attempt_id)
                .await
                .unwrap();
            if phase == "decrypt" {
                assert_eq!(attempts.unwrap().value(), "0");
                assert_eq!(
                    *observed.lock().unwrap(),
                    vec![("decrypt".into(), factor.backup_codes.clone())]
                );
            } else {
                assert!(attempts.is_none());
                assert_eq!(
                    *observed.lock().unwrap(),
                    vec![
                        ("decrypt".into(), factor.backup_codes.clone()),
                        ("encrypt".into(), "[\"remaining\"]".into())
                    ]
                );
            }
            rejected.store(false, std::sync::atomic::Ordering::SeqCst);
            let retry = plugin.on_request(&request, &ctx).await;
            if phase == "decrypt" {
                let response = retry.unwrap().unwrap();
                assert_eq!(response.status, 200);
                let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
                assert!(body.get("token").is_none());
                assert_eq!(
                    (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                        .get("id")
                        .unwrap_or(&serde_json::Value::Null)),
                    user.id
                );
                assert!(response.headers.get("set-cookie").is_none());
                let updated = ctx
                    .database
                    .get_two_factor_by_user_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(updated.id, factor.id);
                assert_eq!(updated.secret, factor.secret);
                assert_eq!(updated.backup_codes, "backup-[\"remaining\"]");
                assert_eq!(updated.failed_verification_count, Some(0.0));
            } else {
                let error_2 = retry.unwrap_err();
                assert_eq!(error_2.status_code(), 401);
                assert_eq!(error_2.to_string(), "Invalid two factor cookie");
                assert_eq!(
                    serde_json::to_value(
                        ctx.database
                            .get_two_factor_by_user_id(&user.id)
                            .await
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::json!(factor)
                );
            }
            assert!(
                ctx.database
                    .get_verification_by_identifier(&attempt_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                serde_json::to_value(
                    ctx.database
                        .get_verification_by_identifier(&key)
                        .await
                        .unwrap()
                )
                .unwrap(),
                before_challenge
            );
            assert_eq!(
                ctx.database
                    .get_user_sessions(&user.id)
                    .await
                    .unwrap()
                    .len(),
                0
            );
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn authenticated_otp_maps_only_session_creation_cancellation_and_preserves_hook_inputs() {
        use better_auth_core::{AuthConfig, CreateSession};
        use better_auth_seaorm::{
            Database, DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore,
        };

        struct Hook {
            mode: u8,
            observed: Arc<std::sync::Mutex<Vec<String>>>,
        }
        #[async_trait]
        impl DatabaseHooks<TestSchema, SeaOrmBackend> for Hook {
            async fn before_update_user(
                &self,
                _id: &str,
                update: &mut UpdateUser,
                _context: &SeaOrmHookContext<'_>,
            ) -> AuthResult<HookControl> {
                if update.two_factor_enabled == Some(true) {
                    self.observed.lock().unwrap().push("user".into());
                    if self.mode == 3 {
                        return Err(AuthError::SessionCreationCancelled);
                    }
                }
                Ok(HookControl::Continue)
            }
            async fn before_create_session(
                &self,
                session: &mut CreateSession,
                context: &SeaOrmHookContext<'_>,
            ) -> AuthResult<HookControl> {
                if context
                    .request
                    .as_ref()
                    .is_some_and(|request| request.path.ends_with("/two-factor/verify-otp"))
                {
                    self.observed.lock().unwrap().push("session".into());
                    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.7"));
                    assert_eq!(session.user_agent.as_deref(), Some("original-otp-agent"));
                    return match self.mode {
                        0 => Ok(HookControl::Cancel),
                        1 => Err(AuthError::forbidden(
                            "session creation cancelled by database hook",
                        )),
                        _ => Err(AuthError::bad_request(
                            "session creation cancelled by database hook",
                        )),
                    };
                }
                Ok(HookControl::Continue)
            }
        }
        struct Sender(Arc<std::sync::Mutex<Option<String>>>);
        #[async_trait]
        impl SendTwoFactorOtp for Sender {
            async fn send(&self, _user: &UserView, otp: &str) -> AuthResult<()> {
                *self.0.lock().unwrap() = Some(otp.into());
                Ok(())
            }
        }
        for mode in 0..4 {
            let database = Database::connect("sqlite::memory:").await.unwrap();
            better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
                .await
                .unwrap();
            let config = Arc::new(AuthConfig::new("authenticated-otp-hook-secret-at-least-32"));
            let mut ctx = AuthContext::new(
                Arc::clone(&config),
                Arc::new(SeaOrmStore::<TestSchema>::new(
                    Arc::clone(&config),
                    database.clone(),
                )),
            );
            let user = ctx
                .database
                .create_user(
                    CreateUser::new()
                        .with_name("Native OTP Owner")
                        .with_email("native-otp@fixture.test"),
                )
                .await
                .unwrap();
            let session = ctx
                .database
                .create_session(CreateSession {
                    token: None,
                    user_id: user.id.clone(),
                    expires_at: Utc::now() + Duration::hours(1),
                    ip_address: Some("127.0.0.7".into()),
                    user_agent: Some("original-otp-agent".into()),
                    active_organization_id: None,
                    active_team_id: None,
                    impersonated_by: None,
                    additional_fields: better_auth_core::field_policy::FieldValues::default(),
                })
                .await
                .unwrap();
            let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
            ctx.database = Arc::new(SeaOrmStore::<TestSchema>::new(config, database).with_hooks(
                vec![Arc::new(Hook {
                    mode,
                    observed: Arc::clone(&observed),
                })],
            ));
            let delivered = Arc::new(std::sync::Mutex::new(None));
            let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                send_otp: Some(Arc::new(Sender(Arc::clone(&delivered)))),
                ..Default::default()
            });
            let mut init = better_auth_core::AuthInitContext::new(
                Arc::clone(&ctx.config),
                Arc::clone(&ctx.database),
            );
            plugin.on_init(&mut init).await.unwrap();
            ctx.database = init.database_with_registered_transforms();
            let parts = init.into_parts();
            ctx.metadata = parts.metadata;
            ctx.extensions = parts.extensions;
            let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/send-otp");
            request.headers.insert(
                "cookie".into(),
                create_session_cookie(&session.token, &ctx.config)
                    .split(';')
                    .next()
                    .unwrap()
                    .into(),
            );
            request.body = Some(b"{}".to_vec());
            assert_eq!(
                plugin
                    .on_request(&request, &ctx)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                200
            );
            let before = ctx.database.get_user_sessions(&user.id).await.unwrap();
            assert_eq!(before.len(), 1);
            assert_eq!(
                (before)
                    .first()
                    .expect("fixture contains the requested session")
                    .id,
                session.id
            );
            assert_eq!(
                (before)
                    .first()
                    .expect("fixture contains the requested session")
                    .token,
                session.token
            );
            let code = delivered
                .lock()
                .unwrap()
                .clone()
                .expect("real delivery required");
            request.path = "/two-factor/verify-otp".into();
            request.body = Some(
                serde_json::to_vec(&serde_json::json!({"code":code,"trustDevice":true})).unwrap(),
            );
            let result = better_auth_core::with_request_hook_context(
                &request,
                plugin.on_request(&request, &ctx),
            )
            .await;
            match mode {
                0 => {
                    let response = result.unwrap().unwrap();
                    assert_eq!(response.status, 500);
                    assert_eq!(response.body.len(), 0);
                    assert_eq!(response.headers.get_all("Set-Cookie").count(), 0);
                }
                1 => assert!(matches!(result, Err(AuthError::Forbidden(_)))),
                2 => assert!(matches!(result, Err(AuthError::BadRequest(_)))),
                _ => assert!(matches!(result, Err(AuthError::SessionCreationCancelled))),
            }
            assert_eq!(
                *observed.lock().unwrap(),
                if mode == 3 {
                    vec!["user"]
                } else {
                    vec!["user", "session"]
                }
            );
            let stored_user = ctx
                .database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored_user.two_factor_enabled(), mode != 3);
            let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
            assert_eq!(
                serde_json::to_value(sessions).unwrap(),
                serde_json::to_value(&before).unwrap()
            );
            assert!(
                ctx.database
                    .get_two_factor_by_user_id(&user.id)
                    .await
                    .unwrap()
                    .is_none()
            );
            let key = format!("2fa-otp-{}!{}", user.id, session.id);
            assert!(
                ctx.database
                    .get_verification_by_identifier(&key)
                    .await
                    .unwrap()
                    .is_none()
            );
            let retry = plugin.on_request(&request, &ctx).await.unwrap_err();
            assert!(
                matches!(retry, AuthError::BadRequest(ref message) if message == "OTP has expired")
            );
            assert_eq!(
                ctx.database
                    .get_user_by_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .two_factor_enabled(),
                mode != 3
            );
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn otp_delivery_keeps_owned_request_context_after_dropped_rejecting_observer_and_rotation()
     {
        use better_auth_core::{BackgroundTaskCompletion, BackgroundTaskHandler};
        use tokio::sync::oneshot;
        type Observations = Arc<std::sync::Mutex<Vec<(String, String, String, bool)>>>;
        struct Sender {
            entered: std::sync::Mutex<Option<oneshot::Sender<String>>>,
            release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
            finished: std::sync::Mutex<Option<oneshot::Sender<()>>>,
            observed: Observations,
        }
        impl Sender {
            fn record(&self, user: &UserView) {
                let request = better_auth_core::hooks::current_request_hook_context()
                    .expect("real delivery must retain initiating request context");
                self.observed.lock().unwrap().push((
                    request.path,
                    (*(request.headers)
                        .get("x-delivery-origin")
                        .expect("fixture contains the requested index"))
                    .clone(),
                    (*(request.query)
                        .get("delivery")
                        .expect("fixture contains the requested index"))
                    .clone(),
                    user.two_factor_enabled.unwrap_or(false),
                ));
            }
        }
        #[async_trait]
        impl SendTwoFactorOtp for Sender {
            async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
                self.record(user);
                drop(
                    self.entered
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send(otp.into()),
                );
                let release = self.release.lock().unwrap().take().unwrap();
                release.await.unwrap();
                self.record(user);
                _ = self.finished.lock().unwrap().take().unwrap().send(());
                Err(AuthError::forbidden(
                    "actual asynchronous delivery rejected",
                ))
            }
        }
        struct Observer;
        impl BackgroundTaskHandler for Observer {
            fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
                drop(completion);
                Err(AuthError::forbidden("actual application observer rejected"))
            }
        }
        let mut ctx = test_helpers::create_test_context().await;
        ctx.config = Arc::new((*ctx.config).clone().background_tasks(Arc::new(Observer)));
        let (entered, entry) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        let (finished, done) = oneshot::channel();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let plugin = Arc::new(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(Arc::new(Sender {
                entered: std::sync::Mutex::new(Some(entered)),
                release: std::sync::Mutex::new(Some(gate)),
                finished: std::sync::Mutex::new(Some(finished)),
                observed: Arc::clone(&observed),
            })),
            ..Default::default()
        }));
        let mut init = better_auth_core::AuthInitContext::new(
            Arc::clone(&ctx.config),
            Arc::clone(&ctx.database),
        );
        plugin.on_init(&mut init).await.unwrap();
        ctx.database = init.database_with_registered_transforms();
        let parts = init.into_parts();
        ctx.metadata = parts.metadata;
        ctx.extensions = parts.extensions;
        let user = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_name("Owned Delivery")
                .with_email("delivery-owner@fixture.test"),
        )
        .await;
        let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(1)).await;
        let ctx = Arc::new(ctx);
        let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/send-otp");
        drop(
            request.headers.insert(
                "cookie".into(),
                create_session_cookie(&session.token, &ctx.config)
                    .split(';')
                    .next()
                    .unwrap()
                    .into(),
            ),
        );
        drop(
            request
                .headers
                .insert("x-delivery-origin".into(), "original-sender".into()),
        );
        drop(
            request
                .query
                .insert("delivery".into(), "original-marker".into()),
        );
        request.body = Some(b"{}".to_vec());
        let running_ctx = Arc::clone(&ctx);
        let running_plugin = Arc::clone(&plugin);
        let running_request = request.clone();
        let mut running = tokio::spawn(async move {
            better_auth_core::with_request_hook_context(
                &running_request,
                running_plugin.on_request(&running_request, &running_ctx),
            )
            .await
        });
        let code = entry.await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), &mut running)
            .await
            .expect("configured response must not await held application delivery")
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        let identifier = format!("2fa-otp-{}!{}", user.id, session.id);
        let row = ctx
            .database
            .get_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.value(), format!("{code}:0"));
        assert!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .is_some()
        );
        request.path = "/two-factor/verify-otp".into();
        drop(
            request
                .headers
                .insert("x-delivery-origin".into(), "different-verifier".into()),
        );
        drop(
            request
                .query
                .insert("delivery".into(), "different-marker".into()),
        );
        request.body = Some(serde_json::to_vec(&serde_json::json!({"code":code})).unwrap());
        let verified = better_auth_core::with_request_hook_context(
            &request,
            plugin.on_request(&request, &ctx),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(verified.status, 200);
        assert!(
            ctx.database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .two_factor_enabled()
        );
        assert!(
            ctx.database
                .get_session(&session.token)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_verification_by_identifier(&identifier)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_two_factor_by_user_id(&user.id)
                .await
                .unwrap()
                .is_none()
        );
        let _ignored_send = release.send(());
        tokio::time::timeout(std::time::Duration::from_secs(1), done)
            .await
            .expect("owned delivery must finish after its actual release")
            .unwrap();
        assert_eq!(
            *observed.lock().unwrap(),
            vec![
                (
                    "/two-factor/send-otp".into(),
                    "original-sender".into(),
                    "original-marker".into(),
                    false
                );
                2
            ]
        );
    }
}
// LCOV_EXCL_STOP
