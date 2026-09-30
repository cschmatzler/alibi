use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use validator::Validate;

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

use crate::plugins::helpers::{
    SessionIssueError, delete_session_cookie_headers, get_cookie, get_credential_password_hash,
    issue_user_session, issue_user_session_with_overrides,
};

use super::StatusResponse;

#[cfg(test)]
mod tests;

const TWO_FACTOR_COOKIE_SUFFIX: &str = "two_factor";
const TRUST_DEVICE_COOKIE_SUFFIX: &str = "trust_device";
const DONT_REMEMBER_COOKIE_SUFFIX: &str = "dont_remember";

const METADATA_ENABLED: &str = "two_factor.enabled";
const METADATA_OTP_ENABLED: &str = "two_factor.otp_enabled";
const METADATA_TWO_FACTOR_COOKIE_MAX_AGE: &str = "two_factor.two_factor_cookie_max_age";
const METADATA_TRUST_DEVICE_MAX_AGE: &str = "two_factor.trust_device_max_age";
const METADATA_TOTP_DISABLED: &str = "two_factor.totp_disabled";

const DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS: i64 = 10 * 60;
const DEFAULT_TRUST_DEVICE_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
const DEFAULT_TOTP_PERIOD_SECS: u64 = 30;
const DEFAULT_TOTP_DIGITS: usize = 6;
const DEFAULT_OTP_DIGITS: usize = 6;
const DEFAULT_OTP_LIFETIME_SECS: i64 = 3 * 60;
const DEFAULT_OTP_ATTEMPT_LIMIT: usize = 5;
const DEFAULT_BACKUP_CODE_COUNT: usize = 10;
const DEFAULT_BACKUP_CODE_LENGTH: usize = 10;

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
    #[config(default = AccountLockoutConfig::default())]
    pub account_lockout: AccountLockoutConfig,
    /// Override the issuer embedded in enrollment TOTP URIs.
    #[config(default = None)]
    pub issuer: Option<String>,
    /// Skip the enrollment verification step and enable 2FA immediately.
    #[config(default = false)]
    pub skip_verification_on_enable: bool,
    /// Maximum lifetime for the pending two-factor cookie used during sign-in.
    #[config(default = DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)]
    pub two_factor_cookie_max_age: i64,
    /// Maximum lifetime for the trusted-device cookie.
    #[config(default = DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)]
    pub trust_device_max_age: i64,
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
}

impl std::fmt::Debug for TwoFactorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoFactorConfig")
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
            .finish()
    }
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct EnableRequest {
    password: String,
    issuer: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct DisableRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GetTotpUriRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyTotpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyOtpRequest {
    code: String,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct GenerateBackupCodesRequest {
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct VerifyBackupCodeRequest {
    code: String,
    #[serde(rename = "disableSession")]
    disable_session: Option<bool>,
    #[serde(rename = "trustDevice")]
    trust_device: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EnableResponse {
    method: &'static str,
    #[serde(rename = "totpURI")]
    totp_uri: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TotpUriResponse {
    #[serde(rename = "totpURI")]
    totp_uri: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionTokenResponse<U: Serialize> {
    token: String,
    user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackupCodesResponse {
    status: bool,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TwoFactorRedirectResponse {
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
        user: S::User,
        session: Box<better_auth_core::wire::SessionView>,
        key: String,
    },
    Pending(PendingTwoFactorState<S>),
}

pub(crate) struct SignInTwoFactorRedirect {
    pub response: TwoFactorRedirectResponse,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) struct TrustedDeviceCheck {
    pub trusted: bool,
    pub set_cookie_headers: Vec<String>,
}

pub(crate) fn is_enabled(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> bool {
    ctx.get_metadata(METADATA_ENABLED)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub(crate) async fn inspect_trusted_device(
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
    let Some(signed_value) = verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)? else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

    let Some((token, trust_identifier)) = signed_value.split_once('!') else {
        return Ok(TrustedDeviceCheck {
            trusted: false,
            set_cookie_headers: vec![clear_header],
        });
    };

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

    let Some(verification) = ctx
        .database
        .get_verification_by_identifier(trust_identifier)
        .await?
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

pub(crate) async fn begin_sign_in_challenge(
    user: &impl AuthUser,
    remember_me: Option<bool>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInTwoFactorRedirect> {
    let identifier = format!("2fa-{}", uuid::Uuid::new_v4());
    let expires_at = Utc::now() + Duration::seconds(two_factor_cookie_max_age(ctx));
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: format!("2fa-attempts-{identifier}"),
            value: "0".to_owned(),
            expires_at,
        })
        .await?;

    let mut headers = delete_session_cookie_headers(&ctx.config);
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
        .and_then(|value| value.as_bool())
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
        .and_then(|value| value.as_bool())
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

impl TwoFactorPlugin {
    /// Install a custom OTP sender.
    pub fn custom_send_otp(mut self, sender: Arc<dyn SendTwoFactorOtp>) -> Self {
        self.config.send_otp = Some(sender);
        self
    }

    /// Generate a current TOTP from an application-owned UTF-8 secret.
    ///
    /// This corresponds to `auth.api.generateTOTP`; it has no public HTTP route.
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
    pub async fn view_backup_codes<S: better_auth_core::AuthSchema>(
        &self,
        user_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Vec<String>> {
        view_backup_codes_core(user_id, ctx).await
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
        ) -> better_auth_core::AuthResult<()> {
            ctx.register_user_create_transform(|mut input| {
                _ = input.two_factor_enabled.get_or_insert(false);
                Ok(input)
            });
            ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
            ctx.set_metadata(METADATA_TOTP_DISABLED, serde_json::Value::Bool(self.config.totp_disabled));
            ctx.set_metadata(
                METADATA_OTP_ENABLED,
                serde_json::Value::Bool(self.config.send_otp.is_some()),
            );
            ctx.set_metadata(
                METADATA_TWO_FACTOR_COOKIE_MAX_AGE,
                serde_json::Value::Number(self.config.two_factor_cookie_max_age.into()),
            );
            ctx.set_metadata(
                METADATA_TRUST_DEVICE_MAX_AGE,
                serde_json::Value::Number(self.config.trust_device_max_age.into()),
            );
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
        let (user, session) = ctx.require_session(req).await?;
        let body: EnableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) =
            match enable_core(&body, &user, &session, &self.config, ctx).await {
                Ok(result) => result,
                Err(AuthError::SessionCreationCancelled) => return Ok(AuthResponse::new(500)),
                Err(error) => return Err(error),
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
        let (user, session) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated | AuthError::SessionNotFound => AuthError::Upstream {
                    status: 401,
                    code: "UNAUTHORIZED",
                    message: "Unauthorized",
                },
                other => other,
            })?;
        let body: DisableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (response, set_cookie_headers) = disable_core(&body, &user, &session, req, ctx).await?;
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
        let (user, _session) = ctx.require_session(req).await?;
        let body: GetTotpUriRequest = match better_auth_core::validate_request_body(req) {
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
        let response = send_otp_core(req, &self.config, ctx).await?;
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
                Err(error) => return verification_error_response(error, ctx),
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
        let (user, _session) = ctx.require_session(req).await?;
        let body: GenerateBackupCodesRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let response = generate_backup_codes_core(&body, &user, ctx).await?;
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

async fn enable_core(
    body: &EnableRequest,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(EnableResponse, Vec<String>)> {
    verify_user_password(ctx, user, &body.password).await?;
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "TOTP is not available",
        });
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
        });
    }

    let secret = generate_secret();
    let encrypted_secret = encrypt_value(&ctx.config.secret, &secret)?;
    let backup_codes = generate_backup_codes();
    let encrypted_backup_codes =
        encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;

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
        let _ = ctx
            .database
            .update_two_factor(
                existing.id().as_ref(),
                UpdateTwoFactor {
                    secret: Some(encrypted_secret),
                    backup_codes: Some(encrypted_backup_codes),
                    verified: Some(config.skip_verification_on_enable),
                },
            )
            .await?;
    } else {
        _ = ctx
            .database
            .create_two_factor(CreateTwoFactor {
                user_id: user.id().to_string(),
                secret: encrypted_secret,
                backup_codes: encrypted_backup_codes,
                verified: Some(config.skip_verification_on_enable),
                ..Default::default()
            })
            .await?;
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
        EnableResponse {
            method: "totp",
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
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(ctx, user, &body.password).await?;

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

    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)?
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

    if let Some(trust_cookie) = read_signed_cookie(req, TRUST_DEVICE_COOKIE_SUFFIX, ctx)?
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
    verify_user_password(ctx, user, &body.password).await?;
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
    let two_factor = load_two_factor_record(state.user(), ctx).await?;
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
                ctx,
            )
            .await?;
            mark_factor_verified(&two_factor, ctx).await?;
            Ok(result)
        }
        ResolvedTwoFactorState::Pending(pending) => {
            mark_factor_verified(&two_factor, ctx).await?;
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
        }
    }
}

async fn mark_factor_verified(
    two_factor: &TwoFactor,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if two_factor.verified() != Some(true) {
        let _ = ctx
            .database
            .update_two_factor(
                two_factor.id().as_ref(),
                UpdateTwoFactor {
                    verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}

async fn send_otp_core(
    req: &AuthRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let sender = config
        .send_otp
        .as_ref()
        .ok_or_else(|| AuthError::bad_request("otp isn't configured"))?;
    let state = resolve_two_factor_state(req, ctx).await?;

    let otp = format!(
        "{:0width$}",
        rand::thread_rng().gen_range(0..10u32.pow(DEFAULT_OTP_DIGITS as u32)),
        width = DEFAULT_OTP_DIGITS
    );
    let hashed_otp = better_auth_core::hash_password(None, &otp).await?;
    let identifier = otp_verification_identifier(state.key());

    if let Some(existing) = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
    {
        ctx.database
            .delete_verification(existing.id().as_ref())
            .await?;
    }

    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier,
            value: format!("{}:0", hashed_otp),
            expires_at: Utc::now() + Duration::seconds(DEFAULT_OTP_LIFETIME_SECS),
        })
        .await?;

    if let Err(error) = sender.send(&ctx.user_view(state.user()), &otp).await {
        tracing::warn!(error = %error, "Failed to send two-factor OTP");
    }

    Ok(StatusResponse { status: true })
}

async fn verify_otp_core(
    req: &AuthRequest,
    body: &VerifyOtpRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
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
        return Err(AuthError::bad_request("OTP has expired"));
    };

    let Some((stored_hash, counter)) = verification.value().rsplit_once(':') else {
        return Err(AuthError::internal("Malformed OTP verification payload"));
    };

    let attempts = counter.parse::<usize>().map_err(|error| {
        AuthError::internal(format!("Malformed OTP attempt counter: {}", error))
    })?;
    if attempts >= DEFAULT_OTP_ATTEMPT_LIMIT {
        return Err(AuthError::bad_request(
            "Too many attempts. Please request a new code.",
        ));
    }

    let is_valid = match better_auth_core::verify_password(None, &body.code, stored_hash).await {
        Ok(()) => true,
        Err(AuthError::InvalidCredentials) => false,
        Err(error) => return Err(error),
    };

    if !is_valid {
        let next_value = format!("{}:{}", stored_hash, attempts + 1);
        let expires_at = verification.expires_at();
        let verification_identifier = verification.identifier().to_string();
        _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: verification_identifier,
                value: next_value,
                expires_at,
            })
            .await?;
        if let Some(factor) = &factor {
            record_account_failure(config, factor, ctx).await?;
        }
        return Err(AuthError::authentication_failed("Invalid code"));
    }

    if let Some(factor) = &factor {
        reset_account_failures(config, factor, ctx).await?;
    }

    match state {
        ResolvedTwoFactorState::Session { user, session, .. } => {
            verify_existing_session_factor(user, *session, true, ctx).await
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(pending, req, body.trust_device.unwrap_or(false), true, ctx)
                .await
        }
    }
}

async fn generate_backup_codes_core(
    body: &GenerateBackupCodesRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<BackupCodesResponse> {
    if !user.two_factor_enabled() {
        return Err(AuthError::bad_request("Two factor isn't enabled"));
    }

    verify_user_password(ctx, user, &body.password).await?;
    let _ = load_two_factor_record(user, ctx).await?;

    let backup_codes = generate_backup_codes();
    let encrypted = encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;
    _ = ctx
        .database
        .update_two_factor_backup_codes(user.id().as_ref(), &encrypted)
        .await?;

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
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
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

    let codes = match decrypt_backup_codes(two_factor.backup_codes(), &ctx.config.secret) {
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

    let encrypted = encrypt_value(&ctx.config.secret, &serde_json::to_string(&backup_codes)?)?;
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
                    SessionTokenResponse {
                        token: session.token().to_string(),
                        user: ctx.user_view(&user),
                    },
                    Vec::new(),
                ))
            } else {
                verify_existing_session_factor(user, *session, false, ctx).await
            }
        }
        ResolvedTwoFactorState::Pending(pending) => {
            finalize_pending_two_factor(
                pending,
                req,
                body.trust_device.unwrap_or(false),
                !body.disable_session.unwrap_or(false),
                ctx,
            )
            .await
        }
    }
}

async fn view_backup_codes_core<S: better_auth_core::AuthSchema>(
    user_id: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Vec<String>> {
    let two_factor = ctx
        .database
        .get_two_factor_by_user_id(user_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Backup codes aren't enabled"))?;
    let Some(backup_codes) = decrypt_backup_codes(two_factor.backup_codes(), &ctx.config.secret)?
    else {
        return Err(AuthError::bad_request("Invalid backup code"));
    };
    Ok(backup_codes)
}

async fn resolve_two_factor_state<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<ResolvedTwoFactorState<S>> {
    if let Ok((user, session)) = ctx.require_session(req).await {
        let key = format!("{}!{}", user.id(), session.id());
        return Ok(ResolvedTwoFactorState::Session {
            user,
            session: Box::new(session),
            key,
        });
    }

    let identifier = read_signed_cookie(req, TWO_FACTOR_COOKIE_SUFFIX, ctx)?
        .filter(|identifier| !identifier.is_empty())
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    if verification.expires_at() <= Utc::now() {
        ctx.database
            .delete_verification(verification.id().as_ref())
            .await?;
        return Err(AuthError::authentication_failed(
            "Invalid two factor cookie",
        ));
    }

    let user = ctx
        .database
        .get_user_by_id(verification.value())
        .await?
        .ok_or_else(|| AuthError::authentication_failed("Invalid two factor cookie"))?;
    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)?
        .is_some_and(|value| !value.is_empty());

    Ok(ResolvedTwoFactorState::Pending(PendingTwoFactorState {
        user,
        verification,
        key: identifier,
        dont_remember,
    }))
}

struct FactorAttempt {
    identifier: String,
    count: f64,
    expires_at: chrono::DateTime<Utc>,
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
            return u64::from_str_radix(value, radix)
                .map(|count| count as f64)
                .unwrap_or(f64::NAN);
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
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: attempt.identifier.clone(),
                value: (attempt.count + if failed { 1.0 } else { 0.0 }).to_string(),
                expires_at: attempt.expires_at,
            })
            .await;
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
        let _ = ctx
            .database
            .clear_expired_two_factor_lock(factor.id().as_ref(), now)
            .await?;
    }
    Ok(())
}

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
        .and_then(|factor| factor.failed_verification_count())
        .unwrap_or(0.0);
    if count >= config.account_lockout.max_failed_attempts {
        let milliseconds =
            Utc::now().timestamp_millis() as f64 + config.account_lockout.duration_seconds * 1000.0;
        // JavaScript Date TimeClip rejects nonfinite/out-of-range values and
        // truncates toward zero; nullable/zero settings remain supported.
        if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
            return Err(AuthError::internal("Invalid two-factor lock date"));
        }
        let until = chrono::DateTime::from_timestamp_millis(milliseconds.trunc() as i64)
            .ok_or_else(|| AuthError::internal("Invalid two-factor lock date"))?;
        let _ = ctx
            .database
            .set_two_factor_lock_if_count_at_least(
                factor.id().as_ref(),
                config.account_lockout.max_failed_attempts,
                until,
            )
            .await?;
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
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(SessionTokenResponse<UserView>, Vec<String>)> {
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
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(session.token()).await?;
        return Ok((
            SessionTokenResponse {
                token: session.token().to_string(),
                // TS keeps the verify response on the pre-update snapshot even
                // though the re-issued session already observes 2FA as enabled.
                user: ctx.user_view(&user),
            },
            vec![create_session_cookie(issued.session.token(), &ctx.config)],
        ));
    }

    Ok((
        SessionTokenResponse {
            token: session.token().to_string(),
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
    if !consumed.is_some_and(|verification| verification.value() == pending.user.id().as_ref()) {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TWO_FACTOR_COOKIE",
            message: "Invalid two factor cookie",
        });
    }
    let meta = RequestMeta::from_request(req);
    let issued = issue_user_session(
        ctx,
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
        error => error.into_auth_error(),
    })?;
    // Upstream createSession(user, dontRememberMe) uses a one-day lifetime.
    if pending.dont_remember {
        ctx.database
            .update_session_expiry(issued.session.token(), Utc::now() + Duration::days(1))
            .await?;
    }

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
            token: issued.session.token().to_string(),
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

fn require_totp_enabled(config: &TwoFactorConfig) -> AuthResult<()> {
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "TOTP_NOT_CONFIGURED",
            message: "totp isn't configured",
        });
    }
    Ok(())
}

fn totp_digits(config: &TwoFactorConfig) -> usize {
    if config.totp_digits == 0 {
        DEFAULT_TOTP_DIGITS
    } else {
        config.totp_digits
    }
}

fn totp_period(config: &TwoFactorConfig) -> u64 {
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
    password: &str,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    match better_auth_core::verify_password(None, password, &stored_hash).await {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

fn generate_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn generate_backup_codes() -> Vec<String> {
    (0..DEFAULT_BACKUP_CODE_COUNT)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(DEFAULT_BACKUP_CODE_LENGTH)
                .map(char::from)
                .collect::<String>()
        })
        .map(|code| format!("{}-{}", &code[..5], &code[5..]))
        .collect()
}

fn decrypt_backup_codes(backup_codes: &str, secret: &str) -> AuthResult<Option<Vec<String>>> {
    let decrypted = decrypt_value(secret, backup_codes)?;
    serde_json::from_str(&decrypted)
        .ok()
        .map_or(Ok(None), |codes| Ok(Some(codes)))
}

fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{}", key)
}

fn two_factor_cookie_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
        .and_then(|value| value.as_i64())
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
    let value = format!("{}!{}", token, identifier);
    let expires_at = Utc::now() + Duration::seconds(trust_device_max_age(ctx));
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;
    create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

fn create_signed_cookie_header(
    secret: &str,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<i64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value)?;
    Ok(create_session_like_cookie(
        &cookie_name,
        &signed_value,
        max_age_seconds,
        config,
    ))
}

fn read_signed_cookie<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<String>> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(None);
    };
    verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)
}

fn sign_cookie_value(secret: &str, value: &str) -> AuthResult<String> {
    Ok(better_auth_core::utils::cookie_utils::sign_cookie_value(
        value, secret,
    ))
}

fn verify_signed_cookie_value(secret: &str, signed_value: &str) -> AuthResult<Option<String>> {
    Ok(better_auth_core::utils::cookie_utils::verify_cookie_value(
        signed_value,
        secret,
    ))
}

fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn derive_encryption_key(secret: &str) -> AuthResult<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut okm).map_err(|error| {
        AuthError::internal(format!("Failed to derive encryption key: {}", error))
    })?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

fn encrypt_value(secret: &str, plaintext: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|error| {
            AuthError::internal(format!("Failed to encrypt two-factor data: {}", error))
        })?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(output))
}

fn decrypt_value(secret: &str, encrypted: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let bytes = URL_SAFE_NO_PAD.decode(encrypted).map_err(|error| {
        AuthError::internal(format!(
            "Failed to decode encrypted two-factor data: {}",
            error
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
            AuthError::internal(format!("Failed to decrypt two-factor data: {}", error))
        })?;
    String::from_utf8(plaintext).map_err(|error| {
        AuthError::internal(format!(
            "Two-factor plaintext is not valid UTF-8: {}",
            error
        ))
    })
}

impl<S: better_auth_core::AuthSchema> ResolvedTwoFactorState<S> {
    fn user(&self) -> &S::User {
        match self {
            Self::Session { user, .. } => user,
            Self::Pending(pending) => &pending.user,
        }
    }

    fn key(&self) -> &str {
        match self {
            Self::Session { key, .. } => key,
            Self::Pending(pending) => &pending.key,
        }
    }
}
