use super::*;
/// Callback used by the two-factor plugin to deliver a one-time password.
#[async_trait]
pub trait SendTwoFactorOtp: Send + Sync {
    /// Send a one-time password to the given user.
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()>;
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
#[derive(Clone, alibi_core::PluginConfig)]
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
