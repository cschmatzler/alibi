use super::{CustomSyntheticUserCallback, ExistingUserSignupCallback, UsernameConfig};
use alibi_core::utils::password::PasswordHasher;
use std::sync::Arc;
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct EmailPasswordConfig {
    /// Whether email/password authentication is enabled. Routes remain registered.
    pub enabled: bool,
    pub enable_signup: bool,
    /// Whether to enable the username schema, signup hooks, and endpoints.
    pub enable_username: bool,
    pub username: UsernameConfig,
    pub require_email_verification: bool,
    /// Minimum UTF-16 password length. Zero uses the default of 8.
    pub password_min_length: usize,
    /// Maximum UTF-16 password length. Zero uses the default of 128.
    pub password_max_length: usize,
    /// Whether to automatically sign in the user after sign-up (default: true).
    /// When false, sign-up returns the user but doesn't create a session.
    pub auto_sign_in: bool,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
    pub on_existing_user_signup: Option<Arc<ExistingUserSignupCallback>>,
    pub custom_synthetic_user: Option<Arc<CustomSyntheticUserCallback>>,
}

/// Password length limits in UTF-16 units, shared by every endpoint that
/// accepts a new password. The email/password plugin is always installed, so
/// its configuration is the single source; the defaults only apply to contexts
/// built without it.
pub(crate) fn password_length_limits(
    ctx: &alibi_core::AuthContext<impl alibi_core::AuthSchema>,
) -> (usize, usize) {
    ctx.extensions
        .get::<EmailPasswordConfig>()
        .map_or((8, 128), |config| {
            (config.effective_min_length(), config.effective_max_length())
        })
}

impl EmailPasswordConfig {
    pub(in crate::email_password) const fn effective_min_length(&self) -> usize {
        if self.password_min_length == 0 {
            8
        } else {
            self.password_min_length
        }
    }

    pub(in crate::email_password) const fn effective_max_length(&self) -> usize {
        if self.password_max_length == 0 {
            128
        } else {
            self.password_max_length
        }
    }
}

impl std::fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordConfig")
            .field("enabled", &self.enabled)
            .field("enable_signup", &self.enable_signup)
            .field("enable_username", &self.enable_username)
            .field("username", &self.username)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field("password_min_length", &self.password_min_length)
            .field("password_max_length", &self.password_max_length)
            .field("auto_sign_in", &self.auto_sign_in)
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .field(
                "on_existing_user_signup",
                &self.on_existing_user_signup.as_ref().map(|_| "custom"),
            )
            .field(
                "custom_synthetic_user",
                &self.custom_synthetic_user.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_signup: true,
            enable_username: true,
            username: UsernameConfig::default(),
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
            auto_sign_in: true,
            password_hasher: None,
            on_existing_user_signup: None,
            custom_synthetic_user: None,
        }
    }
}
