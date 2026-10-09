use crate::config::TrustedProvidersResolver;
/// Account-level configuration: linking, token encryption, sign-in behavior.
#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub additional_fields: crate::field_policy::FieldConfigs,
    /// Update OAuth tokens on every sign-in (default: true)
    pub update_account_on_sign_in: bool,
    /// Account linking settings
    pub account_linking: AccountLinkingConfig,
    /// Encrypt OAuth tokens at rest (default: false)
    pub encrypt_oauth_tokens: bool,
    /// Store account data in an account cookie for OAuth-backed access token flows.
    pub store_account_cookie: bool,
    /// Override the account cookie lifetime in seconds, including fractional
    /// and nonfinite values. Equivalent to the published ``account_data`` cookie's
    /// maxAge attribute; takes precedence over the integer advanced override.
    /// None inherits the session cache lifetime (or 300 seconds).
    pub cookie_max_age: Option<f64>,
    /// Where to persist OAuth state during the authorization flow. Automatic
    /// selects database state with a server store, cookie state without one.
    pub store_state_strategy: OAuthStateStrategy,
    /// Skip state-cookie verification during callback processing.
    ///
    /// This is security-sensitive and should stay disabled in normal use.
    pub skip_state_cookie_check: bool,
}

/// Settings that control how OAuth accounts are linked to existing users.
#[derive(Debug, Clone)]
pub struct AccountLinkingConfig {
    /// Enable account linking (default: true)
    pub enabled: bool,
    /// Providers trusted for linking even when their email is unverified.
    /// Empty does not bypass the provider email-verification requirement.
    pub trusted_providers: Vec<String>,
    /// Optional async policy replacing the static list at init and per request.
    pub trusted_providers_resolver: Option<std::sync::Arc<dyn TrustedProvidersResolver>>,
    /// Allow linking accounts with different emails (default: false) - SECURITY WARNING
    pub allow_different_emails: bool,
    /// Allow unlinking all accounts (default: false)
    pub allow_unlinking_all: bool,
    /// Disable implicit linking during sign-in; only explicit link-social may link.
    pub disable_implicit_linking: bool,
    /// Require the *existing local* account's email to be verified before a
    /// social account may be linked to it implicitly (default: true).
    pub require_local_email_verified: bool,
    /// Update user info when a new account is linked (default: false)
    pub update_user_info_on_link: bool,
}

/// Strategy for persisting OAuth state between the sign-in and callback steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OAuthStateStrategy {
    /// Select the deployment default during builder initialization. Initialized
    /// contexts never retain this variant. Low-level uninitialized contexts
    /// keep the historical database fallback for compatibility.
    #[default]
    Automatic,
    /// Persist state in an encrypted cookie.
    Cookie,
    /// Persist state in the verification store plus a signed state cookie.
    Database,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            additional_fields: crate::field_policy::FieldConfigs::new(),
            update_account_on_sign_in: true,
            account_linking: AccountLinkingConfig::default(),
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            cookie_max_age: None,
            store_state_strategy: OAuthStateStrategy::Automatic,
            skip_state_cookie_check: false,
        }
    }
}

impl Default for AccountLinkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: Vec::new(),
            trusted_providers_resolver: None,
            allow_different_emails: false,
            allow_unlinking_all: false,
            disable_implicit_linking: false,
            require_local_email_verified: true,
            update_user_info_on_link: false,
        }
    }
}
