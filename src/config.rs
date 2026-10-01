//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use better_auth_core::background_tasks::{BackgroundTaskCompletion, BackgroundTaskHandler};

pub use better_auth_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, CookieAttributes,
    CookieCacheConfig, CookieCacheStrategy, CookieOverride, CrossSubDomainConfig, IpAddressConfig,
    JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig, VerificationConfig,
    core_paths, extract_origin,
};
