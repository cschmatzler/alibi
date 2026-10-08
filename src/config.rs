//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use alibi_core::background_tasks::{BackgroundTaskCompletion, BackgroundTaskHandler};
pub use alibi_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, BaseUrlProtocol,
    CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride, CookieRefreshCache,
    CrossSubDomainConfig, DatabaseIdGenerator, DatabaseIdStrategy, DynamicBaseUrl, IpAddressConfig,
    JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig, TrustedOriginsResolver,
    TrustedProvidersResolver, TwoFactorDatabaseConfig, UserConfig, VerificationConfig, core_paths, extract_origin,
};
