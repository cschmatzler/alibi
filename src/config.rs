//! Configuration types beyond the root `AuthConfig` entrypoint.

pub use alibi_core::background_tasks::{BackgroundTaskCompletion, BackgroundTaskHandler};
pub use alibi_core::config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, BaseUrlProtocol,
    CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride, CookieRefreshCache,
    CrossSubDomainConfig, DynamicBaseUrl, IpAddressConfig, JwtConfig, OAuthStateStrategy,
    PasswordConfig, SameSite, SessionConfig, TrustedOriginsResolver, TrustedProvidersResolver,
    VerificationConfig, core_paths, extract_origin,
};
