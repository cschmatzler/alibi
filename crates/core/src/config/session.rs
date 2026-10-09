use crate::SameSite;
use chrono::Duration;
use std::sync::Arc;
/// Session-specific configuration
#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct SessionConfig {
    /// No durable server session authority. Session records are instance-local
    /// in memory; no SQL session rows are read or written. Captured caches remain
    /// replayable until their embedded expiry or cache version/secret invalidation.
    pub stateless: bool,
    /// Stateless envelope renewal. Stateful deployments ignore this policy.
    pub cookie_refresh_cache: CookieRefreshCache,
    /// Shared secondary session backend for stateful deployments.
    pub secondary_storage: Option<Arc<dyn crate::store::CacheAdapter>>,
    /// Also persist session rows when a secondary backend is configured.
    pub store_in_database: bool,
    /// Retain ended database sessions for auditing; cache misses never fall back to them.
    pub preserve_in_database: bool,
    /// Additional fields accepted by session input and output policies.
    pub additional_fields: indexmap::IndexMap<String, crate::field_policy::FieldConfig>,
    /// Session expiration duration
    pub expires_in: Duration,

    /// How often to refresh the session expiry (as a Duration).
    ///
    /// A read refreshes when `expires_at - expires_in + update_age` is due.
    /// This uses the stored expiry, including application overrides, rather
    /// than the row's last update timestamp. `None` refreshes on every read
    /// unless refresh is disabled or deferred.
    pub update_age: Option<Duration>,

    /// If `true`, sessions are never automatically refreshed on access.
    pub disable_session_refresh: bool,

    /// Defer refresh and expired-row deletion during `GET` session reads.
    /// `POST /get-session` performs these writes when enabled; otherwise that
    /// method is rejected with 405. Expired browser cookies are still cleared.
    pub defer_session_refresh: bool,

    /// Session freshness window, defaulting to one day. `None` or zero skips
    /// the freshness restriction; a positive window checks creation time.
    pub fresh_age: Option<Duration>,

    /// Cookie name for session token
    pub cookie_name: String,

    /// Cookie settings
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: SameSite,

    /// Optional cookie-based session cache to avoid DB lookups.
    ///
    /// When enabled, session data is cached in a signed/encrypted cookie.
    /// `SessionManager` checks the cookie cache before hitting the database.
    pub cookie_cache: Option<CookieCacheConfig>,
}

impl std::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("secondary_storage", &self.secondary_storage.is_some())
            .field("store_in_database", &self.store_in_database)
            .field("preserve_in_database", &self.preserve_in_database)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// JWT expiration duration
    pub expires_in: Duration,

    /// JWT algorithm
    pub algorithm: String,

    /// Issuer claim
    pub issuer: Option<String>,

    /// Audience claim
    pub audience: Option<String>,
}

/// Configuration for cookie-based session caching.
///
/// When enabled, session data is stored in a signed or encrypted cookie so that
/// subsequent requests can skip the database lookup.
#[derive(Debug, Clone)]
pub struct CookieCacheConfig {
    /// Whether the cookie cache is active.
    pub enabled: bool,

    /// Maximum age in seconds before a fresh DB lookup is required.
    ///
    /// JavaScript falsy zero/NaN selects 300; other IEEE754 values are retained.
    ///
    /// Default: 5 minutes.
    pub max_age: f64,

    /// Strategy used to protect the cached cookie value.
    ///
    /// JWT uses the auth secret unless a locally managed JWT plugin signer is installed.
    pub strategy: CookieCacheStrategy,

    /// Literal or asynchronous application-owned version policy.
    pub version: Option<crate::session::cookie_cache::CookieCacheVersion>,
}

/// Stateless cache renewal policy, corresponding to `cookieCache.refreshCache`.
#[derive(Debug, Clone, Copy, Default)]
pub enum CookieRefreshCache {
    /// No cache renewal.
    #[default]
    Disabled,
    /// Renew when remaining envelope lifetime is below floor(maxAge * 0.2).
    Automatic,
    /// Renew below this remaining lifetime in seconds (JavaScript Number).
    UpdateAge(f64),
}

impl SessionConfig {
    /// Select cookie-only sessions, installing the pinned no-store defaults.
    /// Configure `cookie_cache` afterwards to override strategy, lifetime,
    /// version, or renewal. Existing database defaults are unchanged.
    #[must_use]
    pub fn stateless(mut self) -> Self {
        if !self.stateless {
            self.cookie_refresh_cache = CookieRefreshCache::Automatic;
        }
        self.stateless = true;
        if self.cookie_cache.is_none() {
            self.cookie_cache = Some(CookieCacheConfig {
                enabled: true,
                strategy: CookieCacheStrategy::Jwe,
                max_age: self.expires_in.num_seconds() as f64,
                ..CookieCacheConfig::default()
            });
        }
        self
    }

    /// Whether deployment has durable server session storage.
    #[must_use]
    pub fn has_server_session_store(&self) -> bool {
        !self.stateless
    }
}

/// Strategy for signing / encrypting the cookie cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    /// Base64url-encoded payload + HMAC-SHA256 signature.
    Compact,
    /// Standard JWT with HMAC signing.
    Jwt,
    /// JWE with direct-key AES-256-CBC/HMAC-SHA512 authenticated encryption.
    Jwe,
}

impl Default for CookieCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: 300.0,
            strategy: CookieCacheStrategy::Compact,
            version: None,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            stateless: false,
            cookie_refresh_cache: CookieRefreshCache::Disabled,
            secondary_storage: None,
            store_in_database: false,
            preserve_in_database: false,
            additional_fields: indexmap::IndexMap::default(),
            expires_in: Duration::hours(24 * 7),   // 7 days
            update_age: Some(Duration::hours(24)), // refresh once per day
            disable_session_refresh: false,
            defer_session_refresh: false,
            fresh_age: Some(Duration::days(1)),
            cookie_name: "better-auth.session_token".to_owned(),
            // Secure flag is derived from base_url scheme (HTTPS → true).
            // Default base_url is http://localhost:3000, so default is false.
            cookie_secure: false,
            cookie_http_only: true,
            cookie_same_site: SameSite::Lax,
            cookie_cache: None,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::hours(24), // 1 day
            algorithm: "HS256".to_owned(),
            issuer: None,
            audience: None,
        }
    }
}
