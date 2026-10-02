mod client_ip;

/// Well-known core route paths.
///
/// These constants are the single source of truth for route paths used by both
/// the core request dispatcher (`handle_core_request`) and framework-specific
/// routers (e.g. Axum) so that path strings are never duplicated.
pub mod core_paths {
    pub const OK: &str = "/ok";
    pub const ERROR: &str = "/error";
    pub const HEALTH: &str = "/health";
    pub const OPENAPI_SPEC: &str = "/__test/openapi.json";
    pub const UPDATE_USER: &str = "/update-user";
    pub const DELETE_USER: &str = "/delete-user";
    pub const CHANGE_EMAIL: &str = "/change-email";
    pub const DELETE_USER_CALLBACK: &str = "/delete-user/callback";

    fn valid_error_code(input: &str) -> bool {
        !input.is_empty()
            && input
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '\'')
    }

    fn is_preserved_entity(input: &str) -> bool {
        input.starts_with("amp;")
            || input.starts_with("lt;")
            || input.starts_with("gt;")
            || input.starts_with("quot;")
            || input.starts_with("#39;")
            || input.strip_prefix("#x").is_some_and(|hex| {
                let Some(hex) = hex.strip_suffix(';') else {
                    return false;
                };
                !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
            })
            || input.strip_prefix('#').is_some_and(|digits| {
                let Some(digits) = digits.strip_suffix(';') else {
                    return false;
                };
                !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
            })
    }

    fn sanitize_html(input: &str) -> String {
        let mut out = String::with_capacity(input.len());

        for (idx, ch) in input.char_indices() {
            match ch {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                '&' => {
                    let rest = input.get(idx + ch.len_utf8()..).unwrap_or_default();
                    if is_preserved_entity(rest) {
                        out.push('&');
                    } else {
                        out.push_str("&amp;");
                    }
                }
                _ => out.push(ch),
            }
        }

        out
    }

    fn default_error_description(code: &str) -> String {
        format!(
            "We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find <a href='https://better-auth.com/docs/reference/errors/{code}' target='_blank' rel=\"noopener noreferrer\" style='color: var(--foreground); text-decoration: underline;'>more information about the error</a>."
        )
    }

    /// Build the HTML error page returned by `GET /error`.
    ///
    /// Matches the current TS better-auth error page renderer.
    #[must_use]
    pub fn error_page_html(error_code: &str) -> String {
        error_page_html_with_description(error_code, None)
    }

    /// Build the HTML error page returned by `GET /error`, optionally
    /// overriding the default description text.
    pub fn error_page_html_with_description(
        error_code: &str,
        error_description: Option<&str>,
    ) -> String {
        let safe_code = if valid_error_code(error_code) {
            error_code
        } else {
            "UNKNOWN"
        };
        let description =
            error_description.map_or_else(|| default_error_description(safe_code), sanitize_html);
        let ask_ai_query = format!("What%20does%20the%20error%20code%20{safe_code}%20mean%3F");

        format!(
            include_str!("error-page.html"),
            safe_code = safe_code,
            description = description,
            ask_ai_query = ask_ai_query,
        )
    }
}

#[cfg(test)]
mod tests;

use crate::email::EmailProvider;
use crate::error::AuthError;
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;

/// Main configuration for `BetterAuth`
#[derive(Clone)]
pub struct AuthConfig {
    /// Secret key for signing tokens and sessions
    pub secret: String,

    /// Application name, used for cookie prefixes, email templates, etc.
    ///
    /// Defaults to `"Better Auth"`.
    pub app_name: String,

    /// Base URL for the authentication service (e.g. `"http://localhost:3000"`).
    pub base_url: String,

    /// Base path where the auth routes are mounted.
    ///
    /// All routes handled by `BetterAuth` will be prefixed with this path.
    /// For example, with the default `"/api/auth"`, the sign-in route becomes
    /// `"/api/auth/sign-in/email"`.
    ///
    /// Defaults to `"/api/auth"`.
    pub base_path: String,

    /// Origins that are trusted for CSRF and other cross-origin checks.
    ///
    /// Supports glob patterns (e.g. `"https://*.example.com"`).
    /// These are shared across all middleware that needs origin validation
    /// (CSRF, CORS, etc.).
    pub trusted_origins: Vec<String>,

    /// Paths that should be disabled (skipped) by the router.
    ///
    /// Any request whose path matches an entry in this list will receive
    /// a 404 response, even if a handler is registered for it.
    pub disabled_paths: Vec<String>,
    /// Session configuration
    pub session: SessionConfig,

    /// Verification storage lifecycle settings.
    pub verification: VerificationConfig,

    /// JWT configuration
    pub jwt: JwtConfig,

    /// Password configuration
    pub password: PasswordConfig,

    /// Account configuration (linking, token encryption, etc.)
    pub account: AccountConfig,

    /// Email provider for sending emails (verification, password reset, etc.)
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    /// Observe already running deferred operations. Ignoring their completion
    /// does not cancel them; applications may retain completions for shutdown.
    pub background_tasks: Option<Arc<dyn crate::BackgroundTaskHandler>>,

    /// Validate fresh identity data before its creation hooks or provider
    /// account/session writes. Returning non-provider sign-ins are unchanged.
    pub user_validation: Option<Arc<dyn crate::user_validation::UserInfoValidator>>,

    /// Advanced configuration options
    pub advanced: AdvancedConfig,
}

/// Account-level configuration: linking, token encryption, sign-in behavior.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct AccountConfig {
    /// Update OAuth tokens on every sign-in (default: true)
    pub update_account_on_sign_in: bool,
    /// Account linking settings
    pub account_linking: AccountLinkingConfig,
    /// Encrypt OAuth tokens at rest (default: false)
    pub encrypt_oauth_tokens: bool,
    /// Store account data in an account cookie for OAuth-backed access token flows.
    pub store_account_cookie: bool,
    /// Where to persist OAuth state during the authorization flow.
    pub store_state_strategy: OAuthStateStrategy,
    /// Skip state-cookie verification during callback processing.
    ///
    /// This is security-sensitive and should stay disabled in normal use.
    pub skip_state_cookie_check: bool,
}

/// Settings that control how OAuth accounts are linked to existing users.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct AccountLinkingConfig {
    /// Enable account linking (default: true)
    pub enabled: bool,
    /// Trusted providers that can auto-link (default: empty = all trusted)
    pub trusted_providers: Vec<String>,
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
    /// Persist state in an encrypted cookie.
    #[default]
    Cookie,
    /// Persist state in the verification store plus a signed state cookie.
    Database,
}

/// Session-specific configuration
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct SessionConfig {
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

/// Controls cleanup performed when a verification record is read.
#[derive(Debug, Clone, Default)]
pub struct VerificationConfig {
    /// Keep globally expired verification rows during lookup. Default: false.
    /// An atomic consume still invalidates an expired proof it selects.
    pub disable_cleanup: bool,
}

/// Password validation configuration. Built-in hashing uses pinned scrypt parameters.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct PasswordConfig {
    /// Minimum password length
    pub min_length: usize,

    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
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
    /// The stateful HTTP implementation currently supports Compact. Enabling
    /// Jwt or Jwe returns a configuration error during builder initialization.
    pub strategy: CookieCacheStrategy,

    /// Literal or asynchronous application-owned version policy.
    pub version: Option<crate::cache::CookieCacheVersion>,
}

/// Strategy for signing / encrypting the cookie cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    /// Base64url-encoded payload + HMAC-SHA256 signature.
    Compact,
    /// Standard JWT with HMAC signing.
    Jwt,
    /// JWE with AES-256-GCM encryption.
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

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            update_account_on_sign_in: true,
            account_linking: AccountLinkingConfig::default(),
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            store_state_strategy: OAuthStateStrategy::Database,
            skip_state_cookie_check: false,
        }
    }
}

impl Default for AccountLinkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: Vec::new(),
            allow_different_emails: false,
            allow_unlinking_all: false,
            disable_implicit_linking: false,
            require_local_email_verified: true,
            update_user_info_on_link: false,
        }
    }
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => f.write_str("Strict"),
            Self::Lax => f.write_str("Lax"),
            Self::None => f.write_str("None"),
        }
    }
}

// ── Advanced configuration ──────────────────────────────────────────────

/// Advanced configuration options (mirrors TS `advanced` block).
#[derive(Debug, Clone, Default)]
pub struct AdvancedConfig {
    /// IP address extraction configuration.
    pub ip_address: IpAddressConfig,

    /// Explicit CSRF override. `None` preserves the pinned compatibility behavior
    /// where disabling all origin checks also disables first-login CSRF checks.
    pub disable_csrf_check: Option<bool>,

    /// If `true`, callback / redirect target origin validation is skipped.
    ///
    /// This mirrors Better Auth TS `advanced.disableOriginCheck`.
    /// Request-origin validation is also skipped. First-login Fetch Metadata
    /// checks remain enabled when `disable_csrf_check` is explicitly `Some(false)`.
    pub disable_origin_check: bool,

    /// Skip origin validation for a literal path and its descendants. This does
    /// not disable first-login cross-site navigation protection.
    pub disable_origin_check_paths: Vec<String>,

    /// Admit trailing slashes while resolving the original registered endpoint.
    pub skip_trailing_slashes: bool,

    /// Cross-subdomain cookie sharing configuration.
    pub cross_sub_domain_cookies: Option<CrossSubDomainConfig>,

    /// Per-cookie-name overrides (name, attributes, prefix).
    ///
    /// Keys are the *logical* cookie names (e.g. `"session_token"`,
    /// `"csrf_token"`). Values specify the attributes to override.
    pub cookies: HashMap<String, CookieOverride>,

    /// Default cookie attributes applied to *every* cookie the library sets
    /// (individual overrides in `cookies` take precedence).
    pub default_cookie_attributes: CookieAttributes,

    /// Optional prefix prepended to every cookie name (e.g. `"myapp"` →
    /// `"myapp.session_token"`).
    pub cookie_prefix: Option<String>,

    /// Database-related advanced options.
    pub database: AdvancedDatabaseConfig,

    /// List of header names the framework trusts for extracting the
    /// client's real IP when behind a proxy (e.g. `X-Forwarded-For`).
    pub trusted_proxy_headers: Vec<String>,
}

/// IP-address extraction configuration.
#[derive(Debug, Clone)]
pub struct IpAddressConfig {
    /// Ordered list of headers to check for the client IP.
    /// Defaults to `["x-forwarded-for"]`. Header names are case insensitive.
    pub headers: Vec<String>,

    /// IP addresses or CIDRs removed from the right of a forwarded chain.
    /// Invalid entries are ignored. Without valid entries, only a single
    /// address is admitted. Deployments must prevent clients bypassing the
    /// proxy and supplying their own trusted forwarding headers.
    pub trusted_proxies: Vec<String>,

    /// IPv6 grouping prefix; defaults to 64. Fractional values are floored,
    /// negative values become zero, and values at least 128 or NaN preserve
    /// the full address. IPv4-mapped addresses use IPv4 grouping.
    pub ipv6_subnet: f64,

    /// Fall back to localhost when no configured header resolves an address.
    /// Defaults to true for NODE_ENV dev/development/test or a truthy TEST
    /// environment flag. Applications may configure this explicitly.
    pub localhost_fallback: bool,

    /// If `true`, IP tracking is entirely disabled (no IP stored in sessions).
    pub disable_ip_tracking: bool,
}

/// Configuration for sharing cookies across sub-domains.
#[derive(Debug, Clone)]
pub struct CrossSubDomainConfig {
    /// The parent domain (e.g. `".example.com"`).
    pub domain: String,
}

/// Overridable cookie attributes.
#[derive(Debug, Clone, Default)]
pub struct CookieAttributes {
    /// Override `Secure` flag.
    pub secure: Option<bool>,
    /// Override `HttpOnly` flag.
    pub http_only: Option<bool>,
    /// Override `SameSite` policy.
    pub same_site: Option<SameSite>,
    /// Override `Path`.
    pub path: Option<String>,
    /// Override `Max-Age` (seconds).
    pub max_age: Option<i64>,
    /// Override cookie `Domain`.
    pub domain: Option<String>,
}

/// Per-cookie override entry.
#[derive(Debug, Clone, Default)]
pub struct CookieOverride {
    /// Custom name to use instead of the logical name.
    pub name: Option<String>,
    /// Attribute overrides for this cookie.
    pub attributes: CookieAttributes,
}

/// Database-related advanced options.
#[derive(Debug, Clone)]
pub struct AdvancedDatabaseConfig {
    /// Default `LIMIT` for "find many" queries.
    pub default_find_many_limit: usize,

    /// If `true`, auto-generated IDs will be numeric (auto-increment style)
    /// rather than UUIDs.
    pub use_number_id: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            app_name: "Better Auth".to_owned(),
            base_url: "http://localhost:3000".to_owned(),
            base_path: "/api/auth".to_owned(),
            trusted_origins: Vec::new(),
            disabled_paths: Vec::new(),
            session: SessionConfig::default(),
            verification: VerificationConfig::default(),
            jwt: JwtConfig::default(),
            password: PasswordConfig::default(),
            account: AccountConfig::default(),
            email_provider: None,
            background_tasks: None,
            user_validation: None,
            advanced: AdvancedConfig::default(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
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

impl Default for IpAddressConfig {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".to_owned()],
            trusted_proxies: Vec::new(),
            ipv6_subnet: 64.0,
            localhost_fallback: matches!(
                std::env::var("NODE_ENV").as_deref(),
                Ok("dev" | "development" | "test")
            ) || std::env::var("TEST")
                .is_ok_and(|value| !matches!(value.as_str(), "" | "false")),
            disable_ip_tracking: false,
        }
    }
}

impl Default for AdvancedDatabaseConfig {
    fn default() -> Self {
        Self {
            default_find_many_limit: 100,
            use_number_id: false,
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

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: false,
            require_numbers: false,
            require_special: false,
        }
    }
}

impl AuthConfig {
    /// Integrate deferred task completions with the application executor.
    #[must_use]
    pub fn background_tasks(mut self, handler: Arc<dyn crate::BackgroundTaskHandler>) -> Self {
        self.background_tasks = Some(handler);
        self
    }

    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Set the application name.
    #[must_use]
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Set the base URL (e.g. `"https://myapp.com"`).
    ///
    /// Also updates `session.cookie_secure` to match the URL scheme:
    /// HTTPS URLs set `Secure=true`, HTTP URLs set `Secure=false`.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self.session.cookie_secure = self.base_url.starts_with("https://");
        self
    }

    #[must_use]
    pub fn account(mut self, account: AccountConfig) -> Self {
        self.account = account;
        self
    }

    /// Set the base path where auth routes are mounted.
    #[must_use]
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    /// Add a trusted origin. Supports glob patterns (e.g. `"https://*.example.com"`).
    #[must_use]
    pub fn trusted_origin(mut self, origin: impl Into<String>) -> Self {
        self.trusted_origins.push(origin.into());
        self
    }

    /// Set all trusted origins at once.
    #[must_use]
    pub fn trusted_origins(mut self, origins: Vec<String>) -> Self {
        self.trusted_origins = origins;
        self
    }

    /// Add a path to the disabled paths list.
    #[must_use]
    pub fn disabled_path(mut self, path: impl Into<String>) -> Self {
        self.disabled_paths.push(path.into());
        self
    }

    /// Set all disabled paths at once.
    #[must_use]
    pub fn disabled_paths(mut self, paths: Vec<String>) -> Self {
        self.disabled_paths = paths;
        self
    }

    /// Set the session expiration duration.
    #[must_use]
    pub const fn session_expires_in(mut self, duration: Duration) -> Self {
        self.session.expires_in = duration;
        self
    }

    #[must_use]
    pub const fn session_update_age(mut self, duration: Duration) -> Self {
        self.session.update_age = Some(duration);
        self
    }

    #[must_use]
    pub const fn disable_session_refresh(mut self, disabled: bool) -> Self {
        self.session.disable_session_refresh = disabled;
        self
    }

    #[must_use]
    pub const fn session_fresh_age(mut self, duration: Duration) -> Self {
        self.session.fresh_age = Some(duration);
        self
    }

    /// Set the cookie cache configuration for sessions.
    #[must_use]
    pub fn session_cookie_cache(mut self, config: CookieCacheConfig) -> Self {
        self.session.cookie_cache = Some(config);
        self
    }

    /// Set the JWT expiration duration.
    #[must_use]
    pub const fn jwt_expires_in(mut self, duration: Duration) -> Self {
        self.jwt.expires_in = duration;
        self
    }

    /// Set the minimum password length.
    #[must_use]
    pub const fn password_min_length(mut self, length: usize) -> Self {
        self.password.min_length = length;
        self
    }

    #[must_use]
    pub fn advanced(mut self, advanced: AdvancedConfig) -> Self {
        self.advanced = advanced;
        self
    }

    #[must_use]
    pub fn cookie_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.advanced.cookie_prefix = Some(prefix.into());
        self
    }

    #[must_use]
    pub const fn disable_csrf_check(mut self, disabled: bool) -> Self {
        self.advanced.disable_csrf_check = Some(disabled);
        self
    }

    /// Determine whether this request path opts out of origin validation.
    #[must_use]
    pub fn origin_check_disabled_for(&self, path: &str) -> bool {
        if self.advanced.disable_origin_check {
            return true;
        }
        let path = path
            .strip_prefix(self.base_path.trim_end_matches('/'))
            .filter(|suffix| suffix.starts_with('/'))
            .unwrap_or(path)
            .trim_end_matches('/');
        self.advanced.disable_origin_check_paths.iter().any(|skip| {
            let skip = skip.trim_end_matches('/');
            path == skip
                || path
                    .strip_prefix(skip)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }

    /// Apply the configured origin policy at an initialized request callback.
    #[must_use]
    pub fn current_origin_check_disabled(&self) -> bool {
        crate::hooks::current_request_hook_context()
            .map_or(self.advanced.disable_origin_check, |request| {
                self.origin_check_disabled_for(&request.path)
            })
    }

    #[must_use]
    pub const fn disable_origin_check(mut self, disabled: bool) -> Self {
        self.advanced.disable_origin_check = disabled;
        self
    }

    #[must_use]
    pub fn cross_sub_domain_cookies(mut self, domain: impl Into<String>) -> Self {
        self.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig {
            domain: domain.into(),
        });
        self
    }

    /// Check whether a given origin is trusted.
    ///
    /// An origin is trusted if it matches:
    /// 1. The origin extracted from [`base_url`](Self::base_url), or
    /// 2. Any pattern in [`trusted_origins`](Self::trusted_origins) (after
    ///    extracting the origin portion from the pattern).
    ///
    /// Glob patterns are supported — `*` matches any characters except `/`,
    /// `**` matches any characters including `/`.
    #[must_use]
    pub fn is_origin_trusted(&self, origin: &str) -> bool {
        // Check base_url origin
        if let Some(base_origin) = extract_origin(&self.base_url)
            && (origin == base_origin
                || (self.base_url.split_once(':').is_some_and(|(scheme, _)| {
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                }) && extract_origin(origin).as_deref() == Some(base_origin.as_str())))
        {
            return true;
        }
        // Check trusted_origins patterns
        self.trusted_origins.iter().any(|pattern| {
            let pattern_origin = legacy_pattern_origin(pattern).unwrap_or_default();
            glob_match::glob_match(&pattern_origin, origin)
        })
    }

    /// Check whether a URL is a safe redirect target.
    ///
    /// A URL is safe if it is a relative path (starts with `/`, no
    /// traversal tricks) or its origin matches [`base_url`](Self::base_url)
    /// or [`trusted_origins`](Self::trusted_origins).
    ///
    /// This is used by both the CSRF middleware (for POST body/query
    /// targets) and per-endpoint origin checks (e.g. verify-email GET).
    #[must_use]
    pub fn is_redirect_target_trusted(&self, url: &str) -> bool {
        if is_safe_relative_path(url) {
            return true;
        }
        extract_origin(url).is_some_and(|origin| self.is_origin_trusted(&origin))
    }

    /// Check whether a given path is disabled.
    #[must_use]
    pub fn is_path_disabled(&self, path: &str) -> bool {
        self.disabled_paths.iter().any(|disabled| disabled == path)
    }

    ///
    /// # Errors
    ///
    /// Returns a configuration error if the signing secret is empty or shorter than 32 bytes.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.secret.is_empty() {
            return Err(AuthError::config("Secret key cannot be empty"));
        }

        if self.secret.len() < 32 {
            return Err(AuthError::config(
                "Secret key must be at least 32 characters",
            ));
        }

        Ok(())
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig").finish_non_exhaustive()
    }
}

/// Check whether a URL is a safe relative path.
///
/// A relative path is safe if it starts with a single `/` and has no
/// traversal or scheme-escape tricks (`//`, `\`, `%2f`, `%5c`).
///
/// This is used by [`AuthConfig::is_redirect_target_trusted`] and the
/// CSRF middleware.
#[must_use]
pub fn is_safe_relative_path(value: &str) -> bool {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value
            .chars()
            .any(|character| matches!(character, '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}'))
    {
        return false;
    }

    let path = value.split(['?', '#']).next().unwrap_or(value);
    let lower = path.to_ascii_lowercase();
    !lower.contains("%2f")
        && !lower.contains("%5c")
        && url::Url::parse("https://better-auth.invalid")
            .and_then(|base| base.join(value))
            .is_ok_and(|url| url.origin().ascii_serialization() == "https://better-auth.invalid")
}

/// Extract the origin (scheme + host + port) from a URL string.
///
/// For example, `"https://example.com/path"` → `"https://example.com"`.
///
/// This is used by [`AuthConfig::is_origin_trusted`] and the CSRF middleware
/// so that origin comparison is centralised in one place.
#[must_use]
pub fn extract_origin(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url)
        && matches!(parsed.scheme(), "http" | "https")
    {
        return match parsed.origin() {
            url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
            url::Origin::Opaque(_) => None,
        };
    }
    // Custom schemes retain the existing Rust contract. Their upstream
    // authority/path matcher is a separate capability.
    legacy_pattern_origin(url)
}

// Configured glob/custom-scheme matching keeps its existing contract; avoid
// normalizing an explicit pattern into a newly trusted authority.
fn legacy_pattern_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let rest = url.get(scheme_end + 3..)?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = format!("{}{}", url.get(..scheme_end + 3)?, rest.get(..host_end)?);
    Some(origin)
}
