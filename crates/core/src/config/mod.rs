mod id;
#[doc(hidden)]
pub use id::serial_id_statements;
pub use id::{DatabaseIdGenerator, DatabaseIdStrategy};
mod account;
mod advanced;
mod identity;
mod session;

pub use account::AccountConfig;
pub use account::AccountLinkingConfig;
pub use account::OAuthStateStrategy;
pub use advanced::AdvancedConfig;
pub use advanced::AdvancedDatabaseConfig;
pub use advanced::CookieAttributes;
pub use advanced::CookieOverride;
pub use advanced::CrossSubDomainConfig;
pub use advanced::IpAddressConfig;
pub use advanced::SameSite;
pub use advanced::TwoFactorDatabaseConfig;
pub use identity::PasswordConfig;
pub use identity::UserConfig;
pub use identity::VerificationConfig;
pub use session::CookieCacheConfig;
pub use session::CookieCacheStrategy;
pub use session::CookieRefreshCache;
pub use session::JwtConfig;
pub use session::SessionConfig;
mod client_ip;
mod secrets;
pub use secrets::ManagedSecrets;

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
}

use crate::email::EmailProvider;
use crate::error::AuthError;
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;

/// Response policy for awaited lifecycle notifications. Explicit verification
/// delivery retains its direct error contract; deferred work logs its errors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AwaitedNotificationErrorPolicy {
    /// Propagate the callback error after retaining any committed auth writes.
    #[default]
    Propagate,
    /// Log delivery failure and continue the authentication response.
    LogAndContinue,
}

mod origin;
pub use origin::{
    BaseUrlProtocol, DynamicBaseUrl, TrustedOriginsResolver, TrustedProvidersResolver,
};

/// Main configuration for `BetterAuth`
#[derive(Clone)]
pub struct AuthConfig {
    /// Single-secret input. Managed mode uses `current_secret()` instead.
    pub secret: String,

    /// Versioned encryption keys. When present, its current key signs new tokens.
    /// Bare encrypted values require an explicitly configured legacy key.
    pub managed_secrets: Option<ManagedSecrets>,

    /// Application name, used for cookie prefixes, email templates, etc.
    ///
    /// Defaults to `"Better Auth"`.
    pub app_name: String,

    /// Base URL for the authentication service (e.g. `"http://localhost:3000"`).
    pub base_url: String,

    /// Request-dependent host allowlist. Static `base_url` remains the default.
    pub dynamic_base_url: Option<DynamicBaseUrl>,

    /// Application callback resolving additional trusted origins from the real request.
    pub trusted_origins_resolver: Option<std::sync::Arc<dyn TrustedOriginsResolver>>,

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

    /// Render the built-in HTML page for `GET /error` instead of redirecting to `/`.
    ///
    /// Defaults to `false` when `NODE_ENV` is `production`, and `true` otherwise.
    /// Set this to `true` to enable the renderer in production, corresponding to
    /// upstream's explicit `onAPIError.customizeDefaultErrorPage` option.
    pub render_error_page: bool,

    /// Default OAuth error destination, corresponding to `onAPIError.errorURL`.
    pub api_error_url: Option<String>,

    /// Propagate ordinary endpoint failures to the hosting application.
    /// Explicit public API errors continue to return HTTP responses.
    pub throw_api_errors: bool,

    /// Session configuration
    pub session: SessionConfig,

    /// Application user-field input, adapter and public output policies.
    pub user: UserConfig,

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
    /// Error handling when the request awaits a lifecycle notification.
    pub awaited_notification_errors: AwaitedNotificationErrorPolicy,

    /// Validate fresh identity data before its creation hooks or provider
    /// account/session writes. Returning non-provider sign-ins are unchanged.
    pub user_validation: Option<Arc<dyn crate::user_validation::UserInfoValidator>>,

    /// Advanced configuration options
    pub advanced: AdvancedConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            managed_secrets: None,
            app_name: "Better Auth".to_owned(),
            base_url: "http://localhost:3000".to_owned(),
            dynamic_base_url: None,
            trusted_origins_resolver: None,
            base_path: "/api/auth".to_owned(),
            trusted_origins: Vec::new(),
            disabled_paths: Vec::new(),
            render_error_page: !std::env::var("NODE_ENV").is_ok_and(|value| value == "production"),
            api_error_url: None,
            throw_api_errors: false,
            session: SessionConfig::default(),
            user: UserConfig::default(),
            verification: VerificationConfig::default(),
            jwt: JwtConfig::default(),
            password: PasswordConfig::default(),
            account: AccountConfig::default(),
            email_provider: None,
            background_tasks: None,
            awaited_notification_errors: AwaitedNotificationErrorPolicy::default(),
            user_validation: None,
            advanced: AdvancedConfig::default(),
        }
    }
}

impl AuthConfig {
    /// Choose whether awaited lifecycle email delivery failures fail the request.
    #[must_use]
    pub const fn awaited_notification_errors(
        mut self,
        policy: AwaitedNotificationErrorPolicy,
    ) -> Self {
        self.awaited_notification_errors = policy;
        self
    }

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

    /// Configure the default OAuth error destination (`onAPIError.errorURL`).
    /// An empty value uses the endpoint's ordinary fallback.
    #[must_use]
    pub fn api_error_url(mut self, url: impl Into<String>) -> Self {
        self.api_error_url = Some(url.into());
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

    /// Propagate ordinary endpoint exceptions through the public request result.
    #[must_use]
    pub const fn throw_api_errors(mut self, enabled: bool) -> Self {
        self.throw_api_errors = enabled;
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

    /// Current key for signing tokens and cookies. Retained keys are encryption
    /// readers; signed cookies and signed JWTs deliberately use only this key.
    #[must_use]
    pub fn current_secret(&self) -> &str {
        self.managed_secrets
            .as_ref()
            .map_or(self.secret.as_str(), ManagedSecrets::current_secret)
    }

    /// Encryption readers in configured order, followed by a distinct legacy key.
    pub fn verification_secrets(&self) -> impl Iterator<Item = &str> {
        let keys = self
            .managed_secrets
            .as_ref()
            .map(|secrets| secrets.verification_secrets());
        keys.into_iter().flatten().chain(
            self.managed_secrets
                .is_none()
                .then_some(self.secret.as_str()),
        )
    }

    /// Enable managed encryption with an explicit current version and readers.
    #[must_use]
    pub fn managed_secrets(mut self, secrets: ManagedSecrets) -> Self {
        self.managed_secrets = Some(secrets);
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

    /// Share cookies using the configured or request-resolved base URL's hostname.
    /// This follows the published hostname directly; it does not infer a parent
    /// or registrable domain. Use [`cross_sub_domain_cookies`](Self::cross_sub_domain_cookies)
    /// when a deployment needs an explicit parent domain.
    #[must_use]
    pub fn cross_sub_domain_cookies_from_base_url(mut self) -> Self {
        self.advanced.cross_sub_domain_cookies = Some(CrossSubDomainConfig::default());
        self
    }

    /// Check the resolved base origin or a configured trusted pattern.
    ///
    /// Explicit patterns follow Better Auth 1.7.6: `*` and `?` match URL origins
    /// (or hosts for patterns without a scheme), while custom schemes retain
    /// authority and normalized path-prefix constraints. Resolve dynamic policies
    /// with [`resolve_request`](Self::resolve_request) before evaluating them.
    #[must_use]
    pub fn is_origin_trusted(&self, origin: &str) -> bool {
        // Check base_url origin
        if self.dynamic_base_url.is_none()
            && let Some(base_origin) = extract_origin(&self.base_url)
            && (origin == base_origin
                || (self.base_url.split_once(':').is_some_and(|(scheme, _)| {
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                }) && extract_origin(origin).as_deref() == Some(base_origin.as_str())))
        {
            return true;
        }
        self.trusted_origins
            .iter()
            .any(|pattern| origin::matches_origin(origin, pattern))
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
        self.is_origin_trusted(url)
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
        if self.session.stateless
            && (self.session.secondary_storage.is_some()
                || self.session.store_in_database
                || self.session.preserve_in_database)
        {
            return Err(AuthError::config(
                "Stateless sessions cannot use server session storage",
            ));
        }
        if self
            .dynamic_base_url
            .as_ref()
            .is_some_and(|policy| policy.allowed_hosts.is_empty())
        {
            return Err(AuthError::config(
                "Dynamic base URL allowed hosts cannot be empty",
            ));
        }
        if let Some(secrets) = &self.managed_secrets {
            return secrets.validate();
        }
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_origin ──────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_path() {
        assert_eq!(
            extract_origin("https://example.com/path"),
            Some("https://example.com".to_owned())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_without_path() {
        assert_eq!(
            extract_origin("https://example.com"),
            Some("https://example.com".to_owned())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_port() {
        assert_eq!(
            extract_origin("http://localhost:3000/api"),
            Some("http://localhost:3000".to_owned())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_query() {
        assert_eq!(
            extract_origin("https://example.com?foo=bar"),
            Some("https://example.com".to_owned())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_with_fragment() {
        assert_eq!(
            extract_origin("https://example.com#fragment"),
            Some("https://example.com".to_owned())
        );
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_origin_no_scheme() {
        assert_eq!(extract_origin("example.com"), None);
    }

    // ── AuthConfig::new ─────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn new_config_sets_secret() {
        let cfg = AuthConfig::new("a]secret-that-is-at-least-32-characters-long");
        assert_eq!(cfg.secret, "a]secret-that-is-at-least-32-characters-long");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn new_config_uses_defaults() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567");
        assert_eq!(cfg.app_name, "Better Auth");
        assert_eq!(cfg.base_url, "http://localhost:3000");
        assert_eq!(cfg.base_path, "/api/auth");
        assert_eq!(cfg.trusted_origins, Vec::<String>::new());
    }

    // ── Builder methods ─────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn base_url_sets_cookie_secure_for_https() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.session.cookie_secure);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn base_url_clears_cookie_secure_for_http() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://myapp.com")
            .base_url("http://localhost:3000");
        assert!(!cfg.session.cookie_secure);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn builder_chaining() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .app_name("MyApp")
            .base_path("/auth")
            .disable_csrf_check(true)
            .disable_origin_check(true)
            .cookie_prefix("myapp");

        assert_eq!(cfg.app_name, "MyApp");
        assert_eq!(cfg.base_path, "/auth");
        assert_eq!(cfg.advanced.disable_csrf_check, Some(true));
        assert!(cfg.advanced.disable_origin_check);
        assert_eq!(cfg.advanced.cookie_prefix, Some("myapp".to_owned()));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn trusted_origin_appends() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://a.com")
            .trusted_origin("https://b.com");
        assert_eq!(cfg.trusted_origins.len(), 2);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn trusted_origins_replaces() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://old.com")
            .trusted_origins(vec!["https://new.com".to_owned()]);
        assert_eq!(cfg.trusted_origins, vec!["https://new.com"]);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn disabled_path_appends() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .disabled_path("/admin")
            .disabled_path("/debug");
        assert_eq!(cfg.disabled_paths.len(), 2);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn disabled_paths_replaces() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .disabled_path("/old")
            .disabled_paths(vec!["/new".to_owned()]);
        assert_eq!(cfg.disabled_paths, vec!["/new"]);
    }

    // ── is_origin_trusted ───────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_matches_base_url() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_origin_trusted("https://myapp.com"));
        let native_custom =
            AuthConfig::new("test-secret-min-32-chars-1234567").base_url("myapp://auth");
        assert!(native_custom.is_origin_trusted("myapp://auth"));
        assert!(!native_custom.is_origin_trusted("myapp://auth/callback"));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_rejects_unknown() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_origin_trusted("https://evil.com"));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_origin_trusted_glob_pattern() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .trusted_origin("https://*.example.com");
        assert!(cfg.is_origin_trusted("https://sub.example.com"));
        assert!(!cfg.is_origin_trusted("https://other.com"));
    }

    // ── is_redirect_target_trusted ─────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_relative_path() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_redirect_target_trusted("/dashboard"));
        assert!(cfg.is_redirect_target_trusted("/callback?foo=bar"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_same_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(cfg.is_redirect_target_trusted("https://myapp.com/verified"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_allows_trusted_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .base_url("https://myapp.com")
            .trusted_origin("https://trusted.com");
        assert!(cfg.is_redirect_target_trusted("https://trusted.com/path"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_rejects_untrusted_origin() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_redirect_target_trusted("https://evil.com/phish"));
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck validates callbackURL against trustedOrigins.
    #[test]
    fn redirect_target_rejects_protocol_relative() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").base_url("https://myapp.com");
        assert!(!cfg.is_redirect_target_trusted("//evil.com"));
    }

    // ── is_path_disabled ────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn is_path_disabled_matches() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").disabled_path("/admin");
        assert!(cfg.is_path_disabled("/admin"));
        assert!(!cfg.is_path_disabled("/user"));
    }

    // ── validate ────────────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_rejects_empty_secret() {
        let cfg = AuthConfig::default();
        assert!(cfg.validate().is_err());
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_rejects_short_secret() {
        let cfg = AuthConfig::new("short");
        assert!(cfg.validate().is_err());
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn validate_accepts_valid_secret() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567");
        assert!(cfg.validate().is_ok());
    }

    // ── Defaults ────────────────────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_config_defaults() {
        let s = SessionConfig::default();
        assert_eq!(s.expires_in, Duration::hours(24 * 7));
        assert_eq!(s.update_age, Some(Duration::hours(24)));
        assert!(!s.disable_session_refresh);
        assert_eq!(s.cookie_name, "better-auth.session_token");
        assert!(s.cookie_http_only);
        assert_eq!(s.cookie_same_site, SameSite::Lax);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn jwt_config_defaults() {
        let j = JwtConfig::default();
        assert_eq!(j.expires_in, Duration::hours(24));
        assert_eq!(j.algorithm, "HS256");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn password_config_defaults() {
        let p = PasswordConfig::default();
        assert!(!p.require_uppercase);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn same_site_display() {
        assert_eq!(SameSite::Strict.to_string(), "Strict");
        assert_eq!(SameSite::Lax.to_string(), "Lax");
        assert_eq!(SameSite::None.to_string(), "None");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn cookie_cache_config_defaults() {
        let c = CookieCacheConfig::default();
        assert!(!c.enabled);
        assert!((c.max_age - 300.0).abs() < f64::EPSILON);
        assert_eq!(c.strategy, CookieCacheStrategy::Compact);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn account_config_defaults() {
        let a = AccountConfig::default();
        assert!(a.update_account_on_sign_in);
        assert!(!a.encrypt_oauth_tokens);
        assert!(a.account_linking.enabled);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn core_paths_error_page() {
        let html = crate::error::page::error_page_html("TEST_ERROR");
        assert!(html.contains("TEST_ERROR"));
        assert!(html.contains("Ask AI"));
        assert!(html.contains("<title>Error</title>"));
    }

    // Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
    #[test]
    fn error_page_sanitizes_script_tag() {
        let html = crate::error::page::error_page_html("<script>alert(1)</script>");
        assert!(html.contains("UNKNOWN"));
        assert!(!html.contains("<script>"));
    }

    // Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
    #[test]
    fn error_page_allows_valid_codes() {
        assert!(crate::error::page::error_page_html("SOME_ERROR-CODE").contains("SOME_ERROR-CODE"));
        assert!(crate::error::page::error_page_html("it's").contains("it's"));
    }

    // ── session builder methods ─────────────────────────────────────────

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_builder_methods() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .session_expires_in(Duration::hours(1))
            .session_update_age(Duration::minutes(30))
            .disable_session_refresh(true)
            .session_fresh_age(Duration::minutes(5));

        assert_eq!(cfg.session.expires_in, Duration::hours(1));
        assert_eq!(cfg.session.update_age, Some(Duration::minutes(30)));
        assert!(cfg.session.disable_session_refresh);
        assert_eq!(cfg.session.fresh_age, Some(Duration::minutes(5)));
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_cookie_cache_builder() {
        let cache = CookieCacheConfig {
            enabled: true,
            max_age: 600.0,
            strategy: CookieCacheStrategy::Jwt,
            ..CookieCacheConfig::default()
        };
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567").session_cookie_cache(cache);

        let cc = cfg.session.cookie_cache.as_ref();
        assert!(cc.is_some());
        let cc = cc.unwrap();
        assert!(cc.enabled);
        assert_eq!(cc.strategy, CookieCacheStrategy::Jwt);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn cross_sub_domain_cookies_builder() {
        let cfg = AuthConfig::new("test-secret-min-32-chars-1234567")
            .cross_sub_domain_cookies(".example.com");
        let csd = cfg.advanced.cross_sub_domain_cookies.as_ref();
        assert!(csd.is_some());
        assert_eq!(csd.unwrap().domain, ".example.com");
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn advanced_database_defaults() {
        let d = AdvancedDatabaseConfig::default();
        assert_eq!(d.default_find_many_limit, 100);
        assert!(!d.use_number_id);
    }

    // Rust-specific surface: `AuthConfig`, related configuration builders, and `core_paths` are public Rust APIs with no direct TS analogue.
    #[test]
    fn ip_address_config_defaults() {
        let ip = IpAddressConfig::default();
        assert_eq!(ip.headers, vec!["x-forwarded-for"]);
        assert!(!ip.disable_ip_tracking);
    }
}
// LCOV_EXCL_STOP
