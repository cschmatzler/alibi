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
        .password_min_length(12)
        .disable_csrf_check(true)
        .disable_origin_check(true)
        .cookie_prefix("myapp");

    assert_eq!(cfg.app_name, "MyApp");
    assert_eq!(cfg.base_path, "/auth");
    assert_eq!(cfg.password.min_length, 12);
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
    let cfg =
        AuthConfig::new("test-secret-min-32-chars-1234567").trusted_origin("https://*.example.com");
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
    assert_eq!(p.min_length, 8);
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
    let html = core_paths::error_page_html("TEST_ERROR");
    assert!(html.contains("TEST_ERROR"));
    assert!(html.contains("Ask AI"));
    assert!(html.contains("<title>Error</title>"));
}

// Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
#[test]
fn error_page_sanitizes_script_tag() {
    let html = core_paths::error_page_html("<script>alert(1)</script>");
    assert!(html.contains("UNKNOWN"));
    assert!(!html.contains("<script>"));
}

// Upstream reference: packages/better-auth/src/api/routes/error.ts :: sanitize function and /^[A-Za-z0-9_'-]+$/ whitelist.
#[test]
fn error_page_allows_valid_codes() {
    assert!(core_paths::error_page_html("SOME_ERROR-CODE").contains("SOME_ERROR-CODE"));
    assert!(core_paths::error_page_html("it's").contains("it's"));
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
    assert_eq!(ip.headers, vec!["x-forwarded-for", "x-real-ip"]);
    assert!(!ip.disable_ip_tracking);
}
