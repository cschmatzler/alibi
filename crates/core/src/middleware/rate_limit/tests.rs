use super::*;
use crate::types::HttpMethod;
use std::collections::HashMap as StdHashMap;

fn make_request(path: &str, ip: &str) -> AuthRequest {
    let mut headers = StdHashMap::new();
    headers.insert("x-forwarded-for".to_owned(), ip.to_owned());
    AuthRequest::from_parts(
        HttpMethod::Post,
        path.to_owned(),
        headers,
        None,
        StdHashMap::new(),
    )
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_allows_within_limit() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 5);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/get-session", "1.2.3.4");

    for _ in 0..5 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_blocks_over_limit() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 3);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/get-session", "1.2.3.4");

    for _ in 0..3 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_some());
    assert_eq!(resp.unwrap().status, 429);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_per_client() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 2);
    let mw = RateLimitMiddleware::new(config);

    let req_a = make_request("/get-session", "1.1.1.1");
    let req_b = make_request("/get-session", "2.2.2.2");

    // Client A uses up its limit
    for _ in 0..2 {
        assert!(mw.before_request(&req_a).await.unwrap().is_none());
    }
    assert!(mw.before_request(&req_a).await.unwrap().is_some());

    // Client B should still be allowed
    assert!(mw.before_request(&req_b).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_per_endpoint_override() {
    for (pattern, path) in [
        ("/sign-in/email", "/sign-in/email"),
        ("/sign-in/*", "/sign-in/email"),
        ("/email-otp/*", "/email-otp/send-verification-otp"),
    ] {
        let config = RateLimitConfig::new()
            .default_limit(Duration::from_secs(60), 100)
            .endpoint(pattern, Duration::from_secs(60), 2);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request(path, "1.2.3.4");
        for _ in 0..2 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        assert_eq!(mw.before_request(&req).await.unwrap().unwrap().status, 429);
    }
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_disabled() {
    let config = RateLimitConfig::new()
        .default_limit(Duration::from_secs(60), 1)
        .enabled(false);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/sign-in/email", "1.2.3.4");

    for _ in 0..10 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

// The real middleware must protect sensitive routes without application overrides.
#[tokio::test]
async fn default_sensitive_routes_are_limited_before_generic_routes() {
    for path in [
        "/sign-in/email",
        "/sign-up/email",
        "/change-password",
        "/change-email",
        "/request-password-reset",
        "/send-verification-email",
        "/forget-password/email",
        "/email-otp/send-verification-otp",
        "/email-otp/request-password-reset",
    ] {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new());
        let req = make_request(path, "192.0.2.1");
        for _ in 0..3 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        assert_eq!(
            mw.before_request(&req).await.unwrap().unwrap().status,
            429,
            "{path}"
        );
    }
    let mw = RateLimitMiddleware::new(RateLimitConfig::new());
    let req = make_request("/get-session", "192.0.2.1");
    for _ in 0..100 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
    let response = mw.before_request(&req).await.unwrap().unwrap();
    assert_eq!(response.status, 429);
    assert!(
        response
            .headers
            .get("x-retry-after")
            .unwrap()
            .parse::<u64>()
            .unwrap()
            <= 10
    );
}

// Capacity and expiry are observable admission behavior, not private map layout.
#[tokio::test]
async fn bounded_buckets_preserve_active_quotas_and_recover_after_expiry() {
    let mw = RateLimitMiddleware::new(
        RateLimitConfig::new()
            .default_limit(Duration::from_millis(250), 2)
            .max_buckets(2),
    );
    let first = make_request("/get-session", "192.0.2.1");
    let second = make_request("/get-session", "192.0.2.2");
    let third = make_request("/get-session", "192.0.2.3");
    assert!(mw.before_request(&first).await.unwrap().is_none());
    assert!(mw.before_request(&second).await.unwrap().is_none());
    for _ in 0..8 {
        assert_eq!(
            mw.before_request(&third).await.unwrap().unwrap().status,
            429
        );
    }
    assert!(mw.before_request(&first).await.unwrap().is_none());
    assert_eq!(
        mw.before_request(&first).await.unwrap().unwrap().status,
        429
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(mw.before_request(&third).await.unwrap().is_none());
    assert!(mw.before_request(&first).await.unwrap().is_none());
}

#[tokio::test]
async fn mounted_and_internal_paths_share_sensitive_route_quotas() {
    let mw = RateLimitMiddleware::new(RateLimitConfig::new()).with_base_path("/api/auth/");
    let mounted = make_request("/api/auth/sign-in/email", "192.0.2.1");
    let internal = make_request("/sign-in/email", "192.0.2.1");
    assert!(mw.before_request(&mounted).await.unwrap().is_none());
    assert!(mw.before_request(&internal).await.unwrap().is_none());
    assert!(mw.before_request(&mounted).await.unwrap().is_none());
    assert_eq!(
        mw.before_request(&internal).await.unwrap().unwrap().status,
        429
    );
    let other_mount = make_request("/unrelated/sign-in/email", "192.0.2.1");
    for _ in 0..4 {
        assert!(mw.before_request(&other_mount).await.unwrap().is_none());
    }
}
