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
    let req = make_request("/sign-in/email", "1.2.3.4");

    for _ in 0..5 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_blocks_over_limit() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 3);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/sign-in/email", "1.2.3.4");

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

    let req_a = make_request("/sign-in/email", "1.1.1.1");
    let req_b = make_request("/sign-in/email", "2.2.2.2");

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
    let config = RateLimitConfig::new()
        .default_limit(Duration::from_secs(60), 100)
        .endpoint("/sign-in/email", Duration::from_secs(60), 2);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/sign-in/email", "1.2.3.4");

    for _ in 0..2 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
    assert!(mw.before_request(&req).await.unwrap().is_some());
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
