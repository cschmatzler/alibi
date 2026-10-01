use super::*;
use crate::types::HttpMethod;
use std::collections::HashMap;

fn make_request_with_body(body_size: usize) -> AuthRequest {
    AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".to_owned(),
        HashMap::new(),
        Some(vec![0u8; body_size]),
        HashMap::new(),
    )
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_body_limit_allows_within_limit() {
    let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
    let req = make_request_with_body(512);
    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_body_limit_allows_exact_limit() {
    let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
    let req = make_request_with_body(1024);
    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_body_limit_rejects_over_limit() {
    let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
    let req = make_request_with_body(2048);
    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_some());
    assert_eq!(resp.unwrap().status, 413);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_body_limit_allows_no_body() {
    let mw = BodyLimitMiddleware::new(BodyLimitConfig::new().max_bytes(1024));
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_owned(),
        HashMap::new(),
        None,
        HashMap::new(),
    );
    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_body_limit_disabled() {
    let config = BodyLimitConfig::new().max_bytes(10).enabled(false);
    let mw = BodyLimitMiddleware::new(config);
    let req = make_request_with_body(1000);
    assert!(mw.before_request(&req).await.unwrap().is_none());
}
