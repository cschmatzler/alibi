use super::*;
use std::collections::HashMap;

fn make_options(origin: &str) -> AuthRequest {
    let mut headers = HashMap::new();
    headers.insert("origin".to_owned(), origin.to_owned());
    AuthRequest::from_parts(
        HttpMethod::Options,
        "/sign-in/email".to_owned(),
        headers,
        None,
        HashMap::new(),
    )
}

fn make_get(origin: &str) -> AuthRequest {
    let mut headers = HashMap::new();
    headers.insert("origin".to_owned(), origin.to_owned());
    AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_owned(),
        headers,
        None,
        HashMap::new(),
    )
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_cors_preflight_allowed() {
    let config = CorsConfig::new().allowed_origin("http://localhost:5173");
    let mw = CorsMiddleware::new(config);
    let req = make_options("http://localhost:5173");

    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_some());
    let resp = resp.unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(
        resp.headers.get("Access-Control-Allow-Origin").unwrap(),
        "http://localhost:5173"
    );
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_cors_preflight_not_allowed() {
    let config = CorsConfig::new().allowed_origin("http://localhost:5173");
    let mw = CorsMiddleware::new(config);
    let req = make_options("http://evil.com");

    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_none()); // No CORS headers added for disallowed origin
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_cors_adds_headers_after_request() {
    let config = CorsConfig::new().allowed_origin("http://localhost:5173");
    let mw = CorsMiddleware::new(config);
    let req = make_get("http://localhost:5173");

    let response = AuthResponse::json(200, &serde_json::json!({"ok": true})).unwrap();
    let response = mw.after_request(&req, response).await.unwrap();

    assert_eq!(
        response.headers.get("Access-Control-Allow-Origin").unwrap(),
        "http://localhost:5173"
    );
    assert_eq!(
        response
            .headers
            .get("Access-Control-Allow-Credentials")
            .unwrap(),
        "true"
    );
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_cors_no_origin_header() {
    let config = CorsConfig::new().allowed_origin("http://localhost:5173");
    let mw = CorsMiddleware::new(config);
    let req = AuthRequest::from_parts(
        HttpMethod::Get,
        "/get-session".to_owned(),
        HashMap::new(),
        None,
        HashMap::new(),
    );

    assert!(mw.before_request(&req).await.unwrap().is_none());

    let response = AuthResponse::new(200);
    let response = mw.after_request(&req, response).await.unwrap();
    assert!(!response.headers.contains_key("Access-Control-Allow-Origin"));
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_cors_wildcard() {
    let config = CorsConfig::new()
        .allowed_origin("*")
        .allow_credentials(false);
    let mw = CorsMiddleware::new(config);
    let req = make_get("http://any-origin.com");

    let response = AuthResponse::new(200);
    let response = mw.after_request(&req, response).await.unwrap();
    assert_eq!(
        response.headers.get("Access-Control-Allow-Origin").unwrap(),
        "*"
    );
}
