use super::*;

fn make_request(
    path: &str,
    origin: Option<&str>,
    cookie: bool,
    extra_headers: &[(&str, &str)],
) -> AuthRequest {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    if let Some(origin) = origin {
        headers.insert("origin".to_owned(), origin.to_owned());
    }
    if cookie {
        headers.insert(
            "cookie".to_owned(),
            "better-auth.session_token=test-token".to_owned(),
        );
    }
    for (name, value) in extra_headers {
        headers.insert((*name).to_owned(), (*value).to_owned());
    }
    AuthRequest::from_parts(
        HttpMethod::Post,
        path.to_owned(),
        headers,
        None,
        HashMap::new(),
    )
}

fn test_auth_config(trusted_origins: Vec<String>) -> Arc<AuthConfig> {
    Arc::new(
        AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .trusted_origins(trusted_origins),
    )
}

fn forbidden_message(response: Option<AuthResponse>) -> String {
    let response = response.expect("expected rejection response");
    assert_eq!(response.status, 403);
    let body = serde_json::from_slice::<serde_json::Value>(&response.body).unwrap();
    (*(body).get("message").unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap()
        .to_owned()
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn cookie_backed_requests_require_a_trusted_origin() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
    let message = forbidden_message(mw.before_request(&req).await.unwrap());
    assert_eq!(message, INVALID_ORIGIN);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn cookie_backed_requests_require_origin_or_referer() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    let req = make_request("/sign-out", None, true, &[]);
    let message = forbidden_message(mw.before_request(&req).await.unwrap());
    assert_eq!(message, MISSING_OR_NULL_ORIGIN);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn sign_in_allows_same_origin_fetch_metadata_requests() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    let req = make_request(
        "/sign-in/email",
        Some("http://localhost:3000"),
        false,
        &[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
        ],
    );
    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn sign_in_blocks_cross_site_navigation_login_attempts() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    let req = make_request(
        "/sign-in/email",
        Some("http://evil.com"),
        false,
        &[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
        ],
    );
    let message = forbidden_message(mw.before_request(&req).await.unwrap());
    assert_eq!(message, CROSS_SITE_NAVIGATION_LOGIN_BLOCKED);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn sign_up_rejects_untrusted_origin_without_metadata() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    let req = make_request("/sign-up/email", Some("http://evil.com"), false, &[]);
    assert_eq!(
        forbidden_message(mw.before_request(&req).await.unwrap()),
        "Invalid origin"
    );
}

// Pinned origin-check middleware applies JavaScript truthiness, then checks
// each redirect field's type before route schema parsing.
#[tokio::test]
async fn redirect_targets_enforce_types_origins_and_callback_precedence() {
    let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
    for (field, label) in [
        ("callbackURL", "callbackURL"),
        ("redirectTo", "redirectURL"),
        ("errorCallbackURL", "errorCallbackURL"),
        ("newUserCallbackURL", "newUserCallbackURL"),
    ] {
        for value in [
            serde_json::json!(5),
            serde_json::json!(true),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let mut req = make_request("/send-verification-email", None, false, &[]);
            req.body = Some(serde_json::json!({field:value}).to_string().into_bytes());
            let response = mw
                .before_request(&req)
                .await
                .unwrap()
                .expect("truthy non-string redirect must be rejected before the route");
            assert_eq!(response.status, 400);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                serde_json::json!({"message":format!("Invalid {label}: expected a string")})
            );
        }
        for value in [
            serde_json::Value::Null,
            serde_json::json!(false),
            serde_json::json!(0),
            serde_json::json!(""),
        ] {
            let mut req = make_request("/send-verification-email", None, false, &[]);
            req.body = Some(serde_json::json!({field:value}).to_string().into_bytes());
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }
    let mut request = make_request("/send-verification-email", None, false, &[]);
    request.query.insert(
        "callbackURL".to_owned(),
        "http://evil.com/dashboard".to_owned(),
    );
    request.body = Some(
        serde_json::json!({"callbackURL":"/safe"})
            .to_string()
            .into_bytes(),
    );
    assert!(
        mw.before_request(&request).await.unwrap().is_none(),
        "the body callback overrides the query callback"
    );
    request.body = Some(
        serde_json::json!({"callbackURL":null})
            .to_string()
            .into_bytes(),
    );
    let message = forbidden_message(mw.before_request(&request).await.unwrap());
    assert_eq!(
        message, INVALID_CALLBACK_URL,
        "a falsy body callback falls back to the query"
    );
    request.query.clear();
    request.query.insert(
        "redirectTo".to_owned(),
        "http://evil.com/ignored".to_owned(),
    );
    assert!(
        mw.before_request(&request).await.unwrap().is_none(),
        "upstream reads other redirects from the body only"
    );
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn csrf_can_be_disabled_explicitly() {
    let mw = CsrfMiddleware::new(CsrfConfig::new().enabled(false), test_auth_config(vec![]));
    let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn advanced_disable_origin_check_skips_callback_url_validation() {
    let mut config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .disable_origin_check(true);
    config.trusted_origins = vec![];
    let mw = CsrfMiddleware::new(CsrfConfig::new(), Arc::new(config));
    let mut req = make_request("/sign-in/social", None, false, &[]);
    req.body = Some(
        serde_json::json!({
            "provider": "google",
            "callbackURL": "http://evil.com/dashboard"
        })
        .to_string()
        .into_bytes(),
    );

    assert!(mw.before_request(&req).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[test]
fn extract_origin_still_handles_paths() {
    assert_eq!(
        extract_origin("https://example.com/path"),
        Some("https://example.com".to_owned())
    );
    assert_eq!(
        extract_origin("http://localhost:3000"),
        Some("http://localhost:3000".to_owned())
    );
    assert_eq!(extract_origin("not-a-url"), None);
}
