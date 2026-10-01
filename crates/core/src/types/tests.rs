use super::*;

// ── AuthRequest ─────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_new_defaults() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    assert_eq!(req.method(), &HttpMethod::Get);
    assert_eq!(req.path(), "/test");
    assert!(req.headers.is_empty());
    assert!(req.body.is_none());
    assert!(req.virtual_user_id().is_none());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_from_parts() {
    let mut headers = HashMap::new();
    drop(headers.insert("host".to_owned(), "localhost".to_owned()));
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/login".into(),
        headers,
        Some(b"{}".to_vec()),
        HashMap::new(),
    );
    assert_eq!(req.method(), &HttpMethod::Post);
    assert_eq!(req.header("host"), Some(&"localhost".to_owned()));
    assert!(req.body.is_some());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_body_as_json_with_body() {
    let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/test".into(),
            HashMap::new(),
            Some(br#"{"name":"test","nested":{"$serde_json::private::RawValue":"hello"},"numbers":{"$serde_json::private::Number":"1e400"},"rounded":9007199254740993,"overflow":1e400}"#.to_vec()),
            HashMap::new(),
        );
    let val: serde_json::Value = req.body_as_json().expect("parse");
    assert_eq!(
        (*(val).get("name").unwrap_or(&serde_json::Value::Null)),
        "test"
    );
    assert_eq!(
        (*(*(val).get("nested").unwrap_or(&serde_json::Value::Null))
            .get("$serde_json::private::RawValue")
            .unwrap_or(&serde_json::Value::Null)),
        "hello"
    );
    assert_eq!(
        (*(*(val).get("numbers").unwrap_or(&serde_json::Value::Null))
            .get("$serde_json::private::Number")
            .unwrap_or(&serde_json::Value::Null)),
        "1e400"
    );
    assert_eq!(
        (*(val).get("rounded").unwrap_or(&serde_json::Value::Null)),
        9_007_199_254_740_992_u64
    );
    assert!((*(val).get("overflow").unwrap_or(&serde_json::Value::Null)).is_null());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_body_as_json_without_body() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    let val: serde_json::Value = req.body_as_json().expect("parse empty");
    assert!(val.is_object());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_request_virtual_user_id() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    assert!(req.virtual_user_id().is_none());
    let now = Utc::now();
    req.set_virtual_session(crate::wire::SessionView {
        omitted_fields: std::collections::BTreeSet::default(),
        id: "key-123".into(),
        token: "key-token".into(),
        user_id: "user-123".into(),
        created_at: now,
        updated_at: now,
        expires_at: now,
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
        active: true,
        extension_fields: std::collections::BTreeMap::default(),
    });
    assert_eq!(req.virtual_user_id(), Some("user-123"));
}

// ── AuthResponse ────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_new() {
    let resp = AuthResponse::new(200);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, Vec::<u8>::new());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_json() {
    let resp = AuthResponse::json(200, &OkResponse { ok: true }).expect("json");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "application/json"
    );
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(
        (*(body).get("ok").unwrap_or(&serde_json::Value::Null)),
        true
    );
}

// Pinned Better Call JSON response boundary: JavaScript numbers are rounded
// before emission, including typed integers and arbitrary nested metadata.
#[test]
fn auth_response_json_emits_javascript_numbers_without_mutating_input() {
    #[derive(Serialize)]
    struct ResponseData {
        integer: u64,
        metadata: crate::utils::json::JsValue,
        nonfinite: f64,
    }
    let metadata = crate::utils::json::parse_value(
            r#"{"2":1e400,"1":-0.0,"rounded":9007199254740993,"small":1e-7,"large":1e21,"tie":229069639655724.625,"nested":[-1e400,5e-324],"01":true,"4294967295":false,"id":"9007199254740993","configId":"1e400","providerId":"-0.0"}"#,
        )
        .expect("valid JSON number lexemes");
    let data = ResponseData {
        integer: u64::MAX,
        metadata,
        nonfinite: f64::NAN,
    };
    let response = AuthResponse::json(200, &data).expect("emit response");
    assert_eq!(
        std::str::from_utf8(&response.body).expect("JSON UTF-8"),
        r#"{"integer":18446744073709552000,"metadata":{"1":0,"2":null,"rounded":9007199254740992,"small":1e-7,"large":1e+21,"tie":229069639655724.62,"nested":[null,5e-324],"01":true,"4294967295":false,"id":"9007199254740993","configId":"1e400","providerId":"-0.0"},"nonfinite":null}"#
    );
    assert_eq!(
        data.metadata
            .get("2")
            .and_then(crate::utils::json::JsValue::as_f64),
        Some(f64::INFINITY)
    );
    assert!(
        data.metadata
            .get("1")
            .and_then(crate::utils::json::JsValue::as_f64)
            .expect("number")
            .is_sign_negative()
    );
    assert_eq!(
        data.metadata
            .get("rounded")
            .and_then(crate::utils::json::JsValue::as_f64),
        Some(9_007_199_254_740_992.0)
    );
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_text() {
    let resp = AuthResponse::text(404, "Not found");
    assert_eq!(resp.status, 404);
    assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Not found");
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_html() {
    let resp = AuthResponse::html(200, "<h1>Hi</h1>");
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn auth_response_with_header() {
    let resp = AuthResponse::new(200).with_header("x-custom", "val");
    assert_eq!(resp.headers.get("x-custom").unwrap(), "val");
}

// ── RequestMeta ─────────────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_extracts_from_headers() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    drop(
        req.headers
            .insert("x-forwarded-for".into(), "1.2.3.4".into()),
    );
    drop(req.headers.insert("user-agent".into(), "TestAgent".into()));
    let meta = RequestMeta::from_request(&req);
    assert_eq!(meta.ip_address.as_deref(), Some("1.2.3.4"));
    assert_eq!(meta.user_agent.as_deref(), Some("TestAgent"));
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_ignores_unconfigured_real_ip() {
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    drop(req.headers.insert("x-real-ip".into(), "5.6.7.8".into()));
    let meta = RequestMeta::from_request(&req);
    assert!(meta.ip_address.is_none());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn request_meta_none_when_no_headers() {
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    let meta = RequestMeta::from_request(&req);
    assert!(meta.ip_address.is_none());
    assert!(meta.user_agent.is_none());
}

// ── CreateUser builder ──────────────────────────────────────────────

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn create_user_builder() {
    let cu = CreateUser::new()
        .with_email("Test@Example.COM")
        .with_name("Test")
        .with_email_verified(true)
        .with_username("testuser")
        .with_role("admin")
        .with_metadata(serde_json::json!({"key": "val"}));

    assert!(cu.id.is_none()); // ID generation is delegated to the model/store path
    assert_eq!(cu.email.as_deref(), Some("test@example.com"));
    assert_eq!(cu.name.as_deref(), Some("Test"));
    assert_eq!(cu.email_verified, Some(true));
    assert_eq!(cu.username.as_deref(), Some("testuser"));
    assert_eq!(cu.role.as_deref(), Some("admin"));
    assert!(cu.metadata.is_some());
}

// Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
#[test]
fn create_user_default() {
    let cu = CreateUser::default();
    assert!(cu.id.is_none());
    assert!(cu.email.is_none());
}
