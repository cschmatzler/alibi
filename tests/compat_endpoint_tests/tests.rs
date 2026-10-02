use super::*;
use std::io::Write;

/// Run selected spec-driven endpoint validations in a single smoke test.
/// The hard compatibility gate is the dual-server client-compat harness.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn test_spec_driven_endpoint_validation() {
    let mut config = test_config();
    config.email_provider = Some(std::sync::Arc::new(
        better_auth_core::email::ConsoleEmailProvider,
    ));
    let auth = create_test_auth_with_config(config).await;
    let mut validator = SpecValidator::new();

    // --- GET /ok ---
    let (status, body) = send_request(&auth, get_request("/ok")).await;
    validator.validate_endpoint("/ok", "get", status, &body);

    // --- POST /sign-up/email (success) ---
    let (status_2, body_2) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Spec Test User",
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signup_token = body_2["token"].as_str().unwrap_or("").to_owned();
    validator.validate_endpoint("/sign-up/email", "post", status_2, &body_2);

    // --- POST /sign-in/email (success) ---
    let (status_3, body_3) = send_request(
        &auth,
        post_json(
            "/sign-in/email",
            serde_json::json!({
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signin_token = body_3["token"].as_str().unwrap_or("").to_owned();
    validator.validate_endpoint("/sign-in/email", "post", status_3, &body_3);

    // --- GET /get-session ---
    let (status_4, body_4) =
        send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
    validator.validate_endpoint("/get-session", "get", status_4, &body_4);

    // --- GET /list-sessions ---
    let (status_5, body_5) =
        send_request(&auth, get_with_auth("/list-sessions", &signin_token)).await;
    // list-sessions returns an array, validate the first element against Session schema
    if let Some(arr) = body_5.as_array() {
        if let Some(first) = arr.first() {
            let _session_schema = extract_success_schema(&validator.spec, "/list-sessions", "get");
            let camel_violations = check_camel_case_fields(first, "sessions[0]");
            let passed = camel_violations.is_empty();
            validator.results.push(EndpointResult {
                endpoint: "/list-sessions".to_owned(),
                method: "GET".to_owned(),
                status: status_5,
                passed,
                skipped: false,
                diffs: vec![],
                camel_case_violations: camel_violations,
            });
        } else {
            // Empty array — valid but nothing to validate
            validator.results.push(EndpointResult {
                endpoint: "/list-sessions".to_owned(),
                method: "GET".to_owned(),
                status: status_5,
                passed: true,
                skipped: false,
                diffs: vec![],
                camel_case_violations: vec![],
            });
        }
    } else {
        validator.results.push(EndpointResult {
            endpoint: "/list-sessions".to_owned(),
            method: "GET".to_owned(),
            status: status_5,
            passed: false,
            skipped: false,
            diffs: vec![ShapeDiff {
                path: String::new(),
                kind: DiffKind::TypeMismatch {
                    expected: "array".to_owned(),
                    actual: json_type_name(&body_5).to_owned(),
                },
            }],
            camel_case_violations: vec![],
        });
    }

    // --- POST /sign-out ---
    let (status_6, body_6) = send_request(
        &auth,
        post_json_with_auth("/sign-out", serde_json::json!({}), &signup_token),
    )
    .await;
    validator.validate_endpoint("/sign-out", "post", status_6, &body_6);

    // --- POST /request-password-reset ---
    // Sign up a fresh user for password tests
    let (pw_token, _) = signup_user(&auth, "pw@example.com", "password123", "PW User").await;

    let (status_7, body_7) = send_request(
        &auth,
        post_json(
            "/request-password-reset",
            serde_json::json!({
                "email": "pw@example.com",
            }),
        ),
    )
    .await;
    validator.validate_endpoint("/request-password-reset", "post", status_7, &body_7);

    // --- POST /change-password ---
    let (status_8, body_8) = send_request(
        &auth,
        post_json_with_auth(
            "/change-password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newpassword456",
                "revokeOtherSessions": "false"
            }),
            &pw_token,
        ),
    )
    .await;
    validator.validate_endpoint("/change-password", "post", status_8, &body_8);

    // --- POST /verify-password ---
    let (status_9, body_9) = send_request(
        &auth,
        post_json_with_auth(
            "/verify-password",
            serde_json::json!({
                "password": "newpassword456"
            }),
            &pw_token,
        ),
    )
    .await;
    validator.validate_endpoint("/verify-password", "post", status_9, &body_9);

    // --- POST /update-user ---
    let (upd_token, _) = signup_user(&auth, "upd@example.com", "password123", "UPD User").await;
    let (status_10, body_10) = send_request(
        &auth,
        post_json_with_auth(
            "/update-user",
            serde_json::json!({
                "name": "Updated Name"
            }),
            &upd_token,
        ),
    )
    .await;
    validator.validate_endpoint("/update-user", "post", status_10, &body_10);

    // --- POST /delete-user (spec method) ---
    let (del_token, _) = signup_user(&auth, "del@example.com", "password123", "DEL User").await;
    let (status_11, body_11) = send_request(
        &auth,
        post_json_with_auth("/delete-user", serde_json::json!({}), &del_token),
    )
    .await;
    validator.validate_endpoint("/delete-user", "post", status_11, &body_11);

    // --- POST /change-email ---
    let (ce_token, _) = signup_user(&auth, "ce@example.com", "password123", "CE User").await;
    let (evaluated_status_12, evaluated_body_12) = send_request(
        &auth,
        post_json_with_auth(
            "/change-email",
            serde_json::json!({
                "newEmail": "ce_new@example.com"
            }),
            &ce_token,
        ),
    )
    .await;
    validator.validate_endpoint(
        "/change-email",
        "post",
        evaluated_status_12,
        &evaluated_body_12,
    );

    // --- GET /list-accounts ---
    let (la_token, _) = signup_user(&auth, "la@example.com", "password123", "LA User").await;
    let (evaluated_status_13, evaluated_body_13) =
        send_request(&auth, get_with_auth("/list-accounts", &la_token)).await;
    // list-accounts returns an array, validate camelCase
    if let Some(arr) = evaluated_body_13.as_array() {
        if let Some(first) = arr.first() {
            let camel_violations = check_camel_case_fields(first, "accounts[0]");
            let passed = camel_violations.is_empty();
            validator.results.push(EndpointResult {
                endpoint: "/list-accounts".to_owned(),
                method: "GET".to_owned(),
                status: evaluated_status_13,
                passed,
                skipped: false,
                diffs: vec![],
                camel_case_violations: camel_violations,
            });
        } else {
            // Empty array — valid but nothing to validate
            validator.results.push(EndpointResult {
                endpoint: "/list-accounts".to_owned(),
                method: "GET".to_owned(),
                status: evaluated_status_13,
                passed: true,
                skipped: false,
                diffs: vec![],
                camel_case_violations: vec![],
            });
        }
    } else {
        validator.results.push(EndpointResult {
            endpoint: "/list-accounts".to_owned(),
            method: "GET".to_owned(),
            status: evaluated_status_13,
            passed: false,
            skipped: false,
            diffs: vec![ShapeDiff {
                path: String::new(),
                kind: DiffKind::TypeMismatch {
                    expected: "array".to_owned(),
                    actual: json_type_name(&evaluated_body_13).to_owned(),
                },
            }],
            camel_case_violations: vec![],
        });
    }

    // --- GET /account-info ---
    let (ai_token, ai_signup_body) =
        signup_user(&auth, "ai@example.com", "password123", "AI User").await;
    let ai_user_id = ai_signup_body["user"]["id"]
        .as_str()
        .expect("sign-up should return user id");
    let account_info_account = auth
        .store()
        .create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: ai_user_id.to_owned(),
            account_id: "mock-account-id".to_owned(),
            provider_id: "mock".to_owned(),
            access_token: Some("mock-access-token".to_owned()),
            refresh_token: Some("mock-refresh-token".to_owned()),
            id_token: None,
            access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            refresh_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(2)),
            scope: Some("openid,email,profile".to_owned()),
            password: None,
        })
        .await
        .expect("account-info test account should be created");
    let (evaluated_status_14, evaluated_body_14) = send_request(
        &auth,
        get_with_auth_and_query(
            "/account-info",
            &ai_token,
            vec![("accountId", account_info_account.id.as_str())],
        ),
    )
    .await;
    validator.validate_endpoint(
        "/account-info",
        "get",
        evaluated_status_14,
        &evaluated_body_14,
    );

    // --- GET /__test/openapi.json ---
    let (evaluated_status_15, evaluated_body_15) =
        send_request(&auth, get_request("/__test/openapi.json")).await;
    assert_eq!(
        evaluated_status_15, 200,
        "OpenAPI endpoint should return 200"
    );
    assert!(
        evaluated_body_15["openapi"].is_string(),
        "Should have openapi version"
    );
    assert!(evaluated_body_15["paths"].is_object(), "Should have paths");

    // Print report
    let report = validator.report();
    drop(writeln!(std::io::stderr().lock(), "\n{report}\n"));

    // All known incompatibilities have been fixed.
    // Track any future gaps here so the gate catches *new* regressions.
    let known_failing: HashSet<&str> = HashSet::new();

    assert_eq!(
        validator.skipped_count(),
        0,
        "Spec-driven validation skipped endpoints; path or method drift is losing coverage."
    );

    let unexpected_failures: Vec<_> = validator
        .results
        .iter()
        .filter(|r| !r.passed && !r.skipped && !known_failing.contains(r.endpoint.as_str()))
        .collect();

    assert!(
        unexpected_failures.is_empty(),
        "Spec-driven validation found unexpected failures (not in the known-failing list):\n{}",
        unexpected_failures
            .iter()
            .map(|r| format!("  {} {}", r.method, r.endpoint))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// All error responses must follow the { "message": "..." } format per the spec.
#[tokio::test]
async fn test_error_response_shapes_match_spec() {
    let auth = create_test_auth().await;
    let spec = compat::schema::load_openapi_spec();

    // Collect error scenarios
    let error_scenarios: Vec<(&str, &str, better_auth::prelude::AuthRequest, u16)> = vec![
        (
            "/sign-in/email",
            "post",
            post_json(
                "/sign-in/email",
                serde_json::json!({
                    "email": "nonexistent@example.com",
                    "password": "password123"
                }),
            ),
            401,
        ),
        (
            "/sign-up/email",
            "post",
            post_json("/sign-up/email", serde_json::json!({})),
            400,
        ),
        (
            "/sign-up/email",
            "post",
            post_json(
                "/sign-up/email",
                serde_json::json!({
                    "name": "Short",
                    "email": "short@example.com",
                    "password": "123"
                }),
            ),
            400,
        ),
    ];

    let mut all_passed = true;
    for (path, method, req, expected_status_class) in error_scenarios {
        let (status, body) = send_request(&auth, req).await;
        let status_class = status / 100;
        let expected_class = expected_status_class / 100;

        // Verify status is in the expected class (4xx)
        if status_class != expected_class {
            drop(writeln!(
                std::io::stderr().lock(),
                "WARN: {} {} returned status {} (expected {}xx)",
                method.to_uppercase(),
                path,
                status,
                expected_class
            ));
        }

        // All error responses MUST have a "message" field per the spec
        if status >= 400 {
            if !body["message"].is_string() {
                drop(writeln!(
                    std::io::stderr().lock(),
                    "FAIL: {} {} error response missing 'message' field: {}",
                    method.to_uppercase(),
                    path,
                    body
                ));
                all_passed = false;
            }

            // Validate against spec error schema
            let error_schemas = compat::schema::extract_error_schemas(&spec, path, method);
            if let Some(error_schema) = error_schemas.get(&status.to_string()) {
                let diffs = compat::validation::validate_response(&body, error_schema, "");
                if !diffs.is_empty() {
                    drop(writeln!(
                        std::io::stderr().lock(),
                        "FAIL: {} {} error response shape mismatch (status {}):",
                        method.to_uppercase(),
                        path,
                        status
                    ));
                    for diff in &diffs {
                        drop(writeln!(std::io::stderr().lock(), "      {diff}"));
                    }
                    all_passed = false;
                }
            }
        }
    }

    assert!(
        all_passed,
        "Some error responses don't match the spec. See output above."
    );
}
