use super::*;
use std::io::Write;

// ---------------------------------------------------------------------------
// Schema Diff Tests
// ---------------------------------------------------------------------------

/// Verify the reference spec can be parsed and has a reasonable number of endpoints.
#[test]
fn test_reference_spec_loads() {
    let spec = load_reference_spec();
    assert!(
        spec.len() >= 50,
        "Reference spec should have at least 50 paths, got {}",
        spec.len()
    );
}

/// Print a coverage report showing which reference endpoints are implemented.
/// This test always passes but prints useful diagnostics.
#[tokio::test]
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
async fn test_route_coverage_report() {
    let reference = load_reference_spec();
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let mut covered = 0;
    let mut missing = Vec::new();
    let mut extra = Vec::new();
    let total_ref_endpoints: usize = reference.values().map(HashSet::len).sum();

    for (path, ref_methods) in &reference {
        if let Some(impl_methods) = implemented.get(path) {
            for method in ref_methods {
                if impl_methods.contains(method) {
                    covered += 1;
                } else {
                    missing.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        } else {
            for method in ref_methods {
                missing.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    // Find routes we have that aren't in the reference
    for (path, impl_methods) in &implemented {
        if let Some(ref_methods) = reference.get(path) {
            for method in impl_methods {
                if !ref_methods.contains(method) {
                    extra.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        } else {
            for method in impl_methods {
                extra.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    let coverage_pct = if total_ref_endpoints > 0 {
        (f64::from(covered) / total_ref_endpoints as f64) * 100.0
    } else {
        0.0
    };

    drop(writeln!(
        std::io::stderr().lock(),
        "=== Route Coverage Report ==="
    ));
    drop(writeln!(
        std::io::stderr().lock(),
        "Reference endpoints: {total_ref_endpoints}"
    ));
    drop(writeln!(
        std::io::stderr().lock(),
        "Implemented:         {covered}"
    ));
    drop(writeln!(
        std::io::stderr().lock(),
        "Missing:             {}",
        missing.len()
    ));
    drop(writeln!(
        std::io::stderr().lock(),
        "Extra (non-ref):     {}",
        extra.len()
    ));
    drop(writeln!(
        std::io::stderr().lock(),
        "Coverage:            {coverage_pct:.1}%"
    ));
    drop(writeln!(std::io::stderr().lock()));

    if !missing.is_empty() {
        drop(writeln!(
            std::io::stderr().lock(),
            "--- Missing endpoints ---"
        ));
        for m in &missing {
            drop(writeln!(std::io::stderr().lock(), "  [ ] {m}"));
        }
    }
    if !extra.is_empty() {
        drop(writeln!(
            std::io::stderr().lock(),
            "--- Extra endpoints (not in reference) ---"
        ));
        for e in &extra {
            drop(writeln!(std::io::stderr().lock(), "  [+] {e}"));
        }
    }
    drop(writeln!(
        std::io::stderr().lock(),
        "============================="
    ));
}

#[tokio::test]
async fn test_reference_profile_surface_matches_reference_exactly() {
    let reference = load_reference_spec();
    let expected = reference_profile_reference_surface(&reference);
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let mut missing = Vec::new();
    let mut extra = Vec::new();

    for (path, expected_methods) in &expected {
        match implemented.get(path) {
            Some(actual_methods) => {
                for method in expected_methods {
                    if !actual_methods.contains(method) {
                        missing.push(format!("{} {}", method.to_uppercase(), path));
                    }
                }
                for method in actual_methods {
                    if !expected_methods.contains(method) {
                        extra.push(format!("{} {}", method.to_uppercase(), path));
                    }
                }
            }
            None => {
                for method in expected_methods {
                    missing.push(format!("{} {}", method.to_uppercase(), path));
                }
            }
        }
    }

    assert!(
        missing.is_empty() && extra.is_empty(),
        "reference profile route drift detected\nmissing:\n{}\nextra:\n{}",
        if missing.is_empty() {
            "<none>".to_owned()
        } else {
            missing.join("\n")
        },
        if extra.is_empty() {
            "<none>".to_owned()
        } else {
            extra.join("\n")
        }
    );
}

/// Verify that the endpoints covered by the reference profile exist.
#[tokio::test]
async fn test_reference_profile_endpoints_present() {
    let auth = create_full_auth().await;
    let implemented = collect_implemented_routes(&auth);

    let required = vec![
        ("get", "/ok"),
        ("get", "/error"),
        ("post", "/sign-up/email"),
        ("post", "/sign-in/email"),
        ("post", "/sign-in/username"),
        ("post", "/is-username-available"),
        ("get", "/get-session"),
        ("post", "/sign-out"),
        ("post", "/update-user"),
        ("post", "/delete-user"),
        ("post", "/request-password-reset"),
        ("post", "/reset-password"),
        ("post", "/change-password"),
        ("post", "/verify-password"),
        ("post", "/send-verification-email"),
        ("get", "/verify-email"),
        ("get", "/list-sessions"),
        ("post", "/revoke-session"),
        ("post", "/revoke-sessions"),
        ("post", "/revoke-other-sessions"),
        ("post", "/sign-in/social"),
        ("get", "/callback/{provider}"),
        ("post", "/callback/{provider}"),
        ("post", "/link-social"),
        ("get", "/list-accounts"),
        ("post", "/unlink-account"),
        ("get", "/account-info"),
        ("post", "/change-email"),
        ("get", "/delete-user/callback"),
        ("post", "/device/code"),
        ("post", "/device/token"),
        ("get", "/device"),
        ("post", "/device/approve"),
        ("post", "/device/deny"),
        ("post", "/api-key/create"),
        ("get", "/api-key/get"),
        ("get", "/api-key/list"),
        ("post", "/api-key/update"),
        ("post", "/api-key/delete"),
    ];

    let mut missing = Vec::new();
    for (method, path) in &required {
        let found = implemented
            .get(*path)
            .is_some_and(|methods| methods.contains(*method));
        if !found {
            missing.push(format!("{} {}", method.to_uppercase(), path));
        }
    }

    assert!(
        missing.is_empty(),
        "Missing required endpoints:\n{}",
        missing.join("\n")
    );
}

/// Verify our generated `OpenAPI` spec includes all core routes.
#[tokio::test]
async fn test_generated_openapi_has_core_routes() {
    let auth = create_full_auth().await;
    let spec = auth.openapi_spec();

    assert!(spec.paths.contains_key("/ok"), "OpenAPI spec missing /ok");
    assert!(
        spec.paths.contains_key("/error"),
        "OpenAPI spec missing /error"
    );
    assert!(
        spec.paths.contains_key("/update-user"),
        "OpenAPI spec missing /update-user"
    );
    assert!(
        spec.paths.contains_key("/delete-user"),
        "OpenAPI spec missing /delete-user"
    );
    assert!(
        spec.paths.contains_key("/sign-up/email"),
        "OpenAPI spec missing /sign-up/email"
    );
    assert!(
        spec.paths.contains_key("/sign-in/email"),
        "OpenAPI spec missing /sign-in/email"
    );
    assert!(
        spec.paths.contains_key("/verify-password"),
        "OpenAPI spec missing /verify-password"
    );
    assert!(
        spec.paths.contains_key("/account-info"),
        "OpenAPI spec missing /account-info"
    );
}

/// Verify the generated `OpenAPI` spec version and info fields.
#[tokio::test]
async fn test_generated_openapi_metadata() {
    let auth = create_full_auth().await;
    let spec = auth.openapi_spec();

    assert_eq!(spec.openapi, "3.1.1");
    assert_eq!(spec.info.title, "Better Auth");
    assert!(spec.info.description.is_some());
}

/// GET /ok should return { "ok": true }
#[tokio::test]
async fn test_contract_ok_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(&auth, HttpMethod::Get, "/ok", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
}

/// GET /error should return the TS-compatible HTML error page.
#[tokio::test]
async fn test_contract_error_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(&auth, HttpMethod::Get, "/error", None).await;
    assert_eq!(status, 200);
    let html = body.as_str().expect("/error should return HTML text");
    // The HTML page uses inline-styled elements matching the TS template
    // (not plain `<h1>ERROR</h1>` — both TS and Rust use styled tags).
    assert!(
        html.contains("<title>Error</title>"),
        "error page should contain <title>Error</title>"
    );
    assert!(
        html.contains("ERROR"),
        "error page should contain ERROR heading"
    );
    let text = html_text_content(html);
    assert!(
        text.contains("CODE: UNKNOWN"),
        "error page should contain the CODE: UNKNOWN error code label"
    );
    assert!(
        html.contains("Ask AI"),
        "error page should contain Ask AI button"
    );
}

/// POST /sign-up/email should return { token, user: { id, email, name, ... } }
#[tokio::test]
async fn test_contract_signup_response_shape() {
    let auth = create_full_auth().await;
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({
            "email": "contract@example.com",
            "password": "password123",
            "name": "Contract Test"
        })),
    )
    .await;

    assert_eq!(status, 200);

    // Must have token
    assert!(
        body["token"].is_string(),
        "Response must contain 'token' string"
    );

    // Must have user object with required fields
    let user = &body["user"];
    assert!(user["id"].is_string(), "user.id must be a string");
    assert_eq!(user["email"], "contract@example.com");
    assert_eq!(user["name"], "Contract Test");
    assert!(
        user.get("createdAt").is_some() || user.get("created_at").is_some(),
        "user must have createdAt or created_at"
    );
}

/// POST /sign-in/email should return { token, user: { ... } }
#[tokio::test]
async fn test_contract_signin_response_shape() {
    let auth = create_full_auth().await;

    // Create user first
    drop(
        send_json_request(
            &auth,
            HttpMethod::Post,
            "/sign-up/email",
            Some(serde_json::json!({
                "email": "signin-contract@example.com",
                "password": "password123",
                "name": "Signin Contract"
            })),
        )
        .await,
    );

    // Sign in
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(serde_json::json!({
            "email": "signin-contract@example.com",
            "password": "password123"
        })),
    )
    .await;

    assert_eq!(status, 200);
    assert!(
        body["token"].is_string(),
        "Response must contain 'token' string"
    );
    assert!(body["user"]["id"].is_string(), "user.id must be a string");
    assert_eq!(body["user"]["email"], "signin-contract@example.com");
}

/// POST /sign-out should return { success: true }
#[tokio::test]
async fn test_contract_signout_response_shape() {
    let auth = create_full_auth().await;

    // Create user and get token
    let (_, signup_body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({
            "email": "signout-contract@example.com",
            "password": "password123",
            "name": "Signout Test"
        })),
    )
    .await;

    let token = signup_body["token"].as_str().unwrap();

    // Sign out
    let mut req = AuthRequest::new(HttpMethod::Post, "/sign-out");
    drop(req.headers.insert(
        "cookie".to_owned(),
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(token, &auth.config().secret)
        ),
    ));
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    let resp = auth
        .handle_request(req)
        .await
        .expect("Sign-out should not panic");

    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["success"], true);
    assert!(auth.store().get_session(token).await.unwrap().is_none());
}

/// Error responses must have { "message": "..." } shape
#[tokio::test]
async fn test_contract_error_response_shape() {
    let auth = create_full_auth().await;

    // Try to sign in with invalid credentials
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-in/email",
        Some(serde_json::json!({
            "email": "nonexistent@example.com",
            "password": "password123"
        })),
    )
    .await;

    assert!(
        status >= 400,
        "Error should return 4xx status, got {status}"
    );
    assert!(
        body["message"].is_string(),
        "Error response must have 'message' field, got: {body}"
    );
}

/// Validation error responses must have { "message": "..." } and 4xx status
#[tokio::test]
async fn test_contract_validation_error_shape() {
    let auth = create_full_auth().await;

    // Missing required fields
    let (status, body) = send_json_request(
        &auth,
        HttpMethod::Post,
        "/sign-up/email",
        Some(serde_json::json!({})),
    )
    .await;

    assert!(
        (400..500).contains(&status),
        "Validation error should be 4xx, got {status}"
    );
    assert!(
        body["message"].is_string(),
        "Validation error must have 'message' field"
    );
}

/// GET /__test/openapi.json should return valid `OpenAPI` spec
#[tokio::test]
async fn test_contract_openapi_endpoint() {
    let auth = create_full_auth().await;
    let (status, body) =
        send_json_request(&auth, HttpMethod::Get, "/__test/openapi.json", None).await;

    assert_eq!(status, 200);
    assert!(
        body["openapi"].is_string(),
        "Must have 'openapi' version field"
    );
    assert!(body["info"]["title"].is_string(), "Must have info.title");
    assert!(body["paths"].is_object(), "Must have 'paths' object");
}

/// The pinned router leaves unknown routes empty and skips endpoint hooks.
#[tokio::test]
async fn test_contract_not_found_response() {
    let auth = create_full_auth().await;
    let response = auth
        .handle_request(AuthRequest::new(HttpMethod::Get, "/nonexistent-route"))
        .await
        .unwrap();
    assert_eq!(response.status, 404);
    assert!(response.body.is_empty());
    assert!(!response.headers.contains_key("content-type"));
}
