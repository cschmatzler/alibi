#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![expect(
    unused_results,
    reason = "integration tests intentionally ignore helper return values like HashMap::insert"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "integration tests intentionally use panic-on-failure assertions and direct JSON indexing for endpoint behavior checks"
)]

#[path = "support/openapi_contract/mod.rs"]
mod contract;

use better_auth::BetterAuth;
use better_auth_core::entity::AuthUser;
use better_auth_core::store::UserStore;
use contract::helpers::*;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

fn test_session_cookie(token: &str, auth: &BetterAuth<TestSchema>) -> String {
    format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(token, &auth.config().secret)
    )
}

/// Helper to create test `BetterAuth` instance with memory database
async fn create_test_auth_memory() -> Arc<BetterAuth<TestSchema>> {
    TestHarness::minimal().await.into_arc()
}

/// Helper to create user and get session token
async fn create_test_user_and_session(auth: Arc<BetterAuth<TestSchema>>) -> (String, String) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "email": "integration@test.com",
            "password": "password123",
            "name": "Integration Test User"
        }),
    );
    let (status, json) = send_request(&auth, req).await;
    assert_eq!(status, 200);

    let user_id = json["user"]["id"].as_str().unwrap().to_owned();
    let session_token = json["token"].as_str().unwrap().to_owned();
    (user_id, session_token)
}

async fn user_id_from_email(auth: &Arc<BetterAuth<TestSchema>>, email: &str) -> String {
    auth.store()
        .get_user_by_email(email)
        .await
        .unwrap()
        .map_or_else(|| panic!("expected user for email {email}"), |user| user.id)
}

// ---------------------------------------------------------------------------
// API Key Plugin Integration Tests
// ---------------------------------------------------------------------------

/// Helper: create auth with `ApiKeyPlugin` and return auth + session token
async fn create_auth_with_apikey() -> (Arc<BetterAuth<TestSchema>>, String, String) {
    let auth = create_test_auth_memory().await;
    let (user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;
    (auth, user_id, session_token)
}

/// Create an API key and return (`raw_key`, `key_id`)
async fn create_api_key(
    auth: &BetterAuth<TestSchema>,
    token: &str,
    body: serde_json::Value,
) -> (String, String) {
    use better_auth::prelude::AuthRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    headers.insert("cookie".to_owned(), test_session_cookie(token, auth));
    headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

    let request = AuthRequest::from_parts(
        better_auth::prelude::HttpMethod::Post,
        "/api-key/create".to_owned(),
        headers,
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );

    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    let key = data["key"].as_str().unwrap().to_owned();
    let id = data["id"].as_str().unwrap().to_owned();
    (key, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test for get-session endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_get_session_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) =
            send_request(&auth, get_with_auth("/get-session", &session_token)).await;
        assert_eq!(status, 200);

        assert!(response_data["session"]["token"].is_string());
        assert!(response_data["user"]["id"].is_string());
        assert_eq!(response_data["user"]["email"], "integration@test.com");
    }

    /// Integration test for sign-out endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_sign_out_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) =
            send_request(&auth, post_with_auth("/sign-out", &session_token)).await;
        assert_eq!(status, 200);
        assert_eq!(response_data["success"], true);

        // Verify session is no longer valid; get-session returns 200 with null body.
        let (status2, response2) =
            send_request(&auth, get_with_auth("/get-session", &session_token)).await;
        assert_eq!(status2, 200);
        assert_eq!(response2, serde_json::Value::Null);
    }

    /// Integration test for list-sessions endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_list_sessions_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) =
            send_request(&auth, get_with_auth("/list-sessions", &session_token)).await;
        assert_eq!(status, 200);

        let sessions = response_data.as_array().expect("expected array response");
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0]["token"].is_string());
    }

    /// Integration test for revoke-session endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_revoke_session_integration() {
        use better_auth::prelude::AuthRequest;
        use better_auth::prelude::CreateSession;
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (user_id, session_token1) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create a second session for the same user

        let create_session = CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user_id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("test-agent-2".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };

        let session2 = auth.store().create_session(create_session).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token1, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let revoke_data = serde_json::json!({
            "token": session2.token
        });

        drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/revoke-session".to_owned(),
            headers,
            Some(revoke_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(response_data["status"], true);
    }

    /// Integration test for revoke-sessions endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_revoke_sessions_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) =
            send_request(&auth, post_with_auth("/revoke-sessions", &session_token)).await;
        assert_eq!(status, 200);
        assert_eq!(response_data["status"], true);
    }

    /// Integration test for unauthorized access
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_unauthorized_session_access() {
        let auth = create_test_auth_memory().await;

        // Unauthenticated get-session returns 200 with a null JSON body.
        let (status, response) = send_request(&auth, get_request("/get-session")).await;
        assert_eq!(status, 200);
        assert_eq!(response, serde_json::Value::Null);
    }

    /// Integration test for forget-password endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_forget_password_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, _session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) = send_request(
            &auth,
            post_json(
                "/request-password-reset",
                serde_json::json!({
                    "email": "integration@test.com",
                    "redirectTo": "http://localhost:3000/reset"
                }),
            ),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(response_data["status"], true);
    }

    /// Integration test for reset-password endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_reset_password_integration() {
        use better_auth::prelude::AuthRequest;
        use better_auth::prelude::CreateVerification;
        use chrono::{Duration, Utc};
        use std::collections::HashMap;
        use uuid::Uuid;

        let auth = create_test_auth_memory().await;
        let (_user_id, _session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // First, create a verification token manually

        let reset_token = format!("reset_{}", Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: format!("reset-password:{reset_token}"),
            value: user_id_from_email(&auth, "integration@test.com").await,
            expires_at: Utc::now() + Duration::hours(24),
        };
        auth.store()
            .create_verification(create_verification)
            .await
            .unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let reset_data = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/reset-password".to_owned(),
            headers,
            Some(reset_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(response_data["status"], true);
    }

    /// Integration test for change-password endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_change_password_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) = send_request(
            &auth,
            post_json_with_auth(
                "/change-password",
                serde_json::json!({
                    "currentPassword": "password123",
                    "newPassword": "NewPassword123!",
                    "revokeOtherSessions": "false"
                }),
                &session_token,
            ),
        )
        .await;
        assert_eq!(status, 200);

        assert!(response_data["user"]["id"].is_string());
        assert!(response_data["token"].is_null()); // No new token when not revoking sessions
    }

    /// Integration test for change-password with session revocation
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_change_password_with_revocation_integration() {
        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let (status, response_data) = send_request(
            &auth,
            post_json_with_auth(
                "/change-password",
                serde_json::json!({
                    "currentPassword": "password123",
                    "newPassword": "NewPassword123!",
                    "revokeOtherSessions": "true"
                }),
                &session_token,
            ),
        )
        .await;
        assert_eq!(status, 200);

        assert!(response_data["user"]["id"].is_string());
        assert!(response_data["token"].is_string()); // New token when revoking sessions
    }

    /// Integration test for reset-password token endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_reset_password_token_integration() {
        use better_auth::prelude::AuthRequest;
        use better_auth::prelude::CreateVerification;
        use chrono::{Duration, Utc};
        use std::collections::HashMap;
        use uuid::Uuid;

        let auth = create_test_auth_memory().await;
        let (_user_id, _session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create a verification token manually

        let reset_token = format!("reset_{}", Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: format!("reset-password:{reset_token}"),
            value: user_id_from_email(&auth, "integration@test.com").await,
            expires_at: Utc::now() + Duration::hours(24),
        };
        auth.store()
            .create_verification(create_verification)
            .await
            .unwrap();

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            format!("/reset-password/{reset_token}"),
            HashMap::new(),
            None,
            HashMap::from([(
                "callbackURL".to_owned(),
                "http://localhost:3000/reset".to_owned(),
            )]),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 302);
        let location = response
            .headers
            .get("Location")
            .cloned()
            .unwrap_or_default();
        assert!(location.contains("http://localhost:3000/reset"));
        assert!(location.contains(&format!("token={reset_token}")));
    }

    /// Integration test for /ok endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_ok_endpoint() {
        let auth = create_test_auth_memory().await;

        let (status, response_data) = send_request(&auth, get_request("/ok")).await;
        assert_eq!(status, 200);
        assert_eq!(response_data["ok"], true);
    }

    /// Integration test for /error endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_error_endpoint() {
        for render_error_page in [false, true] {
            let mut config = test_config();
            config.render_error_page = render_error_page;
            let auth = TestHarness::minimal_with_config(config).await.into_arc();
            for (code, description, location, rendered_code) in [
                (None, None, "/?error=UNKNOWN", "UNKNOWN"),
                (Some(""), Some(""), "/?error=UNKNOWN", "UNKNOWN"),
                (
                    Some("<script>alert(1)</script>"),
                    None,
                    "/?error=UNKNOWN",
                    "UNKNOWN",
                ),
                (Some("it's"), None, "/?error=it%27s", "it's"),
                (
                    Some("SOME_ERROR"),
                    Some("<b>space + & café</b>\r\nLocation: https://foreign.test/"),
                    "/?error=SOME_ERROR&error_description=%3Cb%3Espace+%2B+%26+caf%C3%A9%3C%2Fb%3E%0D%0ALocation%3A+https%3A%2F%2Fforeign.test%2F",
                    "SOME_ERROR",
                ),
            ] {
                let mut request = get_request("/error");
                if let Some(code) = code {
                    request.query.insert("error".into(), code.into());
                }
                if let Some(description) = description {
                    request
                        .query
                        .insert("error_description".into(), description.into());
                }
                let response = auth.handle_request(request).await.unwrap();
                if render_error_page {
                    assert_eq!(response.status, 200);
                    let html = String::from_utf8(response.body).unwrap();
                    assert!(html_text_content(&html).contains(&format!("CODE: {rendered_code}")));
                    assert!(!html.contains("<script>alert(1)</script>"));
                    if description.is_some_and(|value| !value.is_empty()) {
                        assert!(html.contains("&lt;b&gt;space + &amp; café&lt;/b&gt;"));
                    } else {
                        assert!(html.contains("We encountered an unexpected error."));
                    }
                } else {
                    assert_eq!(response.status, 302);
                    assert_eq!(
                        response.headers.get("location").map(String::as_str),
                        Some(location)
                    );
                    assert!(response.body.is_empty());
                }
            }
        }
    }

    /// Integration test for POST /get-session being gated on deferSessionRefresh
    // Upstream reference: packages/better-auth/src/api/routes/session.ts :: getSession
    // declares `method: ["GET", "POST"]` and rejects the POST form with 405 unless
    // `session.deferSessionRefresh` is enabled.
    #[tokio::test]
    async fn test_get_session_post_requires_defer_session_refresh() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/get-session".to_owned(),
            headers,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 405);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"], "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED");
    }

    /// Integration test for POST /delete-user
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_delete_user_post_method() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/delete-user".to_owned(),
            headers,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(response_data["success"], true);
    }

    /// Integration test for set-password public route absence
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_set_password_public_route_absent_for_social_user() {
        use better_auth::prelude::{AuthRequest, CreateSession, CreateUser};
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        // Create a user WITHOUT a password (social-only account)
        let create_user = CreateUser::new()
            .with_email("social@test.com")
            .with_name("Social User");
        let user = auth.store().create_user(create_user).await.unwrap();

        let create_session = CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        let session = auth.store().create_session(create_session).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session.token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let set_data = serde_json::json!({
            "newPassword": "MyNewPassword123"
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/set-password".to_owned(),
            headers,
            Some(set_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test for set-password public route remains unavailable with an existing password
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_set_password_already_has_password() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let set_data = serde_json::json!({
            "newPassword": "AnotherPassword123"
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/set-password".to_owned(),
            headers,
            Some(set_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test for set-password public route remains unavailable when unauthenticated
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_set_password_unauthenticated() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let set_data = serde_json::json!({
            "newPassword": "SomePassword123"
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/set-password".to_owned(),
            headers,
            Some(set_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test for revoke-other-sessions endpoint
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_revoke_other_sessions_integration() {
        use better_auth::prelude::{AuthRequest, CreateSession};
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (user_id, session_token1) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create a second session for the same user

        let create_session = CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user_id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("other-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        let session2 = auth.store().create_session(create_session).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token1, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/revoke-other-sessions".to_owned(),
            headers,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        // The current session should still be valid
        let s1 = auth.store().get_session(&session_token1).await.unwrap();
        assert!(s1.is_some());

        // The other session should be revoked
        let s2 = auth.store().get_session(&session2.token).await.unwrap();
        assert!(s2.is_none());
    }

    /// Integration test for cookie-based authentication
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_cookie_based_auth() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Use cookie header instead of Bearer token
        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            format!(
                "{}; other=value",
                better_auth_core::utils::cookie_utils::create_session_cookie(
                    &session_token,
                    auth.config()
                )
                .split(';')
                .next()
                .unwrap()
            ),
        );

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/get-session".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(response_data["user"]["email"], "integration@test.com");
    }

    /// A bare bearer token does not establish a core cookie session.
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_bare_bearer_cannot_override_an_invalid_session_cookie() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Provide both Bearer and cookie, but cookie has invalid token
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_owned(),
            format!("Bearer {session_token}"),
        );
        headers.insert(
            "cookie".to_owned(),
            "better-auth.session_token=invalid_token".to_owned(),
        );

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/get-session".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, serde_json::Value::Null);
        assert!(
            auth.store()
                .get_session(&session_token)
                .await
                .unwrap()
                .is_some()
        );

        let mut request_2 = AuthRequest::new(better_auth::prelude::HttpMethod::Get, "/get-session");
        request_2
            .headers
            .insert("authorization".into(), format!("Bearer {session_token}"));
        request_2
            .headers
            .insert("cookie".into(), test_session_cookie(&session_token, &auth));
        let response_2 = auth.handle_request(request_2).await.unwrap();
        let body_2: serde_json::Value = serde_json::from_slice(&response_2.body).unwrap();
        assert_eq!(body_2["session"]["token"], session_token);
    }

    /// Integration test for unauthorized password operations
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_unauthorized_password_operations() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let change_data = serde_json::json!({
            "currentPassword": "password123",
            "newPassword": "NewPassword123!"
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/change-password".to_owned(),
            headers,
            Some(change_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Integration test for change-email success
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_change_email_success() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let mut config = test_config();
        config.email_provider = Some(Arc::new(better_auth_core::email::ConsoleEmailProvider));
        let auth = TestHarness::minimal_with_config(config).await.into_arc();
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let body = serde_json::json!({ "newEmail": "newemail@test.com" });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/change-email".to_owned(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(data["status"], true);
        assert!(data.get("message").is_none());
    }

    /// Occupied mailbox changes preserve the same success shape as available addresses.
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_change_email_duplicate() {
        use better_auth::prelude::{AuthRequest, CreateUser};
        use std::collections::HashMap;

        let mut config = test_config();
        config.email_provider = Some(Arc::new(better_auth_core::email::ConsoleEmailProvider));
        let auth = TestHarness::minimal_with_config(config).await.into_arc();

        // Create first user
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create second user with a different email
        let create_user = CreateUser::new()
            .with_email("existing@test.com")
            .with_name("Existing User");
        auth.store().create_user(create_user).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let body = serde_json::json!({ "newEmail": "existing@test.com" });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/change-email".to_owned(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
            serde_json::json!({"status":true})
        );
        assert_eq!(
            auth.store()
                .get_user_by_email("existing@test.com")
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("Existing User")
        );
    }

    /// Integration test for change-email unauthenticated → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_change_email_unauthenticated() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let body = serde_json::json!({ "newEmail": "x@y.com" });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/change-email".to_owned(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Integration test for delete-user/callback success
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_delete_user_callback_success() {
        use better_auth::prelude::{AuthRequest, CreateVerification};
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create a deletion verification token
        let token = format!("delete_{}", uuid::Uuid::new_v4());
        let create_verification = CreateVerification {
            identifier: format!("delete-account-{token}"),
            value: user_id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        auth.store()
            .create_verification(create_verification)
            .await
            .unwrap();

        let mut query = HashMap::new();
        query.insert("token".to_owned(), token);

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/delete-user/callback".to_owned(),
            {
                let mut headers = HashMap::new();
                headers.insert(
                    "cookie".to_owned(),
                    test_session_cookie(&session_token, &auth),
                );
                drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));
                headers
            },
            None,
            query,
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(data["success"], true);

        // Verify user is deleted
        let user = auth.store().get_user_by_id(&user_id).await.unwrap();
        assert!(user.is_none());
    }

    /// Integration test for delete-user/callback invalid token → 404
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_delete_user_callback_invalid_token() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut query = HashMap::new();
        query.insert("token".to_owned(), "invalid_token".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/delete-user/callback".to_owned(),
            {
                let mut headers = HashMap::new();
                headers.insert(
                    "cookie".to_owned(),
                    test_session_cookie(&session_token, &auth),
                );
                drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));
                headers
            },
            None,
            query,
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test for list-accounts (empty)
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_list_accounts_empty() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (_user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/list-accounts".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let accounts: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(accounts.len(), 1); // Sign-up creates the credential account.
        assert_eq!(accounts[0]["providerId"], "credential");
    }

    /// Integration test for list-accounts with an account
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_list_accounts_with_account() {
        use better_auth::prelude::{AuthRequest, CreateAccount};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create an account for the user
        let create_account = CreateAccount {
            additional_fields: Default::default(),
            account_id: "12345".to_owned(),
            provider_id: "google".to_owned(),
            user_id: user_id.clone(),
            access_token: Some("access_token".to_owned()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("email profile".to_owned()),
            password: None,
        };
        auth.store().create_account(create_account).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/list-accounts".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let accounts: Vec<serde_json::Value> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(accounts.len(), 2);
        let google_account = accounts
            .iter()
            .find(|account| account["providerId"] == "google")
            .expect("google account should be present");
        // The pinned account parser splits stored scopes on commas; an embedded
        // space remains part of one stored scope.
        assert_eq!(
            google_account["scopes"],
            serde_json::json!(["email profile"])
        );
        // Sensitive fields should NOT be present
        assert!(google_account.get("access_token").is_none());
        assert!(google_account.get("password").is_none());
    }

    /// Integration test for unlink-account success
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_unlink_account_success() {
        use better_auth::prelude::{AuthRequest, CreateAccount};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;
        let (user_id, session_token) = create_test_user_and_session(Arc::clone(&auth)).await;

        // Create two accounts
        for provider in &["google", "github"] {
            let create_account = CreateAccount {
                additional_fields: Default::default(),
                account_id: format!("id_{provider}"),
                provider_id: provider.to_string(),
                user_id: user_id.clone(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: None,
            };
            auth.store().create_account(create_account).await.unwrap();
        }

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session_token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let google_account = auth
            .store()
            .get_user_accounts(&user_id)
            .await
            .unwrap()
            .into_iter()
            .find(|account| account.provider_id == "google")
            .unwrap();
        let unlink_data = serde_json::json!({
            "accountId": google_account.id
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/unlink-account".to_owned(),
            headers,
            Some(unlink_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify only the remaining social account and the credential account remain.
        let accounts = auth.store().get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(
            accounts
                .iter()
                .any(|account| account.provider_id == "github")
        );
        assert!(
            accounts
                .iter()
                .any(|account| account.provider_id == "credential")
        );
    }

    /// Integration test for unlink-account last credential → 400
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_unlink_last_account_fails() {
        use better_auth::prelude::{AuthRequest, CreateAccount, CreateSession, CreateUser};
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        // Create a social-only user (NO password)
        let create_user = CreateUser::new()
            .with_email("social-only@test.com")
            .with_name("Social Only");
        let user = auth.store().create_user(create_user).await.unwrap();

        let create_session = CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        let session = auth.store().create_session(create_session).await.unwrap();

        // Add one account
        let create_account = CreateAccount {
            additional_fields: Default::default(),
            account_id: "id_google".to_owned(),
            provider_id: "google".to_owned(),
            user_id: user.id.clone(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        };
        let account = auth.store().create_account(create_account).await.unwrap();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "cookie".to_owned(),
            test_session_cookie(&session.token, &auth),
        );
        drop(headers.insert("origin".to_owned(), "http://localhost:3000".to_owned()));

        let unlink_data = serde_json::json!({
            "accountId": account.id
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/unlink-account".to_owned(),
            headers,
            Some(unlink_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 400); // Cannot unlink last credential
    }

    /// Integration test for list-accounts unauthenticated → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_list_accounts_unauthenticated() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/list-accounts".to_owned(),
            HashMap::new(),
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    // ---------------------------------------------------------------------------
    // Username Support Tests (Stage 1.7)
    // ---------------------------------------------------------------------------

    /// Sign up with username, then sign in by username
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_sign_up_with_username_and_sign_in() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        // Sign up with username
        let signup_data = serde_json::json!({
            "email": "usernameguy@test.com",
            "password": "password123",
            "name": "Username Guy",
            "username": "cool_user",
            "displayUsername": "Cool User"
        });

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-up/email".to_owned(),
            headers.clone(),
            Some(signup_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(data["user"]["username"], "cool_user");
        assert_eq!(data["user"]["displayUsername"], "Cool User");

        // Now sign in by username
        let signin_data = serde_json::json!({
            "username": "cool_user",
            "password": "password123"
        });

        let request_2 = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-in/username".to_owned(),
            headers,
            Some(signin_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response_2 = auth.handle_request(request_2).await.unwrap();
        assert_eq!(response_2.status, 200);

        let body_str_2 = String::from_utf8(response_2.body).unwrap();
        let data_2: serde_json::Value = serde_json::from_str(&body_str_2).unwrap();
        assert!(data_2["token"].is_string());
        assert_eq!(data_2["user"]["username"], "cool_user");
        assert_eq!(data_2["user"]["email"], "usernameguy@test.com");
    }

    /// Sign in by username with wrong password → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_sign_in_username_wrong_password() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        // Sign up with username
        let signup_data = serde_json::json!({
            "email": "wrongpw@test.com",
            "password": "password123",
            "name": "Wrong PW",
            "username": "wrongpw_user"
        });

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-up/email".to_owned(),
            headers.clone(),
            Some(signup_data.to_string().into_bytes()),
            HashMap::new(),
        );

        auth.handle_request(request).await.unwrap();

        // Sign in with wrong password
        let signin_data = serde_json::json!({
            "username": "wrongpw_user",
            "password": "wrong_password"
        });

        let request_2 = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-in/username".to_owned(),
            headers,
            Some(signin_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request_2).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Sign in by nonexistent username → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_sign_in_username_nonexistent() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let signin_data = serde_json::json!({
            "username": "no_such_user",
            "password": "password123"
        });

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-in/username".to_owned(),
            headers,
            Some(signin_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Integration test: create API key
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_create() {
        let (auth, _user_id, token) = create_auth_with_apikey().await;

        let (key, id) = create_api_key(
            &auth,
            &token,
            serde_json::json!({
                "name": "test-key",
                "prefix": "sk_"
            }),
        )
        .await;

        assert!(!key.is_empty(), "key should not be empty");
        assert!(key.starts_with("sk_"), "key should start with prefix");
        assert!(!id.is_empty(), "id should not be empty");
    }

    /// Integration test: create API key with remaining and expiry
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_create_with_options() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let body = serde_json::json!({
            "name": "limited-key",
            "prefix": "lk_",
            "expiresIn": 3_600_000
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/create".to_owned(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert!(data["key"].is_string());
        assert_eq!(data["name"], "limited-key");
        assert_eq!(data["prefix"], "lk_");
        assert!(data["expiresAt"].is_string());
    }

    /// Integration test: get API key by ID
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_get() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token, serde_json::json!({"name": "get-test"})).await;

        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let mut query = HashMap::new();
        query.insert("id".to_owned(), id.clone());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/get".to_owned(),
            headers,
            None,
            query,
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(data["id"], id);
        assert_eq!(data["name"], "get-test");
        assert!(data["enabled"].as_bool().unwrap());
        // key_hash should NOT be in the response
        assert!(data.get("keyHash").is_none());
        assert!(data.get("key_hash").is_none());
    }

    /// Integration test: list API keys
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_list() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;

        // Create two keys
        create_api_key(&auth, &token, serde_json::json!({"name": "key-1"})).await;
        create_api_key(&auth, &token, serde_json::json!({"name": "key-2"})).await;

        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/list".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        // `/api-key/list` returns a paginated envelope: { apiKeys, total, .. }
        let envelope: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        let data = envelope["apiKeys"].as_array().unwrap().clone();

        assert_eq!(data.len(), 2);
    }

    /// Integration test: update API key
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_update() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token, serde_json::json!({"name": "original-name"})).await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let update_body = serde_json::json!({
            "keyId": id,
            "name": "updated-name",
            "enabled": false
        });

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/update".to_owned(),
            headers,
            Some(update_body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(data["id"], id);
        assert_eq!(data["name"], "updated-name");
        assert_eq!(data["enabled"], false);
    }

    /// Integration test: deleting a user removes the API keys they own
    // Rust-specific surface: api keys reference their owner polymorphically, so no
    // database cascade covers this; the store has to clean up explicitly.
    #[tokio::test]
    async fn test_delete_user_removes_their_api_keys() {
        let (auth, user_id, token) = create_auth_with_apikey().await;
        let (_key, key_id) =
            create_api_key(&auth, &token, serde_json::json!({"name": "orphan-me"})).await;

        assert!(
            auth.store()
                .get_api_key_by_id(&key_id)
                .await
                .unwrap()
                .is_some()
        );

        auth.store().delete_user(&user_id).await.unwrap();

        assert!(
            auth.store()
                .get_api_key_by_id(&key_id)
                .await
                .unwrap()
                .is_none(),
            "a deleted user must not leave usable credentials behind"
        );
    }

    /// Integration test: delete API key
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_delete() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token, serde_json::json!({"name": "delete-me"})).await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let delete_body = serde_json::json!({"keyId": id});

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/delete".to_owned(),
            headers,
            Some(delete_body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(data["success"], true);

        // Verify it's gone by listing
        let mut headers2 = HashMap::new();
        headers2.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers2.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let list_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/list".to_owned(),
            headers2,
            None,
            HashMap::new(),
        );

        let list_response = auth.handle_request(list_request).await.unwrap();
        let list_envelope: serde_json::Value = serde_json::from_slice(&list_response.body).unwrap();
        assert_eq!(list_envelope["apiKeys"].as_array().unwrap().len(), 0);
        assert_eq!(list_envelope["total"], 0);
    }

    /// Integration test: unauthenticated create → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_create_unauthenticated() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let body = serde_json::json!({"name": "no-auth"});

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/create".to_owned(),
            headers,
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Integration test: unauthenticated list → 401
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_list_unauthenticated() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let auth = create_test_auth_memory().await;

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/list".to_owned(),
            HashMap::new(),
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 401);
    }

    /// Integration test: get key owned by another user → 404
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_get_other_users_key() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token1) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token1, serde_json::json!({"name": "user1-key"})).await;

        // Create a second user

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let signup_data = serde_json::json!({
            "email": "user2@test.com",
            "password": "password123",
            "name": "Second User"
        });

        let signup_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-up/email".to_owned(),
            headers,
            Some(signup_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let signup_resp = auth.handle_request(signup_request).await.unwrap();
        let signup_body: serde_json::Value = serde_json::from_slice(&signup_resp.body).unwrap();
        let token2 = signup_body["token"].as_str().unwrap();

        // Try to get user1's key with user2's token
        let mut headers2 = HashMap::new();
        headers2.insert("cookie".to_owned(), test_session_cookie(token2, &auth));
        headers2.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let mut query = HashMap::new();
        query.insert("id".to_owned(), id.clone());

        let get_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/get".to_owned(),
            headers2,
            None,
            query,
        );

        let response = auth.handle_request(get_request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test: delete key owned by another user → 404
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_delete_other_users_key() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token1) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token1, serde_json::json!({"name": "user1-key"})).await;

        // Create a second user

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let signup_data = serde_json::json!({
            "email": "user3@test.com",
            "password": "password123",
            "name": "Third User"
        });

        let signup_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-up/email".to_owned(),
            headers,
            Some(signup_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let signup_resp = auth.handle_request(signup_request).await.unwrap();
        let signup_body: serde_json::Value = serde_json::from_slice(&signup_resp.body).unwrap();
        let token2 = signup_body["token"].as_str().unwrap();

        // Try to delete user1's key with user2's token
        let mut headers2 = HashMap::new();
        headers2.insert("content-type".to_owned(), "application/json".to_owned());
        headers2.insert("cookie".to_owned(), test_session_cookie(token2, &auth));
        headers2.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let delete_body = serde_json::json!({"keyId": id});

        let delete_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/delete".to_owned(),
            headers2,
            Some(delete_body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(delete_request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test: update key owned by another user → 404
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_update_other_users_key() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token1) = create_auth_with_apikey().await;
        let (_key, id) =
            create_api_key(&auth, &token1, serde_json::json!({"name": "user1-key"})).await;

        // Create a second user

        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());

        let signup_data = serde_json::json!({
            "email": "user4@test.com",
            "password": "password123",
            "name": "Fourth User"
        });

        let signup_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/sign-up/email".to_owned(),
            headers,
            Some(signup_data.to_string().into_bytes()),
            HashMap::new(),
        );

        let signup_resp = auth.handle_request(signup_request).await.unwrap();
        let signup_body: serde_json::Value = serde_json::from_slice(&signup_resp.body).unwrap();
        let token2 = signup_body["token"].as_str().unwrap();

        // Try to update user1's key with user2's token
        let mut headers2 = HashMap::new();
        headers2.insert("content-type".to_owned(), "application/json".to_owned());
        headers2.insert("cookie".to_owned(), test_session_cookie(token2, &auth));
        headers2.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let update_body = serde_json::json!({
            "keyId": id,
            "name": "hijacked-name"
        });

        let update_request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Post,
            "/api-key/update".to_owned(),
            headers2,
            Some(update_body.to_string().into_bytes()),
            HashMap::new(),
        );

        let response = auth.handle_request(update_request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// Integration test: list keys for user with no keys → empty array
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_list_empty() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;

        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/list".to_owned(),
            headers,
            None,
            HashMap::new(),
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 200);

        let envelope: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(envelope["apiKeys"].as_array().unwrap().len(), 0);
        assert_eq!(envelope["total"], 0);
    }

    /// Integration test: get key with missing 'id' query param → 400
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_get_missing_id() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;

        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/get".to_owned(),
            headers,
            None,
            HashMap::new(),
        ); // no 'id' param

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 400);
    }

    /// Integration test: get nonexistent key → 404
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_api_key_get_nonexistent() {
        use better_auth::prelude::AuthRequest;
        use std::collections::HashMap;

        let (auth, _user_id, token) = create_auth_with_apikey().await;

        let mut headers = HashMap::new();
        headers.insert("cookie".to_owned(), test_session_cookie(&token, &auth));
        headers.insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let mut query = HashMap::new();
        query.insert("id".to_owned(), "nonexistent-id".to_owned());

        let request = AuthRequest::from_parts(
            better_auth::prelude::HttpMethod::Get,
            "/api-key/get".to_owned(),
            headers,
            None,
            query,
        );

        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, 404);
    }

    /// `get_user_by_username` works via database adapter
    // Upstream source: packages/better-auth/src/api/routes public endpoint handler matching this request path; adapted to the Rust integration endpoint case.
    #[tokio::test]
    async fn test_get_user_by_username_adapter() {
        use better_auth::prelude::CreateUser;
        use better_auth_seaorm::{Database, SeaOrmStore};
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let db = SeaOrmStore::<TestSchema>::new(
            Arc::new(better_auth::AuthConfig::new(
                "test-secret-key-that-is-at-least-32-characters-long",
            )),
            database,
        );

        // Create user with username
        let create = CreateUser::new()
            .with_email("dbtest@test.com")
            .with_name("DB Test")
            .with_username("db_user");

        let user = db.create_user(create).await.unwrap();

        // Lookup by username
        let found = db.get_user_by_username("db_user").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), user.id());

        // Lookup nonexistent
        let not_found = db.get_user_by_username("no_user").await.unwrap();
        assert!(not_found.is_none());
    }
}
