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

#[path = "support/compat/mod.rs"]
mod compat;

#[cfg(test)]
#[path = "integration_tests/tests.rs"]
mod tests;

use better_auth::BetterAuth;
use better_auth_core::entity::AuthUser;
use better_auth_core::store::UserStore;
use compat::helpers::*;
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
