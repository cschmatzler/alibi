use super::*;
use better_auth_core::AuthContext;
use better_auth_core::config::AuthConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn create_test_context() -> AuthContext<TestSchema> {
    let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
    let config = Arc::new(config);
    let database = crate::plugins::test_helpers::create_test_database().await;
    AuthContext::new(config, database)
}

fn create_signup_request(email: &str, password: &str) -> AuthRequest {
    let body = serde_json::json!({
        "name": "Test User",
        "email": email,
        "password": password,
    });
    AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".to_owned(),
        HashMap::new(),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    )
}

// Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
#[tokio::test]
async fn test_auto_sign_in_false_returns_no_session() {
    let plugin = EmailPasswordPlugin::new().auto_sign_in(false);
    let ctx = create_test_context().await;

    let req = create_signup_request("auto@example.com", "Password123!");
    let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Response should NOT have a Set-Cookie header
    let has_cookie = response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
    assert!(!has_cookie, "auto_sign_in=false should not set a cookie");

    // Response body token should be null
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_null(),
        "auto_sign_in=false should return null token"
    );
    // But the user should still be created
    assert!(
        (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null))
        .is_string()
    );
}

// Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
#[tokio::test]
async fn test_auto_sign_in_true_returns_session() {
    let plugin = EmailPasswordPlugin::new(); // default auto_sign_in=true
    let ctx = create_test_context().await;

    let req = create_signup_request("autotrue@example.com", "Password123!");
    let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Response SHOULD have a Set-Cookie header
    let has_cookie = response
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
    assert!(has_cookie, "auto_sign_in=true should set a cookie");

    // Response body token should be a string
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_string(),
        "auto_sign_in=true should return a session token"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
#[tokio::test]
async fn test_password_max_length_rejection() {
    let plugin = EmailPasswordPlugin::new().password_max_length(128);
    let ctx = create_test_context().await;

    // Password of exactly 129 chars should be rejected
    let long_password = format!("A1!{}", "a".repeat(126)); // 129 chars total
    let req = create_signup_request("long@example.com", &long_password);
    let err = plugin.handle_sign_up(&req, &ctx).await.unwrap_err();
    assert_eq!(err.status_code(), 400);

    // Password of exactly 128 chars should be accepted
    let ok_password = format!("A1!{}", "a".repeat(125)); // 128 chars total
    let req_2 = create_signup_request("ok@example.com", &ok_password);
    let response = plugin.handle_sign_up(&req_2, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
}

// Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
#[tokio::test]
async fn test_custom_password_hasher() {
    /// A simple test hasher that prefixes the password with "hashed:"
    struct TestHasher;

    #[async_trait]
    impl PasswordHasher for TestHasher {
        async fn hash(&self, password: &str) -> AuthResult<String> {
            Ok(format!("hashed:{password}"))
        }
        async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
            Ok(hash == format!("hashed:{password}"))
        }
    }

    let hasher: Arc<dyn PasswordHasher> = Arc::new(TestHasher);
    let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
    let ctx = create_test_context().await;

    // Sign up with custom hasher
    let req = create_signup_request("hasher@example.com", "Password123!");
    let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    // Verify the stored hash uses our custom hasher
    let user = ctx
        .database
        .get_user_by_email("hasher@example.com")
        .await
        .unwrap()
        .unwrap();
    let stored_hash = ctx
        .database
        .get_user_accounts(&user.id())
        .await
        .unwrap()
        .into_iter()
        .find(|account| account.provider_id() == "credential")
        .and_then(|account| account.password().map(str::to_owned))
        .expect("credential account should store hashed password");
    assert_eq!(stored_hash, "hashed:Password123!");

    // Sign in should work with the custom hasher
    let signin_body = serde_json::json!({
        "email": "hasher@example.com",
        "password": "Password123!",
    });
    let signin_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-in/email".to_owned(),
        HashMap::new(),
        Some(signin_body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response_2 = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
    assert_eq!(response_2.status, 200);

    // Sign in with wrong password should fail
    let bad_body = serde_json::json!({
        "email": "hasher@example.com",
        "password": "WrongPassword!",
    });
    let bad_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-in/email".to_owned(),
        HashMap::new(),
        Some(bad_body.to_string().into_bytes()),
        HashMap::new(),
    );
    let err = plugin.handle_sign_in(&bad_req, &ctx).await.unwrap_err();
    assert_eq!(err.to_string(), AuthError::InvalidCredentials.to_string());
}

// Upstream reference: packages/better-auth/src/plugins/username/index.ts :: sign-in path verifies the password once before creating a session; adapted to ensure the Rust username path does not duplicate expensive password verification.
#[tokio::test]
async fn test_sign_in_username_verifies_password_once() {
    struct CountingHasher {
        verify_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PasswordHasher for CountingHasher {
        async fn hash(&self, password: &str) -> AuthResult<String> {
            Ok(format!("hashed:{password}"))
        }

        async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(hash == format!("hashed:{password}"))
        }
    }

    let verify_calls = Arc::new(AtomicUsize::new(0));
    let hasher: Arc<dyn PasswordHasher> = Arc::new(CountingHasher {
        verify_calls: std::sync::Arc::clone(&verify_calls),
    });
    let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
    let ctx = create_test_context().await;

    let signup_body = serde_json::json!({
        "email": "username-counter@example.com",
        "password": "Password123!",
        "name": "Counter User",
        "username": "Counter_User",
    });
    let signup_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".to_owned(),
        HashMap::new(),
        Some(signup_body.to_string().into_bytes()),
        HashMap::new(),
    );
    let signup_response = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
    assert_eq!(signup_response.status, 200);

    verify_calls.store(0, Ordering::SeqCst);

    let signin_body = serde_json::json!({
        "username": "COUNTER_USER",
        "password": "Password123!",
    });
    let signin_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-in/username".to_owned(),
        HashMap::new(),
        Some(signin_body.to_string().into_bytes()),
        HashMap::new(),
    );
    let signin_response = plugin
        .handle_sign_in_username(&signin_req, &ctx)
        .await
        .unwrap();
    assert_eq!(signin_response.status, 200);
    assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
}

// Rust-specific surface: route-table registration for the endpoint declared in
// packages/better-auth/src/plugins/username/index.ts :: isUsernameAvailable.
#[tokio::test]
async fn test_is_username_available_route_registered() {
    let plugin = EmailPasswordPlugin::new();
    let routes = <EmailPasswordPlugin as AuthPlugin<TestSchema>>::routes(&plugin);
    assert!(
        routes.iter().any(|r| r.path == "/is-username-available"),
        "route /is-username-available should be registered"
    );
}

// Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
// isUsernameAvailable returns `{ available: true }` when no user holds the
// normalized username; adapted to the Rust email-password plugin.
#[tokio::test]
async fn test_is_username_available_fresh() {
    let plugin = EmailPasswordPlugin::new();
    let ctx = create_test_context().await;

    let body = serde_json::json!({ "username": "fresh_user" });
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/is-username-available".to_owned(),
        HashMap::new(),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response = plugin
        .handle_is_username_available(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
        true
    );
}

// Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
// isUsernameAvailable returns `{ available: false }` when the adapter finds a
// user on the normalized username; adapted to the Rust email-password plugin.
#[tokio::test]
async fn test_is_username_available_taken() {
    let plugin = EmailPasswordPlugin::new();
    let ctx = create_test_context().await;

    // Sign up a user with a username
    let signup_body = serde_json::json!({
        "name": "Taken User",
        "email": "taken@example.com",
        "password": "Password123!",
        "username": "taken_user",
    });
    let signup_req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".to_owned(),
        HashMap::new(),
        Some(signup_body.to_string().into_bytes()),
        HashMap::new(),
    );
    let resp = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
    assert_eq!(resp.status, 200);

    let body = serde_json::json!({ "username": "taken_user" });
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/is-username-available".to_owned(),
        HashMap::new(),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response = plugin
        .handle_is_username_available(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
        false
    );
}

// Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
// isUsernameAvailable throws UNPROCESSABLE_ENTITY with code USERNAME_TOO_SHORT
// below `minUsernameLength` (default 3); adapted to the Rust email-password plugin.
#[tokio::test]
async fn test_is_username_available_too_short() {
    let plugin = EmailPasswordPlugin::new();
    let ctx = create_test_context().await;

    let body = serde_json::json!({ "username": "ab" });
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/is-username-available".to_owned(),
        HashMap::new(),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response = plugin
        .handle_is_username_available(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 422);
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
        "USERNAME_TOO_SHORT"
    );
}

// Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
// isUsernameAvailable rejects usernames that fail `defaultUsernameValidator`
// with UNPROCESSABLE_ENTITY; adapted to the Rust email-password plugin.
#[tokio::test]
async fn test_is_username_available_invalid_chars() {
    let plugin = EmailPasswordPlugin::new();
    let ctx = create_test_context().await;

    let body = serde_json::json!({ "username": "bad user!" });
    let req = AuthRequest::from_parts(
        HttpMethod::Post,
        "/is-username-available".to_owned(),
        HashMap::new(),
        Some(body.to_string().into_bytes()),
        HashMap::new(),
    );
    let response = plugin
        .handle_is_username_available(&req, &ctx)
        .await
        .unwrap();
    assert_eq!(response.status, 422);
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
        "INVALID_USERNAME"
    );
}
