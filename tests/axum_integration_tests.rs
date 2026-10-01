#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![cfg(feature = "axum")]

#[cfg(test)]
#[path = "axum_integration_tests/tests.rs"]
mod tests;

use axum::{
    body::Body,
    extract::{FromRef, State},
    http::{Method, Request, StatusCode},
};
use better_auth::integrations::axum::{AxumIntegration, CurrentSession, OptionalSession};
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, UserManagementPlugin, password_management::SendResetPassword,
};
use better_auth::prelude::AuthUser;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_seaorm::{Database, DatabaseConnection, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
// for oneshot
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    auth: Arc<BetterAuth<TestSchema>>,
    app_name: &'static str,
}

impl FromRef<AppState> for Arc<BetterAuth<TestSchema>> {
    fn from_ref(input: &AppState) -> Self {
        Self::clone(&input.auth)
    }
}

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

fn test_session_cookie(token: &str) -> String {
    format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            token,
            "test-secret-key-that-is-at-least-32-characters-long"
        )
    )
}

/// Helper to create test `BetterAuth` instance with all plugins
async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    database
}

async fn create_test_auth() -> Arc<BetterAuth<TestSchema>> {
    create_test_auth_with_config(
        AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .password_min_length(6),
    )
    .await
}

async fn create_test_auth_with_config(config: AuthConfig) -> Arc<BetterAuth<TestSchema>> {
    struct NoopResetSender;

    #[async_trait::async_trait]
    impl SendResetPassword for NoopResetSender {
        async fn send(
            &self,
            _user: &Value,
            _url: &str,
            _token: &str,
        ) -> better_auth::AuthResult<()> {
            Ok(())
        }
    }

    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);
    Arc::new(
        AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new().send_reset_password(Arc::new(NoopResetSender)))
            .plugin(EmailVerificationPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .build()
            .await
            .expect("Failed to create test auth instance"),
    )
}

/// Helper to create the complete Axum router (mimics the example server)
fn create_test_router(auth: Arc<BetterAuth<TestSchema>>) -> axum::Router {
    use axum::Router;

    // Create auth router using the BetterAuth AxumIntegration
    let auth_router = Arc::clone(&auth).axum_router();

    // Create main application router
    Router::new()
        // Mount auth routes under /auth prefix
        .nest("/auth", auth_router)
        // Add CORS layer
        .layer(CorsLayer::permissive())
        .with_state(auth)
}

fn create_extractor_test_router(auth: Arc<BetterAuth<TestSchema>>) -> axum::Router {
    use axum::{Json, Router, routing::get};

    async fn current_session_route(session: CurrentSession<TestSchema>) -> Json<Value> {
        Json(json!({
            "authenticated": true,
            "userId": session.user.id,
        }))
    }

    async fn optional_session_route(session: OptionalSession<TestSchema>) -> Json<Value> {
        Json(json!({
            "authenticated": session.0.is_some(),
        }))
    }

    Router::new()
        .nest("/auth", Arc::clone(&auth).axum_router())
        .route("/current-session", get(current_session_route))
        .route("/optional-session", get(optional_session_route))
        .layer(CorsLayer::permissive())
        .with_state(auth)
}

fn create_app_state_test_router(auth: Arc<BetterAuth<TestSchema>>) -> axum::Router {
    use axum::{Json, Router, routing::get};

    async fn current_session_route(
        State(state): State<AppState>,
        session: CurrentSession<TestSchema>,
    ) -> Json<Value> {
        Json(json!({
            "app": state.app_name,
            "authenticated": true,
            "userId": session.user.id(),
        }))
    }

    async fn optional_session_route(
        State(state): State<AppState>,
        session: OptionalSession<TestSchema>,
    ) -> Json<Value> {
        Json(json!({
            "app": state.app_name,
            "authenticated": session.0.is_some(),
        }))
    }

    let state = AppState {
        auth: Arc::clone(&auth),
        app_name: "test-app",
    };

    Router::new()
        .nest("/auth", auth.axum_router_with_state::<AppState>())
        .route("/current-session", get(current_session_route))
        .route("/optional-session", get(optional_session_route))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Helper to create a user and return user data + session token
async fn create_test_user(router: axum::Router) -> (Value, String) {
    let signup_data = json!({
        "email": "test@example.com",
        "password": "password123",
        "name": "Test User"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-up/email")
        .header("content-type", "application/json")
        .body(Body::from(signup_data.to_string()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK); // BetterAuth returns 200, not 201

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_data: Value = serde_json::from_slice(&body_bytes).unwrap();

    let token = (*(response_data).get("token").unwrap_or(&Value::Null))
        .as_str()
        .unwrap()
        .to_owned();
    (response_data, token)
}
