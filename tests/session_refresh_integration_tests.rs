#![cfg(test)]
//! Persisted expiry, deferred writes and authoritative session boundaries.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "session_refresh_integration_tests/tests.rs"]
mod tests;

use better_auth::plugins::SessionManagementPlugin;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, AuthSession, AuthUser, CreateUser, HttpMethod};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://session.fixture.test";

async fn fixture(deferred: bool, disabled: bool) -> (BetterAuth<Schema>, DatabaseConnection) {
    let mut config =
        AuthConfig::new("session-fixture-secret-at-least-32-characters").base_url(ORIGIN);
    config.session.defer_session_refresh = deferred;
    config.session.disable_session_refresh = disabled;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db.clone()))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    (auth, db)
}

async fn issued(auth: &BetterAuth<Schema>, email: &str) -> (String, String, String) {
    let user = auth
        .store()
        .create_user(CreateUser::new().with_email(email))
        .await
        .unwrap();
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
        session.token(),
        auth.config(),
    );
    (
        user.id().into_owned(),
        session.token().to_owned(),
        cookie.split(';').next().unwrap().to_owned(),
    )
}

async fn request(
    auth: &BetterAuth<Schema>,
    method: HttpMethod,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(method, format!("/api/auth{path}"));
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(req.headers.insert("cookie".into(), cookie.into()));
    if let Some(body) = body {
        drop(
            req.headers
                .insert("content-type".into(), "application/json".into()),
        );
        req.body = Some(serde_json::to_vec(&body).unwrap());
    }
    let response = auth.handle_request(req).await.unwrap();
    let body_2 = serde_json::from_slice(&response.body).unwrap();
    (response, body_2)
}
