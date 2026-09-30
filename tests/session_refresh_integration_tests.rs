//! Persisted expiry, deferred writes and authoritative session boundaries.
#![expect(
    clippy::unwrap_used,
    reason = "integration setup and successful endpoints"
)]

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
    _ = req.headers.insert("origin".into(), ORIGIN.into());
    _ = req.headers.insert("cookie".into(), cookie.into());
    if let Some(body) = body {
        _ = req
            .headers
            .insert("content-type".into(), "application/json".into());
        req.body = Some(serde_json::to_vec(&body).unwrap());
    }
    let response = auth.handle_request(req).await.unwrap();
    let body = serde_json::from_slice(&response.body).unwrap();
    (response, body)
}

#[tokio::test]
async fn expiry_based_refresh_returns_the_persisted_snapshot_and_renews_cookie_once() {
    let (auth, _) = fixture(false, false).await;
    let (user, token, cookie) = issued(&auth, "expiry@session.fixture.test").await;
    let stale_expiry = Utc::now() + Duration::hours(1);
    auth.store()
        .update_session_expiry(&token, stale_expiry)
        .await
        .unwrap();
    let before = auth.store().get_session(&token).await.unwrap().unwrap();
    assert!(before.updated_at() > Utc::now() - Duration::seconds(5));
    let (response, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(response.status, 200, "{value}");
    let stored = auth.store().get_session(&token).await.unwrap().unwrap();
    assert_eq!(stored.id(), before.id());
    assert_eq!(stored.token(), token);
    assert_eq!(stored.user_id().as_ref(), user);
    assert!(stored.expires_at() > stale_expiry + Duration::days(6));
    assert_eq!(
        value["session"]["expiresAt"],
        json!(
            stored
                .expires_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        )
    );
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|header| header.contains("Max-Age=604800"))
    );
    let (again, repeated) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(repeated, value);
    assert!(again.headers.get_all("set-cookie").next().is_none());
}

#[tokio::test]
async fn deferred_get_is_read_only_and_post_updates_and_cleans_expired_rows() {
    let (auth, _) = fixture(true, false).await;
    let (_, token, cookie) = issued(&auth, "deferred@session.fixture.test").await;
    auth.store()
        .update_session_expiry(&token, Utc::now() + Duration::hours(1))
        .await
        .unwrap();
    let before = auth.store().get_session(&token).await.unwrap().unwrap();
    let (get, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(get.status, 200);
    assert_eq!(value["needsRefresh"], true);
    assert_eq!(
        auth.store()
            .get_session(&token)
            .await
            .unwrap()
            .unwrap()
            .expires_at(),
        before.expires_at()
    );
    let (post, value) = request(
        &auth,
        HttpMethod::Post,
        "/get-session",
        &cookie,
        Some(json!({})),
    )
    .await;
    assert_eq!(post.status, 200, "{value}");
    assert!(value.get("needsRefresh").is_none());
    assert!(
        auth.store()
            .get_session(&token)
            .await
            .unwrap()
            .unwrap()
            .expires_at()
            > before.expires_at() + Duration::days(6)
    );
    auth.store()
        .update_session_expiry(&token, Utc::now() - Duration::seconds(1))
        .await
        .unwrap();
    let (get, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(value, Value::Null);
    assert_eq!(get.headers.get_all("set-cookie").count(), 3);
    assert!(auth.store().get_session(&token).await.unwrap().is_some());
    let (post, value) = request(
        &auth,
        HttpMethod::Post,
        "/get-session",
        &cookie,
        Some(json!({})),
    )
    .await;
    assert_eq!(post.status, 200);
    assert_eq!(value, Value::Null);
    assert!(auth.store().get_session(&token).await.unwrap().is_none());
}

#[tokio::test]
async fn expired_nested_middleware_forwards_cleanup_cookies_and_respects_deferral() {
    for deferred in [false, true] {
        let (auth, _) = fixture(deferred, false).await;
        let (_, token, cookie) = issued(&auth, "expired@session.fixture.test").await;
        auth.store()
            .update_session_expiry(&token, Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        let (response, value) =
            request(&auth, HttpMethod::Get, "/list-sessions", &cookie, None).await;
        assert_eq!(response.status, 401, "{value}");
        assert_eq!(value["code"], "UNAUTHORIZED");
        assert_eq!(response.headers.get_all("set-cookie").count(), 3);
        assert!(
            response
                .headers
                .get_all("set-cookie")
                .all(|cookie| cookie.contains("Max-Age=0"))
        );
        assert_eq!(
            auth.store().get_session(&token).await.unwrap().is_some(),
            deferred
        );
    }
}

#[tokio::test]
async fn concurrent_deletion_during_refresh_never_returns_a_revoked_session() {
    let (auth, db) = fixture(false, false).await;
    let (_, token, cookie) = issued(&auth, "revocation-race@session.fixture.test").await;
    auth.store()
        .update_session_expiry(&token, Utc::now() + Duration::hours(1))
        .await
        .unwrap();
    _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER revoke_on_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN DELETE FROM sessions WHERE token = OLD.token; SELECT RAISE(IGNORE); END".to_owned())).await.unwrap();
    let (response, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(response.status, 401, "{value}");
    assert_eq!(
        value,
        json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
    );
    assert_eq!(response.headers.get_all("set-cookie").count(), 3);
    assert!(auth.store().get_session(&token).await.unwrap().is_none());
}

#[tokio::test]
async fn failed_refresh_reports_upstream_error_instead_of_authenticating_the_old_snapshot() {
    let (auth, db) = fixture(false, false).await;
    let (_, token, cookie) = issued(&auth, "write-error@session.fixture.test").await;
    let expiry = Utc::now() + Duration::hours(1);
    auth.store()
        .update_session_expiry(&token, expiry)
        .await
        .unwrap();
    _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER fail_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN SELECT RAISE(ABORT, 'fixture refresh failure'); END".to_owned())).await.unwrap();
    let (response, value) = request(&auth, HttpMethod::Get, "/get-session", &cookie, None).await;
    assert_eq!(response.status, 500, "{value}");
    assert_eq!(
        value,
        json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
    );
    assert_eq!(
        auth.store()
            .get_session(&token)
            .await
            .unwrap()
            .unwrap()
            .expires_at(),
        expiry
    );
    assert!(response.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        response.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        response.headers.get("pragma").map(String::as_str),
        Some("no-cache")
    );
}

#[tokio::test]
async fn authoritative_revocation_bypasses_virtual_sessions_and_preserves_foreign_expiry() {
    let (auth, _) = fixture(false, false).await;
    let (_, owner_token, owner_cookie) = issued(&auth, "owner@session.fixture.test").await;
    let (_, foreign_token, _) = issued(&auth, "foreign@session.fixture.test").await;
    let expiry = Utc::now() + Duration::hours(1);
    auth.store()
        .update_session_expiry(&foreign_token, expiry)
        .await
        .unwrap();
    let foreign = auth
        .store()
        .get_session(&foreign_token)
        .await
        .unwrap()
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Post, "/revoke-session");
    request.set_virtual_session(auth.context().session_view(&foreign));
    assert!(
        auth.context()
            .require_authoritative_session(&request)
            .await
            .is_err()
    );
    _ = request
        .headers
        .insert("cookie".into(), owner_cookie.clone());
    let (_, authenticated) = auth
        .context()
        .require_authoritative_session(&request)
        .await
        .unwrap();
    assert_eq!(authenticated.token, owner_token);
    let (response, value) = self::request(
        &auth,
        HttpMethod::Post,
        "/revoke-session",
        &owner_cookie,
        Some(json!({"token":foreign_token})),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(value, json!({"status":true}));
    assert_eq!(
        auth.store()
            .get_session(&foreign_token)
            .await
            .unwrap()
            .unwrap()
            .expires_at(),
        expiry
    );
}
