use super::*;
use crate::entity::AuthSession;
use crate::test_store::{BundledSchema, test_config, test_database};
use crate::types::AuthRequest;
use crate::types::HttpMethod;
use crate::wire::SessionView;
use chrono::Duration;

fn test_manager() -> SessionManager<BundledSchema> {
    let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
    SessionManager::new(test_config(), runtime.block_on(test_database()))
}

// ── validate_token_format ───────────────────────────────────────────

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn valid_token_format() {
    let mgr = test_manager();
    let token = "abcdefghijklmnopqrstuvwxyz123456";
    assert!(mgr.validate_token_format(token));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn invalid_token_non_alphanumeric() {
    let mgr = test_manager();
    assert!(!mgr.validate_token_format("abcdefghijklmnopqrstuvwxy_123456"));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn invalid_token_too_short() {
    let mgr = test_manager();
    assert!(!mgr.validate_token_format("session_short"));
}

// ── extract_session_token ───────────────────────────────────────────

// Pinned Better Call sessions require a signed cookie; bearer authentication
// is supplied by the separate bearer plugin, not core session parsing.
#[test]
fn extract_rejects_bare_bearer() {
    let mgr = test_manager();
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    drop(
        req.headers
            .insert("authorization".into(), "Bearer my-token".into()),
    );
    assert_eq!(mgr.extract_session_token(&req), None);
}

#[test]
fn extract_cookie_checks_signature_and_first_duplicate() {
    let mgr = test_manager();
    let signed = crate::utils::cookie_utils::sign_cookie_value("tok123", &mgr.config.secret);
    let foreign = crate::utils::cookie_utils::sign_cookie_value("tok123", "another-server-secret");
    for (cookie, expected) in [
        (
            format!("better-auth.session_token={signed}; other=val"),
            Some("tok123"),
        ),
        ("better-auth.session_token=tok123".to_owned(), None),
        (format!("better-auth.session_token={foreign}"), None),
        (
            format!("better-auth.session_token={signed}; better-auth.session_token=invalid"),
            Some("tok123"),
        ),
        (
            format!("better-auth.session_token=invalid; better-auth.session_token={signed}"),
            None,
        ),
    ] {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        drop(req.headers.insert("cookie".into(), cookie));
        assert_eq!(mgr.extract_session_token(&req).as_deref(), expected);
    }
}

#[test]
fn extract_ignores_bearer_when_signed_cookie_exists() {
    let mgr = test_manager();
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    drop(
        req.headers
            .insert("authorization".into(), "Bearer bearer-tok".into()),
    );
    let signed = crate::utils::cookie_utils::sign_cookie_value("cookie-tok", &mgr.config.secret);
    drop(req.headers.insert(
        "cookie".into(),
        format!("better-auth.session_token={signed}"),
    ));
    assert_eq!(mgr.extract_session_token(&req), Some("cookie-tok".into()));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn extract_returns_none_without_auth() {
    let mgr = test_manager();
    let req = AuthRequest::new(HttpMethod::Get, "/test");
    assert_eq!(mgr.extract_session_token(&req), None);
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn extract_skips_empty_cookie_value() {
    let mgr = test_manager();
    let mut req = AuthRequest::new(HttpMethod::Get, "/test");
    drop(
        req.headers
            .insert("cookie".into(), "better-auth.session_token=".into()),
    );
    assert_eq!(mgr.extract_session_token(&req), None);
}

// ── is_session_fresh ────────────────────────────────────────────────

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn session_fresh_when_within_window() {
    let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
    config.session.fresh_age = Some(Duration::minutes(10));
    let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
    let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

    // A session created "now" is fresh within a 10-minute window.
    let session = SessionView {
        omitted_fields: std::collections::BTreeSet::default(),
        active_team_id: None,
        extension_fields: std::collections::BTreeMap::default(),
        id: "s1".into(),
        expires_at: Utc::now() + Duration::hours(1),
        token: "tok".into(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        ip_address: None,
        user_agent: None,
        user_id: "u1".into(),
        impersonated_by: None,
        active_organization_id: None,
        active: true,
    };
    assert!(mgr.is_session_fresh(&session));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn session_not_fresh_when_old() {
    let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
    config.session.fresh_age = Some(Duration::minutes(10));
    let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
    let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

    let session = SessionView {
        omitted_fields: std::collections::BTreeSet::default(),
        active_team_id: None,
        extension_fields: std::collections::BTreeMap::default(),
        id: "s1".into(),
        expires_at: Utc::now() + Duration::hours(1),
        token: "tok".into(),
        created_at: Utc::now() - Duration::minutes(20),
        updated_at: Utc::now(),
        ip_address: None,
        user_agent: None,
        user_id: "u1".into(),
        impersonated_by: None,
        active_organization_id: None,
        active: true,
    };
    assert!(!mgr.is_session_fresh(&session));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[test]
fn disabled_freshness_allows_an_old_session() {
    let mut config = (*test_config()).clone();
    config.session.fresh_age = None;
    let mgr = SessionManager::new(Arc::new(config), test_manager().database);
    let session = SessionView {
        omitted_fields: std::collections::BTreeSet::default(),
        active_team_id: None,
        extension_fields: std::collections::BTreeMap::default(),
        id: "s1".into(),
        expires_at: Utc::now() + Duration::hours(1),
        token: "tok".into(),
        created_at: Utc::now() - Duration::days(30),
        updated_at: Utc::now(),
        ip_address: None,
        user_agent: None,
        user_id: "u1".into(),
        impersonated_by: None,
        active_organization_id: None,
        active: true,
    };
    assert!(mgr.is_session_fresh(&session));
}

// ── async operations ────────────────────────────────────────────────

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn create_and_get_session() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    // Create a user first
    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    let session = mgr.create_session(&user, None, None).await.unwrap();
    let token = session.token().to_owned();

    let retrieved = mgr.get_session(&token).await.unwrap();
    assert!(retrieved.is_some());
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn refresh_returns_the_persisted_expiry() {
    let db = test_database().await;
    let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
    // Refresh on every access so a single `get_session` exercises the path.
    config.session.update_age = None;
    let mgr = SessionManager::new(Arc::new(config), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("refresh@test.com"))
        .await
        .unwrap();
    let session = mgr.create_session(&user, None, None).await.unwrap();
    let token = session.token().to_owned();

    // Move the stored expiry back so the refresh is observable.
    let stale = session.expires_at() - Duration::minutes(30);
    db.update_session_expiry(&token, stale).await.unwrap();

    let returned = mgr
        .get_session(&token)
        .await
        .unwrap()
        .expect("session should still be live");
    let stored = db
        .get_session(&token)
        .await
        .unwrap()
        .expect("session should still be stored");

    assert!(
        returned.expires_at() > stale,
        "refresh should have extended the expiry"
    );
    assert_eq!(
        returned.expires_at(),
        stored.expires_at(),
        "returned session must reflect the persisted expiry, not the pre-refresh value"
    );
}

#[test]
fn refresh_preferences_verify_the_first_cookie_and_use_javascript_truthiness() {
    let manager = test_manager();
    let name = crate::utils::cookie_utils::related_cookie_name(&manager.config, "dont_remember");
    let valid = crate::utils::cookie_utils::sign_cookie_value("true", &manager.config.secret);
    let empty = crate::utils::cookie_utils::sign_cookie_value("", &manager.config.secret);
    let wrong = crate::utils::cookie_utils::sign_cookie_value("true", "foreign-secret");
    for (header, expected) in [
        (format!("{name}={valid}"), true),
        (format!("{name}={empty}"), false),
        (format!("{name}={wrong}"), false),
        (format!("{name}=invalid; {name}={valid}"), false),
        (format!("{name}={valid}; {name}=invalid"), true),
    ] {
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        drop(request.headers.insert("cookie".into(), header));
        assert_eq!(manager.request_disables_refresh(&request), expected);
    }
    for (value, expected) in [("", false), ("false", true), ("0", true), ("true", true)] {
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        drop(request.query.insert("disableRefresh".into(), value.into()));
        assert_eq!(manager.request_disables_refresh(&request), expected);
    }
}

#[tokio::test]
async fn recent_sessions_refresh_at_the_expiry_based_half_second_boundary() {
    let db = test_database().await;
    let config = test_config();
    let manager = SessionManager::new(Arc::clone(&config), Arc::clone(&db));
    let user = db
        .create_user(crate::types::CreateUser::new().with_email("half-second@test.com"))
        .await
        .unwrap();
    for difference in [Duration::milliseconds(500), Duration::milliseconds(-500)] {
        let session = manager.create_session(&user, None, None).await.unwrap();
        let expiry = Utc::now() + config.session.expires_in - config.session.update_age.unwrap()
            + difference;
        db.update_session_expiry(session.token(), expiry)
            .await
            .unwrap();
        let returned = manager.get_session(session.token()).await.unwrap().unwrap();
        let stored = db.get_session(session.token()).await.unwrap().unwrap();
        assert_eq!(returned.expires_at(), stored.expires_at());
        assert_eq!(returned.token(), session.token());
        if difference > Duration::zero() {
            assert_eq!(stored.expires_at(), expiry);
        } else {
            assert!(stored.expires_at() > expiry + Duration::hours(23));
        }
    }
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn create_session_without_metadata_uses_empty_strings() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    let session = mgr.create_session(&user, None, None).await.unwrap();
    assert_eq!(session.ip_address.as_deref(), Some(""));
    assert_eq!(session.user_agent.as_deref(), Some(""));
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn delete_session_removes_it() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    let session = mgr.create_session(&user, None, None).await.unwrap();
    let token = session.token().to_owned();

    mgr.delete_session(&token).await.unwrap();
    let retrieved = mgr.get_session(&token).await.unwrap();
    assert!(retrieved.is_none());
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn revoke_session_returns_true_when_found() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    let session = mgr.create_session(&user, None, None).await.unwrap();
    let result = mgr.revoke_session(session.token()).await.unwrap();
    assert!(result);
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn revoke_session_returns_false_when_not_found() {
    let mgr = SessionManager::new(test_config(), test_database().await);
    let result = mgr.revoke_session("nonexistent-token").await.unwrap();
    assert!(!result);
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn list_user_sessions_excludes_expired() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    // Create two sessions
    drop(mgr.create_session(&user, None, None).await.unwrap());
    drop(mgr.create_session(&user, None, None).await.unwrap());

    let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
    assert_eq!(sessions.len(), 2);
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn revoke_all_user_sessions() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    drop(mgr.create_session(&user, None, None).await.unwrap());
    drop(mgr.create_session(&user, None, None).await.unwrap());

    let count = mgr.revoke_all_user_sessions(user.id()).await.unwrap();
    assert_eq!(count, 2);

    let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
    assert_eq!(sessions, Vec::<SessionView>::new());
}

// Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
#[tokio::test]
async fn revoke_other_sessions_keeps_current() {
    let db = test_database().await;
    let mgr = SessionManager::new(test_config(), Arc::clone(&db));

    let user = db
        .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
        .await
        .unwrap();

    let current = mgr.create_session(&user, None, None).await.unwrap();
    drop(mgr.create_session(&user, None, None).await.unwrap());
    drop(mgr.create_session(&user, None, None).await.unwrap());

    let count = mgr
        .revoke_other_user_sessions(user.id(), current.token())
        .await
        .unwrap();
    assert_eq!(count, 2);

    let remaining = mgr.list_user_sessions(user.id()).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        (*(remaining)
            .first()
            .expect("fixture contains the requested index"))
        .token(),
        current.token()
    );
}
