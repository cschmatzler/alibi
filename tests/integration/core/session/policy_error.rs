//! Explicit application errors stay observable at the direct session API.

#[path = "../../../support/session_policy_store.rs"]
mod policy_store;

use better_auth::plugins::SessionManagementPlugin;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::store::{SessionStore, UserStore};
use better_auth_core::{
    AuthRequest, AuthResponse, AuthSession, AuthUser, CreateSession, CreateUser, HttpMethod,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use policy_store::{PolicyStore, Schema};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

const ORIGIN: &str = "http://session-policy.fixture.test";

async fn get(auth: &BetterAuth<Schema>, path: &str, cookie: &str) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(HttpMethod::Get, format!("/api/auth{path}"));
    drop(req.headers.insert("cookie".into(), cookie.into()));
    let response = auth.handle_request(req).await.unwrap();
    let body = serde_json::from_slice(&response.body).unwrap();
    (response, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_store_policy_reaches_get_session_and_nested_middleware_still_rejects_authentication()
     {
        let config =
            AuthConfig::new("session-policy-fixture-secret-minimum-32-characters").base_url(ORIGIN);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let raw = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
        let user = raw
            .create_user(CreateUser::new().with_email("policy-owner@fixture.test"))
            .await
            .unwrap();
        let reject = Arc::new(AtomicBool::new(false));
        let rejected_reads = Arc::new(AtomicUsize::new(0));
        let auth = AuthBuilder::new(config)
            .store(PolicyStore {
                inner: Arc::clone(&raw),
                reject: Arc::clone(&reject),
                rejected_reads: Arc::clone(&rejected_reads),
            })
            .plugin(SessionManagementPlugin::new())
            .build()
            .await
            .unwrap();
        let issued = auth
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
            issued.token(),
            auth.config(),
        )
        .unwrap();
        let cookie = cookie.split(';').next().unwrap();
        let (accepted, session) = get(&auth, "/get-session", cookie).await;
        assert_eq!(accepted.status, 200, "{session}");
        assert_eq!(
            session.pointer("/session/token"),
            Some(&json!(issued.token()))
        );
        assert_eq!(session.pointer("/user/id"), Some(&json!(user.id())));
        let (accepted_list, sessions) = get(&auth, "/list-sessions", cookie).await;
        assert_eq!(accepted_list.status, 200, "{sessions}");
        assert_eq!(sessions.as_array().unwrap().len(), 1);
        assert_eq!(sessions.pointer("/0/token"), Some(&json!(issued.token())));
        let before = raw.get_session(issued.token()).await.unwrap().unwrap();

        reject.store(true, Ordering::SeqCst);
        let (denied, error) = get(&auth, "/get-session", cookie).await;
        assert_eq!(denied.status, 403, "{error}");
        assert_eq!(
            error,
            json!({"code":"FIXTURE_SESSION_POLICY","message":"Fixture session policy"})
        );
        assert_eq!(
            denied.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            denied.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        let (nested, error_2) = get(&auth, "/list-sessions", cookie).await;
        assert_eq!(nested.status, 401, "{error_2}");
        assert_eq!(
            error_2,
            json!({"code":"UNAUTHORIZED","message":"Unauthorized"})
        );
        assert!(nested.headers.get_all("set-cookie").next().is_none());
        assert_eq!(rejected_reads.load(Ordering::SeqCst), 2);
        let after = raw.get_session(issued.token()).await.unwrap().unwrap();
        assert_eq!(after.id(), before.id());
        assert_eq!(after.token(), before.token());
        assert_eq!(after.user_id(), before.user_id());
        assert_eq!(after.expires_at(), before.expires_at());
        assert_eq!(after.updated_at(), before.updated_at());
    }

    #[tokio::test]
    async fn signed_empty_session_cookie_leaves_a_real_empty_token_row_untouched() {
        let config =
            AuthConfig::new("session-policy-fixture-secret-minimum-32-characters").base_url(ORIGIN);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await
            .unwrap();
        let user = auth
            .store()
            .create_user(CreateUser::new().with_email("empty-token-owner@fixture.test"))
            .await
            .unwrap();
        let empty = auth
            .store()
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: Some(String::new()),
                user_id: user.id().into_owned(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await
            .unwrap();
        assert_eq!(empty.token(), "");
        let valid = auth
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let signed_empty =
            better_auth_core::utils::cookie_utils::sign_cookie_value("", &auth.config().secret);
        assert_eq!(
            better_auth_core::utils::cookie_utils::verify_cookie_value(
                &signed_empty,
                &auth.config().secret
            ),
            Some(String::new())
        );
        let empty_cookie_value = format!("{}={signed_empty}", auth.config().session.cookie_name);
        let empty_cookie = empty_cookie_value.as_str();
        let valid_cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
            valid.token(),
            auth.config(),
        )
        .unwrap();
        let valid_cookie = valid_cookie.split(';').next().unwrap();
        for cookie in [
            empty_cookie.to_owned(),
            format!("{empty_cookie}; {valid_cookie}"),
        ] {
            let (response, value) = get(&auth, "/get-session", &cookie).await;
            assert_eq!(response.status, 200, "{value}");
            assert_eq!(value, Value::Null, "signed empty tokens are absent");
            assert!(response.headers.get_all("set-cookie").next().is_none());
            let stored = auth.store().get_session("").await.unwrap().unwrap();
            assert_eq!(stored.id(), empty.id());
            assert_eq!(stored.token(), empty.token());
            assert_eq!(stored.user_id(), empty.user_id());
            assert_eq!(stored.expires_at(), empty.expires_at());
            assert_eq!(stored.updated_at(), empty.updated_at());
        }
        let (response, value) = get(
            &auth,
            "/get-session",
            &format!("{valid_cookie}; {empty_cookie}"),
        )
        .await;
        assert_eq!(response.status, 200, "{value}");
        assert_eq!(value.pointer("/session/token"), Some(&json!(valid.token())));
        assert_eq!(value.pointer("/user/id"), Some(&json!(user.id())));
    }
}
