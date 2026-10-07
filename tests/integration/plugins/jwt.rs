//! JWT issuance observes the pinned session middleware and completed-response context.

use alibi::plugins::jwt::{
    DefineJwtPayload, DefineJwtSubject, JwtPlugin, JwtPluginConfig, JwtSession,
};
use alibi::plugins::{ApiKeyPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthSession, AuthUser,
    CreateUser, HttpMethod,
};
use alibi_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use alibi_seaorm::{Database, SeaOrmStore};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

type Schema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://jwt-session.fixture.test";

#[derive(Default)]
struct ObservedClaims(Mutex<Vec<Value>>, Mutex<Vec<Value>>);

#[async_trait]
impl DefineJwtPayload for ObservedClaims {
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
        let snapshot = json!(session);
        self.0.lock().unwrap().push(snapshot.clone());
        Ok(json!({"snapshot":snapshot}).as_object().unwrap().clone())
    }
}

#[async_trait]
impl DefineJwtSubject for ObservedClaims {
    async fn subject(&self, session: &JwtSession) -> AuthResult<Option<String>> {
        self.1.lock().unwrap().push(json!(session));
        Ok(None)
    }
}

struct EarlierExposedHeaders;

#[async_trait]
impl AuthPlugin<Schema> for EarlierExposedHeaders {
    fn name(&self) -> &'static str {
        "earlier-exposed-headers"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if req.path() == "/get-session" {
            drop(response.headers.insert(
                "access-control-expose-headers",
                " existing, ,existing, set-auth-jwt, set-auth-jwt, Existing ",
            ));
        }
        Ok(response)
    }
}

async fn fixture(
    deferred: bool,
    disabled: bool,
) -> (
    BetterAuth<Schema>,
    DatabaseConnection,
    JwtPlugin,
    Arc<ObservedClaims>,
) {
    let mut config =
        AuthConfig::new("jwt-session-fixture-secret-at-least-32-characters").base_url(ORIGIN);
    config.session.defer_session_refresh = deferred;
    config.session.disable_session_refresh = disabled;
    config.session.update_age = Some(Duration::zero());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    _ = db
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "CREATE TABLE expiry_writes (token TEXT NOT NULL)".to_owned(),
        ))
        .await
        .unwrap();
    _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER observe_expiry_write AFTER UPDATE OF expires_at ON sessions BEGIN INSERT INTO expiry_writes(token) VALUES(new.token); END".to_owned())).await.unwrap();
    let observed = Arc::new(ObservedClaims::default());
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        define_payload: Some(Arc::<ObservedClaims>::clone(&observed)),
        define_subject: Some(Arc::<ObservedClaims>::clone(&observed)),
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db.clone()))
        .plugin(SessionManagementPlugin::new())
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .plugin(EarlierExposedHeaders)
        .plugin(jwt.clone())
        .build()
        .await
        .unwrap();
    (auth, db, jwt, observed)
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
    let cookie =
        alibi_core::utils::cookie_utils::create_session_cookie(session.token(), auth.config())
            .unwrap();
    (
        user.id().into_owned(),
        session.token().to_owned(),
        cookie.split(';').next().unwrap().to_owned(),
    )
}

fn request(path: &str, cookie: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, format!("/api/auth{path}"));
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(req.headers.insert("cookie".into(), cookie.into()));
    req
}

async fn age(
    auth: &BetterAuth<Schema>,
    db: &DatabaseConnection,
    token: &str,
    expired: bool,
) -> Value {
    auth.store()
        .update_session_expiry(
            token,
            Utc::now() + Duration::seconds(if expired { -60 } else { 3600 }),
        )
        .await
        .unwrap();
    _ = db
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM expiry_writes".to_owned(),
        ))
        .await
        .unwrap();
    serde_json::to_value(
        auth.context()
            .session_view(&auth.store().get_session(token).await.unwrap().unwrap()),
    )
    .unwrap()
}

async fn writes(db: &DatabaseConnection) -> i64 {
    db.query_one_raw(Statement::from_string(
        DbBackend::Sqlite,
        "SELECT COUNT(*) AS count FROM expiry_writes".to_owned(),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "count")
    .unwrap()
}

async fn verified(jwt: &JwtPlugin, auth: &BetterAuth<Schema>, token: &str) -> Map<String, Value> {
    jwt.verify_jwt(token, None, None, auth.context())
        .await
        .unwrap()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn token_signs_the_single_normally_refreshed_snapshot_and_honors_suppression() {
        for (case, deferred, disabled, query, preference, should_refresh) in [
            ("normal", false, false, None, None, true),
            ("empty-query", false, false, Some(""), None, true),
            ("false-query", false, false, Some("false"), None, false),
            (
                "remember-preference",
                false,
                false,
                None,
                Some("true"),
                false,
            ),
            ("empty-preference", false, false, None, Some(""), true),
            ("disabled", false, true, None, None, false),
            ("deferred", true, false, None, None, false),
            ("deferred-empty-query", true, false, Some(""), None, false),
            (
                "deferred-false-query",
                true,
                false,
                Some("false"),
                None,
                false,
            ),
            (
                "deferred-preference",
                true,
                false,
                None,
                Some("true"),
                false,
            ),
            ("deferred-disabled", true, true, None, None, false),
        ] {
            let (auth, db, jwt, observed) = fixture(deferred, disabled).await;
            let (user_id, token, mut cookie) =
                issued(&auth, &format!("{case}@jwt-session.fixture.test")).await;
            let before = age(&auth, &db, &token, false).await;
            if let Some(value) = preference {
                cookie.push_str("; better-auth.dont_remember=");
                cookie.push_str(&alibi_core::utils::cookie_utils::sign_cookie_value(
                    value,
                    &auth.config().secret,
                ));
            }
            let mut req = request("/token", &cookie);
            if let Some(query) = query {
                drop(req.query.insert("disableRefresh".into(), query.into()));
            }
            let response = auth.handle_request(req).await.unwrap();
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response.status, 200, "{case}: {body}");
            let claims = verified(
                &jwt,
                &auth,
                (*(body).get("token").unwrap_or(&Value::Null))
                    .as_str()
                    .unwrap(),
            )
            .await;
            let stored = auth.store().get_session(&token).await.unwrap().unwrap();
            assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), user_id);
            assert_eq!(
                (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("user")
                    .unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null)),
                user_id
            );
            assert_eq!(
                (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("session")
                    .unwrap_or(&Value::Null)),
                json!(auth.context().session_view(&stored)),
                "{case}"
            );
            assert_eq!(
                stored.id().as_ref(),
                (*(before).get("id").unwrap_or(&Value::Null))
                    .as_str()
                    .unwrap()
            );
            assert_eq!(stored.token(), token);
            assert_eq!(stored.user_id().as_ref(), user_id);
            if deferred && query.is_none_or(str::is_empty) && preference != Some("true") {
                assert_eq!(
                    (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                        .get("needsRefresh")
                        .unwrap_or(&Value::Null)),
                    !disabled,
                    "{case}"
                );
            } else {
                assert!(
                    (*(claims).get("snapshot").unwrap_or(&Value::Null))
                        .get("needsRefresh")
                        .is_none(),
                    "{case}"
                );
            }
            assert_eq!(
                observed.0.lock().unwrap().len(),
                1,
                "{case}: one payload callback"
            );
            assert_eq!(
                *observed.0.lock().unwrap(),
                *observed.1.lock().unwrap(),
                "{case}: payload and subject callbacks receive the same authenticated snapshot"
            );
            assert_eq!(
                writes(&db).await,
                i64::from(should_refresh),
                "{case}: one refresh write"
            );
            assert_eq!(
                response.headers.get_all("set-cookie").count(),
                usize::from(should_refresh),
                "{case}"
            );
            if should_refresh {
                assert!(stored.expires_at() > Utc::now() + Duration::days(6));
                assert!(
                    response
                        .headers
                        .get_all("set-cookie")
                        .next()
                        .unwrap()
                        .contains("Max-Age=604800")
                );
            } else {
                assert_eq!(
                    json!(auth.context().session_view(&stored)),
                    before,
                    "{case}: no state changes"
                );
            }
        }
    }

    #[tokio::test]
    async fn session_jwt_header_uses_the_original_snapshot_and_exact_exposed_header_set() {
        for deferred in [false, true] {
            let (auth, db, jwt, observed) = fixture(deferred, false).await;
            let (user_id, token, cookie) = issued(&auth, "header@jwt-session.fixture.test").await;
            let before = age(&auth, &db, &token, false).await;
            let mut suppressed = request("/get-session", &cookie);
            drop(
                suppressed
                    .query
                    .insert("disableRefresh".into(), "false".into()),
            );
            let response = auth.handle_request(suppressed).await.unwrap();
            let claims = verified(&jwt, &auth, response.headers.get("set-auth-jwt").unwrap()).await;
            assert_eq!(
                (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("session")
                    .unwrap_or(&Value::Null))
                .get("expiresAt")
                .unwrap_or(&Value::Null)),
                (*(before).get("expiresAt").unwrap_or(&Value::Null))
            );
            assert_eq!(
                response
                    .headers
                    .get("access-control-expose-headers")
                    .unwrap(),
                "existing, set-auth-jwt, Existing"
            );
            assert_eq!(writes(&db).await, 0);
            observed.0.lock().unwrap().clear();
            let response_2 = auth
                .handle_request(request("/get-session", &cookie))
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&response_2.body).unwrap();
            assert_eq!(response_2.status, 200, "{body}");
            let claims_2 =
                verified(&jwt, &auth, response_2.headers.get("set-auth-jwt").unwrap()).await;
            assert_eq!((*(claims_2).get("sub").unwrap_or(&Value::Null)), user_id);
            assert_eq!(
                (*(*(*(claims_2).get("snapshot").unwrap_or(&Value::Null))
                    .get("session")
                    .unwrap_or(&Value::Null))
                .get("expiresAt")
                .unwrap_or(&Value::Null)),
                (*(before).get("expiresAt").unwrap_or(&Value::Null))
            );
            assert_eq!(
                (*(*(body).get("session").unwrap_or(&Value::Null))
                    .get("token")
                    .unwrap_or(&Value::Null)),
                token
            );
            let stored = auth.store().get_session(&token).await.unwrap().unwrap();
            assert_eq!(
                (*(body).get("session").unwrap_or(&Value::Null)),
                json!(auth.context().session_view(&stored))
            );
            assert_eq!(
                response_2
                    .headers
                    .get("access-control-expose-headers")
                    .unwrap(),
                "existing, set-auth-jwt, Existing"
            );
            assert_eq!(observed.0.lock().unwrap().len(), 1);
            assert_eq!(writes(&db).await, i64::from(!deferred));
            observed.0.lock().unwrap().clear();
            let expired = age(&auth, &db, &token, true).await;
            let response_3 = auth
                .handle_request(request("/get-session", &cookie))
                .await
                .unwrap();
            let body_2: Value = serde_json::from_slice(&response_3.body).unwrap();
            assert_eq!(response_3.status, 200);
            assert_eq!(body_2, Value::Null);
            let claims_3 =
                verified(&jwt, &auth, response_3.headers.get("set-auth-jwt").unwrap()).await;
            assert_eq!(
                (*(*(*(claims_3).get("snapshot").unwrap_or(&Value::Null))
                    .get("session")
                    .unwrap_or(&Value::Null))
                .get("expiresAt")
                .unwrap_or(&Value::Null)),
                (*(expired)
                    .get("expiresAt")
                    .expect("fixture contains the requested index"))
            );
            assert_eq!((*(claims_3).get("sub").unwrap_or(&Value::Null)), user_id);
            assert_eq!(observed.0.lock().unwrap().len(), 1);
            assert_eq!(response_3.headers.get_all("set-cookie").count(), 3);
            assert_eq!(
                auth.store().get_session(&token).await.unwrap().is_some(),
                deferred
            );
            // The endpoint's normal middleware still rejects the same expired proof.
            let response_4 = auth
                .handle_request(request("/token", &cookie))
                .await
                .unwrap();
            assert_eq!(response_4.status, 401);
            assert_eq!(observed.0.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn api_key_virtual_owner_overrides_another_cookie_without_creating_a_session() {
        let (auth, db, jwt, observed) = fixture(false, false).await;
        let (key_owner, owner_token, owner_cookie) =
            issued(&auth, "key-owner@jwt-session.fixture.test").await;
        let (cookie_owner, cookie_token, cookie) =
            issued(&auth, "cookie-owner@jwt-session.fixture.test").await;
        let mut create = request("/api-key/create", &owner_cookie);
        create.method = HttpMethod::Post;
        drop(
            create
                .headers
                .insert("content-type".into(), "application/json".into()),
        );
        create.body = Some(serde_json::to_vec(&json!({"name":"JWT virtual principal"})).unwrap());
        let created = auth.handle_request(create).await.unwrap();
        assert_eq!(created.status, 200);
        let created: Value = serde_json::from_slice(&created.body).unwrap();
        let raw_key = (*(created).get("key").unwrap_or(&Value::Null))
            .as_str()
            .unwrap();
        let before = auth.store().get_user_sessions(&key_owner).await.unwrap();
        let foreign_before = age(&auth, &db, &cookie_token, false).await;
        let mut req = request("/token", &cookie);
        drop(req.headers.insert("x-api-key".into(), raw_key.into()));
        let response = auth.handle_request(req).await.unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, 200, "{body}");
        let claims = verified(
            &jwt,
            &auth,
            (*(body).get("token").unwrap_or(&Value::Null))
                .as_str()
                .unwrap(),
        )
        .await;
        assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), key_owner);
        assert_ne!((*(claims).get("sub").unwrap_or(&Value::Null)), cookie_owner);
        assert_eq!(
            (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
            (*(created).get("id").unwrap_or(&Value::Null))
        );
        assert_eq!(
            (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("token")
            .unwrap_or(&Value::Null)),
            raw_key
        );
        assert_eq!(
            (*(*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                .get("session")
                .unwrap_or(&Value::Null))
            .get("userId")
            .unwrap_or(&Value::Null)),
            key_owner
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&key_owner).await.unwrap())
                .unwrap(),
            json!(before)
        );
        assert_eq!(
            json!(
                auth.context().session_view(
                    &auth
                        .store()
                        .get_session(&cookie_token)
                        .await
                        .unwrap()
                        .unwrap()
                )
            ),
            foreign_before
        );
        assert_eq!(response.headers.get_all("set-cookie").count(), 0);
        assert_eq!(writes(&db).await, 0);
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        let mut req_2 = request("/get-session", "");
        drop(req_2.headers.insert("x-api-key".into(), raw_key.into()));
        let response_2 = auth.handle_request(req_2).await.unwrap();
        let body_2: Value = serde_json::from_slice(&response_2.body).unwrap();
        assert_eq!(
            (*(*(body_2).get("user").unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null)),
            key_owner
        );
        assert_eq!(
            (*(*(body_2).get("session").unwrap_or(&Value::Null))
                .get("id")
                .unwrap_or(&Value::Null)),
            (*(created).get("id").unwrap_or(&Value::Null))
        );
        assert!(response_2.headers.get("set-auth-jwt").is_none());
        assert!(
            response_2
                .headers
                .get("access-control-expose-headers")
                .is_none()
        );
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        let mut bad = request("/token", &cookie);
        drop(bad.headers.insert(
            "x-api-key".into(),
            "invalid-api-key-proof-with-adequate-length".into(),
        ));
        let rejected = auth.handle_request(bad).await.unwrap();
        assert_eq!(rejected.status, 403);
        assert_eq!(observed.0.lock().unwrap().len(), 1);
        assert_eq!(
            auth.store()
                .get_user_sessions(&key_owner)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            auth.store()
                .get_session(&owner_token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn failed_refresh_retains_the_direct_hook_snapshot_but_never_authorizes_token_issuance() {
        for (action, status, cookie_count) in [
            ("IGNORE", 401, 3),
            ("ABORT, 'fixture refresh failure'", 500, 0),
        ] {
            let (auth, db, jwt, observed) = fixture(false, false).await;
            let (user_id, token, cookie) =
                issued(&auth, "failed-refresh@jwt-session.fixture.test").await;
            let before = age(&auth, &db, &token, false).await;
            _ = db.execute_raw(Statement::from_string(DbBackend::Sqlite,
            format!("CREATE TRIGGER reject_refresh BEFORE UPDATE OF expires_at ON sessions BEGIN SELECT RAISE({action}); END")))
            .await.unwrap();
            let response = auth
                .handle_request(request("/get-session", &cookie))
                .await
                .unwrap();
            let error: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response.status, status, "{action}: {error}");
            assert_eq!(
                (*(error).get("code").unwrap_or(&Value::Null)),
                "FAILED_TO_GET_SESSION"
            );
            let claims = verified(&jwt, &auth, response.headers.get("set-auth-jwt").unwrap()).await;
            assert_eq!((*(claims).get("sub").unwrap_or(&Value::Null)), user_id);
            assert_eq!(
                (*(*(claims).get("snapshot").unwrap_or(&Value::Null))
                    .get("session")
                    .unwrap_or(&Value::Null)),
                before
            );
            assert_eq!(response.headers.get_all("set-cookie").count(), cookie_count);
            assert_eq!(writes(&db).await, 0);
            assert_eq!(
                json!(
                    auth.context()
                        .session_view(&auth.store().get_session(&token).await.unwrap().unwrap())
                ),
                before
            );
            assert_eq!(observed.0.lock().unwrap().len(), 1);
            let response_2 = auth
                .handle_request(request("/token", &cookie))
                .await
                .unwrap();
            let error_2: Value = serde_json::from_slice(&response_2.body).unwrap();
            assert_eq!(response_2.status, 401);
            assert_eq!(
                error_2,
                json!({"code":"UNAUTHORIZED","message":"Unauthorized"})
            );
            assert!(response_2.headers.get("set-auth-jwt").is_none());
            assert_eq!(observed.0.lock().unwrap().len(), 1);
            assert_eq!(writes(&db).await, 0);
        }
    }

    #[tokio::test]
    async fn caller_supplied_hook_snapshot_cannot_set_a_jwt_or_authorize_the_token_endpoint() {
        let (auth, db, _, observed) = fixture(false, false).await;
        let (user_id, token, _) = issued(&auth, "forged-context@jwt-session.fixture.test").await;
        let before = age(&auth, &db, &token, false).await;
        let user = auth
            .store()
            .get_user_by_id(&user_id)
            .await
            .unwrap()
            .unwrap();
        let session = auth.store().get_session(&token).await.unwrap().unwrap();
        for path in ["/get-session", "/token"] {
            let req = request(path, "");
            req.set_session_hook_snapshot(
                auth.context().user_view(&user),
                auth.context().session_view(&session),
            );
            let response = auth.handle_request(req).await.unwrap();
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            if path == "/get-session" {
                assert_eq!(response.status, 200);
                assert_eq!(body, Value::Null);
            } else {
                assert_eq!(response.status, 401);
                assert_eq!(
                    body,
                    json!({"code":"UNAUTHORIZED","message":"Unauthorized"})
                );
            }
            assert!(response.headers.get("set-auth-jwt").is_none());
            assert_eq!(observed.0.lock().unwrap().len(), 0);
            assert_eq!(writes(&db).await, 0);
            assert!(auth.store().list_jwks().await.unwrap().is_empty());
            assert_eq!(
                json!(
                    auth.context()
                        .session_view(&auth.store().get_session(&token).await.unwrap().unwrap())
                ),
                before
            );
        }
    }
}
