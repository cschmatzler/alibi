#![cfg(test)]
//! JWT issuance observes the pinned session middleware and completed-response context.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "jwt_session_integration_tests/tests.rs"]
mod tests;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use better_auth::plugins::jwt::{
    DefineJwtPayload, DefineJwtSubject, JwtPlugin, JwtPluginConfig, JwtSession,
};

use better_auth::plugins::{ApiKeyPlugin, SessionManagementPlugin};

use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};

use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, AuthSession, AuthUser,
    CreateUser, HttpMethod,
};

use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};

use better_auth_seaorm::{Database, SeaOrmStore};

use chrono::{Duration, Utc};

use serde_json::{Map, Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

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
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
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
