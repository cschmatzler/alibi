//! Actual two-host authentication and one-use HTTP provider grants.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Form, Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{
    EmailPasswordPlugin, OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateSession,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Statement};
use better_auth_seaorm::store::entities::{account, session, user, verification};
use better_auth_seaorm::{
    Database, DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceExt;
const PATH: &str = "/__test/profiles/oauth-proxy/api/auth";
const SECRET: &str = "local-fixture-dedicated-oauth-proxy-secret-32";
struct Grant {
    challenge: String,
    redirect: String,
    used: bool,
}
struct Provider {
    grants: HashMap<String, Grant>,
    receipts: Vec<Value>,
    count: usize,
    profile: Value,
    failure: String,
    session_hooks: Vec<Value>,
    after_requests: Vec<Value>,
    tracking: bool,
}
#[derive(Clone)]
pub(super) struct Fixture {
    provider: Arc<Mutex<Provider>>,
    preview: DatabaseConnection,
    production: DatabaseConnection,
}
fn profile() -> Value {
    json!({"id":777,"email":"proxy-owner@fixture.test","email_verified":true,"name":"Proxy Owner","avatar_url":"https://assets.fixture.test/avatar.png","state":"active","locked":false})
}
fn date(v: DateTime<Utc>) -> String {
    v.to_rfc3339_opts(SecondsFormat::Millis, true)
}
struct CompletedRequests(Fixture);
#[async_trait]
impl AuthPlugin<TestSchema> for CompletedRequests {
    fn name(&self) -> &'static str {
        "proxy-application-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let mut provider = self.0.provider.lock().await;
        if provider.tracking
            && (req.path().ends_with("/oauth-proxy") || req.path() == "/oauth-proxy-callback")
        {
            provider
                .after_requests
                .push(json!({"callbackURL":req.query.get("callbackURL")}));
        }
        Ok(response)
    }
}
struct SessionHooks(Fixture);
#[async_trait]
impl SeaOrmHooks<TestSchema> for SessionHooks {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path.contains("oauth-proxy"))
        {
            let mut provider = self.0.provider.lock().await;
            let mode = provider.failure.clone();
            provider
                .session_hooks
                .push(json!({"userId":session.user_id,"mode":mode}));
            if mode == "cancel-session" {
                return Ok(HookControl::Cancel);
            }
            if mode == "ordinary-session-error" {
                return Err(AuthError::internal("private proxy session failure"));
            }
            if mode == "coded-session-error" {
                return Err(AuthError::Api {
                    status: 500,
                    code: Some("PROXY_SESSION_DENIED".into()),
                    message: "Configured proxy session denied".into(),
                });
            }
        }
        Ok(HookControl::Continue)
    }
}
impl Fixture {
    pub(super) async fn reset(&self) -> AuthResult<()> {
        for db in [&self.preview, &self.production] {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "DROP TRIGGER IF EXISTS proxy_delete_veto",
            ))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
            let _ = session::Entity::delete_many()
                .exec(db)
                .await
                .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
            let _ = account::Entity::delete_many()
                .exec(db)
                .await
                .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
            let _ = verification::Entity::delete_many()
                .exec(db)
                .await
                .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
            let _ = user::Entity::delete_many()
                .exec(db)
                .await
                .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
        }
        let mut provider = self.provider.lock().await;
        provider.grants.clear();
        provider.receipts.clear();
        provider.count = 0;
        provider.failure = "none".into();
        provider.session_hooks.clear();
        provider.after_requests.clear();
        provider.tracking = false;
        provider.profile = profile();
        Ok(())
    }
}
pub(super) async fn router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    let preview = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    let production = Database::connect("sqlite::memory:")
        .await
        .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    let fixture = Fixture {
        preview,
        production,
        provider: Arc::new(Mutex::new(Provider {
            grants: HashMap::new(),
            receipts: vec![],
            count: 0,
            profile: profile(),
            failure: "none".into(),
            session_hooks: vec![],
            after_requests: vec![],
            tracking: false,
        })),
    };
    for db in [&fixture.preview, &fixture.production] {
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(db)
            .await
            .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    }
    let production_origin = config.base_url.replace("localhost", "127.0.0.1");
    let mut routers = vec![];
    for (origin, db) in [
        (&config.base_url, &fixture.preview),
        (&production_origin, &fixture.production),
    ] {
        let settings = config
            .clone()
            .base_url(origin)
            .base_path(PATH)
            .trusted_origin(config.base_url.clone())
            .trusted_origin(production_origin.clone());
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(settings, db.clone())
                        .with_hooks(vec![Arc::new(SessionHooks(fixture.clone()))]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider(
                    "gitlab",
                    OAuthProvider::gitlab_with_issuer(
                        "proxy-fixture-client",
                        "proxy-fixture-secret",
                        &format!("{}/__test/oauth-proxy/provider", config.base_url),
                    ),
                ))
                .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                    current_url: Some(origin.clone()),
                    production_url: Some(production_origin.clone()),
                    secret: Some(SECRET.into()),
                    ..Default::default()
                }))
                .plugin(CompletedRequests(fixture.clone()))
                .build()
                .await?,
        );
        routers.push(Router::new().nest(PATH, auth.clone().axum_router().with_state(auth)));
    }
    let mut routers = routers.into_iter();
    let preview_router = routers
        .next()
        .ok_or_else(|| better_auth::AuthError::internal("Missing preview router"))?;
    let production_router = routers
        .next()
        .ok_or_else(|| better_auth::AuthError::internal("Missing production router"))?;
    let router=Router::new().route(&format!("{PATH}/{{*rest}}"),any(move |request:Request|{
        let selected=if request.headers().get("host").and_then(|host|host.to_str().ok()).is_some_and(|host|host.starts_with("127.0.0.1:")){production_router.clone()}else{preview_router.clone()};
        async move {selected.oneshot(request).await}
    }))
    .route("/__test/oauth-proxy/state",get(state))
    .route("/__test/oauth-proxy/control",post(|State(fixture):State<Fixture>,Json(value):Json<Value>|async move{
        let mode=value.get("mode").and_then(Value::as_str).unwrap_or("none").to_owned();{let mut provider=fixture.provider.lock().await;provider.failure=mode.clone();provider.tracking=true;}let db=&fixture.preview;
        db.execute_raw(Statement::from_string(db.get_database_backend(),"DROP TRIGGER IF EXISTS proxy_delete_veto")).await.map_err(|e|e.to_string())?;
        if mode=="delete-veto" {db.execute_raw(Statement::from_string(db.get_database_backend(),"CREATE TRIGGER proxy_delete_veto BEFORE DELETE ON verifications BEGIN SELECT RAISE(ABORT, 'proxy delete veto'); END")).await.map_err(|e|e.to_string())?;}
        Ok::<_,String>(Json(json!({"status":true})))
    }))
    .route("/__test/oauth-proxy/profile",post(|State(fixture):State<Fixture>,Json(value):Json<Value>|async move{fixture.provider.lock().await.profile=value;Json(json!({"status":true}))}))
    .route("/__test/oauth-proxy/provider/oauth/authorize",get(authorize))
    .route("/__test/oauth-proxy/provider/oauth/token",post(token))
    .route("/__test/oauth-proxy/provider/api/v4/user",get(|State(fixture):State<Fixture>,headers:HeaderMap|async move{
        let mut provider=fixture.provider.lock().await;provider.receipts.push(json!({"stage":"userinfo","authorization":headers.get("authorization").and_then(|v|v.to_str().ok())}));Json(provider.profile.clone())
    })).with_state(fixture.clone());
    Ok((router, fixture))
}
async fn authorize(
    State(fixture): State<Fixture>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let mut provider = fixture.provider.lock().await;
    provider
        .receipts
        .push(json!({"stage":"authorize","query":query}));
    provider.count += 1;
    let code = format!("proxy-fixture-code-{}", provider.count);
    let Some(redirect) = query.get("redirect_uri") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(challenge) = query.get("code_challenge") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(state) = query.get("state") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(mut url) = url::Url::parse(redirect) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let _ = url
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", state);
    let _ = provider.grants.insert(
        code,
        Grant {
            challenge: challenge.clone(),
            redirect: redirect.clone(),
            used: false,
        },
    );
    (StatusCode::FOUND, [("location", url.to_string())]).into_response()
}
async fn token(
    State(fixture): State<Fixture>,
    Form(body): Form<HashMap<String, String>>,
) -> Response {
    let mut provider = fixture.provider.lock().await;
    provider.receipts.push(json!({"stage":"token","body":body}));
    let Some(code) = body.get("code") else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    };
    let Some(grant) = provider.grants.get_mut(code) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    };
    let valid = !grant.used
        && Some(&grant.redirect) == body.get("redirect_uri")
        && body.get("code_verifier").is_some_and(|verifier| {
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == grant.challenge
        });
    if !valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    };
    grant.used = true;
    Json(json!({"access_token":"proxy-fixture-access","refresh_token":"proxy-fixture-refresh","token_type":"Bearer","scope":"read_user issued","expires_in":3600})).into_response()
}
async fn state(State(fixture): State<Fixture>) -> Result<Json<Value>, String> {
    let mut result = serde_json::Map::new();
    for (name, db) in [
        ("preview", &fixture.preview),
        ("production", &fixture.production),
    ] {
        let users = user::Entity::find()
            .order_by_asc(user::Column::CreatedAt)
            .all(db)
            .await
            .map_err(|e| e.to_string())?;
        let accounts = account::Entity::find()
            .order_by_asc(account::Column::CreatedAt)
            .all(db)
            .await
            .map_err(|e| e.to_string())?;
        let sessions = session::Entity::find()
            .order_by_asc(session::Column::CreatedAt)
            .all(db)
            .await
            .map_err(|e| e.to_string())?;
        let verification = verification::Entity::find()
            .order_by_asc(verification::Column::CreatedAt)
            .all(db)
            .await
            .map_err(|e| e.to_string())?;
        let _=result.insert(name.into(),json!({
            "users":users.iter().map(|r|json!({"id":r.id,"name":r.name,"email":r.email,"emailVerified":r.email_verified,"image":r.image,"createdAt":date(r.created_at),"updatedAt":date(r.updated_at)})).collect::<Vec<_>>(),
            "accounts":accounts.iter().map(|r|json!({"id":r.id,"userId":r.user_id,"accountId":r.account_id,"providerId":r.provider_id,"accessToken":r.access_token,"refreshToken":r.refresh_token,"idToken":r.id_token,"scope":r.scope,"accessTokenExpiresAt":r.access_token_expires_at.map(date),"refreshTokenExpiresAt":r.refresh_token_expires_at.map(date),"createdAt":date(r.created_at),"updatedAt":date(r.updated_at)})).collect::<Vec<_>>(),
            "sessions":sessions.iter().map(|r|json!({"id":r.id,"userId":r.user_id,"token":r.token,"expiresAt":date(r.expires_at),"createdAt":date(r.created_at),"updatedAt":date(r.updated_at),"ipAddress":r.ip_address,"userAgent":r.user_agent})).collect::<Vec<_>>(),
            "verification":verification.iter().map(|r|json!({"id":r.id,"expiresAt":date(r.expires_at),"createdAt":date(r.created_at),"updatedAt":date(r.updated_at)})).collect::<Vec<_>>(),
        }));
    }
    let _ = result.insert(
        "receipts".into(),
        json!(fixture.provider.lock().await.receipts),
    );
    let _ = result.insert(
        "sessionHooks".into(),
        json!(fixture.provider.lock().await.session_hooks),
    );
    let _ = result.insert(
        "afterRequests".into(),
        json!(fixture.provider.lock().await.after_requests),
    );
    Ok(Json(Value::Object(result)))
}
