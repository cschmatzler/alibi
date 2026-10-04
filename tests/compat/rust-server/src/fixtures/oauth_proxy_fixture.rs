//! Actual two-host authentication and one-use HTTP provider grants.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{
    OAuthAccountKey, OAuthAccountKeyContext, OAuthAccountKeyResolver, OAuthProvider,
};
use better_auth::plugins::{
    EmailPasswordPlugin, OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateSession,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Statement};
use better_auth_seaorm::store::entities::{account, session, user, verification};
use better_auth_seaorm::{Database, DatabaseConnection, DatabaseHooks, HookControl};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceExt;
const PATH: &str = "/__test/profiles/oauth-proxy/api/auth";
const OPTION_MODES: &[&str] = &[
    "dedicated",
    "request",
    "dynamic",
    "environment",
    "environment-skip",
    "error",
    "empty-error",
    "fractional",
    "nan",
    "infinity",
    "negative-infinity",
    "cache",
    "cache-error",
    "signup-absent",
    "signup-disabled",
    "custom",
    "bad-key",
];
const SECRET: &str = "local-fixture-dedicated-oauth-proxy-secret-32";
struct CacheFailure;
#[async_trait]
impl better_auth_core::CookieCacheVersionResolver for CacheFailure {
    async fn resolve(
        &self,
        _context: &better_auth_core::CacheVersionContext,
    ) -> AuthResult<String> {
        Err(AuthError::internal("private cache publication failure"))
    }
}
struct AccountKey(bool);
#[async_trait]
impl OAuthAccountKeyResolver for AccountKey {
    async fn resolve(&self, context: OAuthAccountKeyContext) -> Result<Value, String> {
        if context.tokens.access_token.is_none() {
            return Err("actual provider token required".into());
        }
        Ok(Value::String(if self.0 {
            String::new()
        } else {
            context
                .profile
                .get("account_key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        }))
    }
}
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
pub(crate) struct Fixture {
    provider: Arc<Mutex<Provider>>,
    preview: DatabaseConnection,
    production: DatabaseConnection,
    key_modes: Arc<Mutex<[String; 2]>>,
    initial_mode: &'static str,
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
impl DatabaseHooks<TestSchema, crate::backend::Backend> for SessionHooks {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        context: &crate::backend::HookContext<'_>,
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
    pub(crate) async fn reset(&self) -> AuthResult<()> {
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
        *self.key_modes.lock().await = [self.initial_mode.into(), self.initial_mode.into()];
        Ok(())
    }
}
pub(crate) async fn router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    build_router(config, false, false).await
}
pub(crate) async fn managed_router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    build_router(config, true, false).await
}
pub(crate) async fn cookie_router(config: &AuthConfig) -> AuthResult<(Router, Fixture)> {
    build_router(config, false, true).await
}
async fn build_router(
    config: &AuthConfig,
    managed: bool,
    cookie: bool,
) -> AuthResult<(Router, Fixture)> {
    let path = if cookie {
        "/__test/profiles/oauth-proxy-cookie/api/auth"
    } else if managed {
        "/__test/profiles/managed-proxy/api/auth"
    } else {
        PATH
    };
    let control = if cookie {
        "/__test/oauth-proxy-cookie"
    } else if managed {
        "/__test/managed-proxy"
    } else {
        "/__test/oauth-proxy"
    };
    let initial_mode = if managed { "old" } else { "dedicated" };
    let preview = Database::connect(crate::sqlite_fixture::options())
        .await
        .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    let production = Database::connect(crate::sqlite_fixture::options())
        .await
        .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    let fixture = Fixture {
        preview,
        production,
        key_modes: Arc::new(Mutex::new([initial_mode.into(), initial_mode.into()])),
        initial_mode,
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
        crate::backend::migrate(db)
            .await
            .map_err(|error| better_auth::AuthError::internal(error.to_string()))?;
    }
    let production_origin = config.base_url.replace("localhost", "127.0.0.1");
    let mut routers = HashMap::new();
    for (index, origin, db) in [
        (0, &config.base_url, &fixture.preview),
        (1, &production_origin, &fixture.production),
    ] {
        for mode in if managed {
            vec!["old", "retained", "retired", "legacy", "bare"]
        } else {
            OPTION_MODES.to_vec()
        } {
            let mut settings = config
                .clone()
                .base_url(origin)
                .base_path(path)
                .trusted_origin(config.base_url.clone())
                .trusted_origin(production_origin.clone());
            if mode == "environment" {
                settings = settings.base_url(&production_origin);
            }
            if mode == "dynamic" {
                settings.dynamic_base_url = Some(better_auth_core::config::DynamicBaseUrl {
                    allowed_hosts: vec!["localhost:*".into(), "127.0.0.1:*".into()],
                    protocol: Some(better_auth_core::config::BaseUrlProtocol::Http),
                    fallback: Some(origin.clone()),
                });
            }
            if mode == "error" {
                settings.api_error_url =
                    Some(format!("{}/configured-error?kept=yes", config.base_url));
            }
            if mode == "empty-error" {
                settings.api_error_url = Some(String::new());
            }
            if ["cache", "cache-error"].contains(&mode) {
                settings.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
                    enabled: true,
                    max_age: 120.0,
                    version: (mode == "cache-error").then(|| {
                        better_auth_core::CookieCacheVersion::Resolver(Arc::new(CacheFailure))
                    }),
                    ..Default::default()
                });
            }
            if cookie {
                settings.account.store_state_strategy =
                    better_auth_core::OAuthStateStrategy::Cookie;
            }
            if managed {
                const OLD: &str = "managed-old-reader-key-at-least-32-characters";
                const CURRENT: &str = "compat-test-only-key-not-real-minimum-32chars";
                const LEGACY: &str = "managed-legacy-reader-key-at-least-32-characters";
                settings.secret = LEGACY.into();
                settings.managed_secrets = match mode {
                    "old" => Some(better_auth_core::ManagedSecrets::new(0, OLD)),
                    "retained" => {
                        Some(better_auth_core::ManagedSecrets::new(2, CURRENT).retain(0, OLD))
                    }
                    "retired" => Some(better_auth_core::ManagedSecrets::new(2, CURRENT)),
                    "legacy" => Some(
                        better_auth_core::ManagedSecrets::new(2, CURRENT)
                            .retain(0, OLD)
                            .legacy(LEGACY),
                    ),
                    _ => None,
                };
            }
            let mut provider = OAuthProvider::gitlab_with_issuer(
                "proxy-fixture-client",
                "proxy-fixture-secret",
                &format!("{}{control}/provider", config.base_url),
            );
            provider.disable_sign_up = mode == "signup-disabled";
            let policy = provider.authorization.as_mut().expect("factory policy");
            policy.disable_sign_up_option =
                (mode != "signup-absent").then_some(mode == "signup-disabled");
            if ["custom", "bad-key"].contains(&mode) {
                policy.callback_path = Some("provider-return".into());
                policy.account_key = Some(OAuthAccountKey(Arc::new(AccountKey(mode == "bad-key"))));
            }
            let auth = Arc::new(
                AuthBuilder::<TestSchema>::new(settings.clone())
                    .store(
                        crate::backend::store::<TestSchema>(settings, db.clone())
                            .with_hooks(vec![Arc::new(SessionHooks(fixture.clone()))]),
                    )
                    .rate_limit(RateLimitConfig::new().enabled(false))
                    .plugin(EmailPasswordPlugin::new().enable_username(false))
                    .plugin(SessionManagementPlugin::new())
                    .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
                    .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                        current_url: (!["request", "dynamic", "environment", "environment-skip"]
                            .contains(&mode))
                        .then(|| origin.clone()),
                        max_age_seconds: match mode {
                            "fractional" => 0.125,
                            "nan" => f64::NAN,
                            "infinity" => f64::INFINITY,
                            "negative-infinity" => f64::NEG_INFINITY,
                            _ => 60.0,
                        },
                        production_url: (!["environment", "environment-skip"].contains(&mode))
                            .then(|| production_origin.clone()),
                        secret: (!managed).then(|| SECRET.into()),
                    }))
                    .plugin(CompletedRequests(fixture.clone()))
                    .build()
                    .await?,
            );
            routers.insert(
                (index, mode.to_owned()),
                Router::new().nest(path, auth.clone().axum_router().with_state(auth)),
            );
        }
    }
    let dispatch_modes = fixture.key_modes.clone();
    let router=Router::new().route(&format!("{path}/{{*rest}}"),any(move |mut request:Request|{
        if request.uri().path() == format!("{path}/provider-return") {
            let rewritten = format!("{path}/callback/gitlab{}", request.uri().query().map(|query| format!("?{query}")).unwrap_or_default());
            *request.uri_mut() = rewritten.parse().expect("fixture callback URI");
        }
        let index=usize::from(request.headers().get("host").and_then(|host|host.to_str().ok()).is_some_and(|host|host.starts_with("127.0.0.1:")));
        let modes=dispatch_modes.clone();let routers=routers.clone();
        async move {let mode=modes.lock().await[index].clone();let selected=routers.get(&(index,mode)).expect("configured runtime").clone();selected.oneshot(request).await}
    }))
    .route(&format!("{control}/keys"),post({let preview=config.base_url.clone();let production=production_origin.clone();move |State(fixture):State<Fixture>,Json(value):Json<Value>|{let preview=preview.clone();let production=production.clone();async move{
        let mode=value.get("mode").and_then(Value::as_str).unwrap_or("");let origin=value.get("origin").and_then(Value::as_str);
        if !managed || !["old","retained","retired","legacy","bare"].contains(&mode) || origin.is_some_and(|origin|origin!=preview&&origin!=production){return (StatusCode::BAD_REQUEST,Json(json!({"error":"Unknown key runtime"}))).into_response();}
        let mut modes=fixture.key_modes.lock().await;
        for(index,origin_value)in [preview,production].iter().enumerate(){if origin.is_none_or(|origin|origin==origin_value){modes[index]=mode.into();}}
        Json(json!({"status":true})).into_response()
    }}}))
    .route(&format!("{control}/options"),post({let preview=config.base_url.clone();let production=production_origin.clone();move |State(fixture):State<Fixture>,Json(value):Json<Value>|{let preview=preview.clone();let production=production.clone();async move{
        let mode=value.get("mode").and_then(Value::as_str).unwrap_or("");let origin=value.get("origin").and_then(Value::as_str);
        if managed || !OPTION_MODES.contains(&mode) || origin.is_some_and(|origin|origin!=preview&&origin!=production){return (StatusCode::BAD_REQUEST,Json(json!({"error":"Unknown option runtime"}))).into_response();}
        let mut modes=fixture.key_modes.lock().await;for(index,origin_value)in [preview,production].iter().enumerate(){if origin.is_none_or(|origin|origin==origin_value){modes[index]=mode.into();}}Json(json!({"status":true})).into_response()
    }}}))
    .route(&format!("{control}/state"),get(state))
    .route(&format!("{control}/control"),post(|State(fixture):State<Fixture>,Json(value):Json<Value>|async move{
        let mode=value.get("mode").and_then(Value::as_str).unwrap_or("none").to_owned();{let mut provider=fixture.provider.lock().await;provider.failure=mode.clone();provider.tracking=true;}let db=&fixture.preview;
        db.execute_raw(Statement::from_string(db.get_database_backend(),"DROP TRIGGER IF EXISTS proxy_delete_veto")).await.map_err(|e|e.to_string())?;
        if mode=="delete-veto" {db.execute_raw(Statement::from_string(db.get_database_backend(),"CREATE TRIGGER proxy_delete_veto BEFORE DELETE ON verifications BEGIN SELECT RAISE(ABORT, 'proxy delete veto'); END")).await.map_err(|e|e.to_string())?;}
        Ok::<_,String>(Json(json!({"status":true})))
    }))
    .route(&format!("{control}/profile"),post(|State(fixture):State<Fixture>,Json(value):Json<Value>|async move{fixture.provider.lock().await.profile=value;Json(json!({"status":true}))}))
    .route(&format!("{control}/provider/oauth/authorize"),get(authorize))
    .route(&format!("{control}/provider/oauth/token"),post(token))
    .route(&format!("{control}/provider/api/v4/user"),get(|State(fixture):State<Fixture>,headers:HeaderMap|async move{
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
