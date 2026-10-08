//! A real auth store and one-use local OAuth provider for popup acceptance.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{CorsConfig, RateLimitConfig};
use alibi::plugins::oauth::OAuthProvider;
use alibi::plugins::{BearerPlugin, OAuthPlugin, OAuthPopupPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::sea_orm::{ActiveModelTrait, EntityTrait, Set};
use alibi_seaorm::store::entities::{account, session, user, verification};
use alibi_seaorm::{Database, DatabaseConnection};
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
const PATH: &str = "/__test/profiles/oauth-popup/api/auth";
const CONTROL: &str = "/__test/oauth-popup";
struct Grant {
    challenge: String,
    redirect: String,
    used: bool,
}
#[derive(Default)]
struct Provider {
    grants: HashMap<String, Grant>,
    receipts: Vec<Value>,
    count: usize,
    hold: bool,
}
#[derive(Clone)]
struct Fixture {
    database: DatabaseConnection,
    provider: Arc<Mutex<Provider>>,
}

pub(crate) async fn router(config: &AuthConfig) -> AuthResult<Router> {
    let database = Database::connect(crate::sqlite_fixture::options())
        .await
        .map_err(|e| alibi::AuthError::internal(e.to_string()))?;
    crate::backend::migrate(&database)
        .await
        .map_err(|e| alibi::AuthError::internal(e.to_string()))?;
    let fixture = Fixture {
        database: database.clone(),
        provider: Arc::new(Mutex::new(Provider::default())),
    };
    let settings = config
        .clone()
        .base_path(PATH)
        .trusted_origin("http://app.fixture.test")
        .trusted_origin(config.base_url.clone())
        .trusted_origin(config.base_url.replace("localhost", "127.0.0.1"));
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(settings.clone())
            .store(crate::backend::store::<TestSchema>(settings, database))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .cors(
                CorsConfig::new()
                    .allowed_origin("http://app.fixture.test")
                    .allowed_origin(config.base_url.clone())
                    .allowed_origin(config.base_url.replace("localhost", "127.0.0.1")),
            )
            .plugin(SessionManagementPlugin::new())
            .plugin(BearerPlugin::new())
            .plugin(
                OAuthPlugin::new()
                    .add_provider(
                        "local",
                        OAuthProvider::gitlab_with_issuer(
                            "popup-client",
                            "popup-secret",
                            &format!("{}{CONTROL}/provider", config.base_url),
                        ),
                    )
                    .add_provider(
                        "gitlab",
                        OAuthProvider::gitlab_with_issuer(
                            "popup-client",
                            "popup-secret",
                            &format!("{}{CONTROL}/provider", config.base_url),
                        ),
                    ),
            )
            .plugin(OAuthPopupPlugin::new())
            .build()
            .await?,
    );
    Ok(Router::new().nest(PATH,auth.clone().axum_router().with_state(auth))
        .merge(Router::new()
        .route(&format!("{CONTROL}/hold"),post(|State(f):State<Fixture>|async move {f.provider.lock().await.hold=true;Json(json!({"status":true}))}))
        .route(&format!("{CONTROL}/state"),get(state))
        .route(&format!("{CONTROL}/reset"),post(reset))
        .route(&format!("{CONTROL}/expire"),post(expire))
        .route(&format!("{CONTROL}/provider/oauth/authorize"),get(authorize))
        .route(&format!("{CONTROL}/provider/oauth/token"),post(token))
        .route(&format!("{CONTROL}/provider/api/v4/user"),get(|State(f):State<Fixture>,headers:HeaderMap|async move {
            f.provider.lock().await.receipts.push(json!({"stage":"userinfo","authorization":headers.get("authorization").and_then(|v|v.to_str().ok())}));
            Json(json!({"id":132,"email":"popup-owner@fixture.test","email_verified":true,"name":"Popup Owner","avatar_url":"https://assets.fixture.test/popup.png","state":"active","locked":false}))
        })).with_state(fixture)))
}
async fn authorize(
    State(f): State<Fixture>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let mut p = f.provider.lock().await;
    if p.hold {
        return axum::response::Html("<title>Provider awaiting approval</title>").into_response();
    }
    p.receipts.push(json!({"stage":"authorize","query":query}));
    p.count += 1;
    let code = format!("popup-code-{}", p.count);
    let (Some(redirect), Some(challenge), Some(state)) = (
        query.get("redirect_uri"),
        query.get("code_challenge"),
        query.get("state"),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(mut callback) = url::Url::parse(redirect) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    callback
        .query_pairs_mut()
        .append_pair("state", state)
        .append_pair("code", &code);
    p.grants.insert(
        code,
        Grant {
            challenge: challenge.clone(),
            redirect: redirect.clone(),
            used: false,
        },
    );
    (StatusCode::FOUND, [("location", callback.to_string())]).into_response()
}
async fn token(State(f): State<Fixture>, Form(body): Form<HashMap<String, String>>) -> Response {
    let mut p = f.provider.lock().await;
    p.receipts.push(json!({"stage":"token","body":body}));
    let Some(grant) = body.get("code").and_then(|code| p.grants.get_mut(code)) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    };
    if grant.used
        || body.get("redirect_uri") != Some(&grant.redirect)
        || !body.get("code_verifier").is_some_and(|v| {
            URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == grant.challenge
        })
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response();
    }
    grant.used = true;
    Json(json!({"access_token":"popup-access","refresh_token":"popup-refresh","token_type":"Bearer","scope":"read_user","expires_in":3600})).into_response()
}
async fn reset(State(f): State<Fixture>) -> Result<Json<Value>, String> {
    session::Entity::delete_many()
        .exec(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    account::Entity::delete_many()
        .exec(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    verification::Entity::delete_many()
        .exec(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    user::Entity::delete_many()
        .exec(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    *f.provider.lock().await = Provider::default();
    Ok(Json(json!({"status":true})))
}
async fn expire(State(f): State<Fixture>) -> Result<Json<Value>, String> {
    for row in verification::Entity::find()
        .all(&f.database)
        .await
        .map_err(|e| e.to_string())?
    {
        let mut value: Value = serde_json::from_str(&row.value).map_err(|e| e.to_string())?;
        value["expiresAt"] = json!(0);
        let mut row: verification::ActiveModel = row.into();
        row.value = Set(value.to_string());
        row.expires_at = Set(chrono::DateTime::UNIX_EPOCH);
        row.update(&f.database).await.map_err(|e| e.to_string())?;
    }
    Ok(Json(json!({"status":true})))
}
async fn state(State(f): State<Fixture>) -> Result<Json<Value>, String> {
    let users = user::Entity::find()
        .all(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    let accounts = account::Entity::find()
        .all(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    let sessions = session::Entity::find()
        .all(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    let verification = verification::Entity::find()
        .all(&f.database)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Json(json!({
        "user":users.iter().map(|r|json!({"id":r.id,"name":r.name,"email":r.email,"emailVerified":r.email_verified,"image":r.image,"createdAt":r.created_at,"updatedAt":r.updated_at})).collect::<Vec<_>>(),
        "account":accounts.iter().map(|r|json!({"id":r.id,"userId":r.user_id,"providerId":r.provider_id,"accountId":r.account_id,"accessToken":r.access_token,"refreshToken":r.refresh_token,"idToken":r.id_token,"password":r.password,"scope":r.scope,"accessTokenExpiresAt":r.access_token_expires_at,"refreshTokenExpiresAt":r.refresh_token_expires_at,"createdAt":r.created_at,"updatedAt":r.updated_at})).collect::<Vec<_>>(),
        "session":sessions.iter().map(|r|json!({"id":r.id,"userId":r.user_id,"token":r.token,"ipAddress":r.ip_address,"userAgent":r.user_agent,"createdAt":r.created_at,"updatedAt":r.updated_at,"expiresAt":r.expires_at})).collect::<Vec<_>>(),
        "verification":verification.iter().map(|r|json!({"id":r.id,"identifier":r.identifier,"value":r.value,"createdAt":r.created_at,"updatedAt":r.updated_at,"expiresAt":r.expires_at})).collect::<Vec<_>>(),
        "receipts":f.provider.lock().await.receipts
    })))
}
