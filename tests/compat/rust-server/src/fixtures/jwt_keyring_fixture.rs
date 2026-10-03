//! Application-owned SQL key storage and actual public JWT callback receipts.
use crate::TestSchema;
use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use better_auth::plugins::jwt::{
    DefineJwtPayload, DefineJwtSubject, JwtAlgorithm, JwtClaimsConfig, JwtExpiration,
    JwtKeyPairConfig, JwtKeyring, JwtKeyringContext, JwtPlugin, JwtPluginConfig, JwtSession,
    JwtSignOptions,
};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use better_auth_core::{AuthRequest, CookieCacheConfig, CreateJwk, HttpMethod, Jwk};
use better_auth_seaorm::DatabaseConnection;
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, QueryResult, Statement};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Barrier, watch};

#[derive(Default)]
struct State {
    events: Mutex<Vec<Value>>,
    failure: Mutex<Option<Failure>>,
    race: Mutex<Option<Arc<Race>>>,
    writer: tokio::sync::Mutex<()>,
}
#[derive(Clone, Deserialize)]
struct Failure {
    operation: String,
    kind: String,
}
struct Race {
    first: watch::Sender<bool>,
    both: Barrier,
    second: watch::Sender<bool>,
}
impl Race {
    fn new() -> Self {
        Self {
            first: watch::channel(false).0,
            both: Barrier::new(2),
            second: watch::channel(false).0,
        }
    }
    async fn wait(sender: &watch::Sender<bool>) -> AuthResult<()> {
        let mut receiver = sender.subscribe();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            receiver.wait_for(|value| *value),
        )
        .await
        .map_err(|_| AuthError::internal("application keyring scheduling timeout"))?
        .map(|_| ())
        .map_err(|error| AuthError::internal(error.to_string()));
        result
    }
}
#[derive(Clone)]
struct Application {
    profile: String,
    mode: &'static str,
    database: DatabaseConnection,
    state: Arc<State>,
}
fn database_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::internal(error.to_string())
}
fn timestamp(value: i64) -> AuthResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(value).ok_or_else(|| AuthError::internal("key timestamp"))
}
fn stored(row: QueryResult) -> AuthResult<Jwk> {
    Ok(Jwk {
        id: row.try_get("", "id").map_err(database_error)?,
        public_key: row.try_get("", "publicKey").map_err(database_error)?,
        private_key: row.try_get("", "privateKey").map_err(database_error)?,
        created_at: timestamp(row.try_get("", "createdAt").map_err(database_error)?)?,
        expires_at: row
            .try_get::<Option<i64>>("", "expiresAt")
            .map_err(database_error)?
            .map(timestamp)
            .transpose()?,
        alg: row.try_get("", "alg").map_err(database_error)?,
        crv: row.try_get("", "crv").map_err(database_error)?,
    })
}
fn observed(key: &Jwk) -> Value {
    json!({"id":key.id,"publicKey":serde_json::from_str::<Value>(&key.public_key).unwrap_or_else(|_|json!(key.public_key)),"privateKeyEncrypted":serde_json::from_str::<Value>(&key.private_key).is_ok_and(|value|value.is_string()),
        "createdAt":key.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),"expiresAt":key.expires_at.map(|value|value.to_rfc3339_opts(SecondsFormat::Millis,true)),"alg":key.alg,"crv":key.crv})
}
fn context(context: &JwtKeyringContext<'_>) -> Value {
    let request = context.request;
    json!({"path":context.path,"method":request.map(|request|format!("{:?}",request.method()).to_uppercase()),"marker":request.and_then(|request|request.headers.get("x-keyring-proof")),"hasCookie":request.is_some_and(|request|request.headers.get("cookie").is_some_and(|value|!value.is_empty()))})
}
fn snapshot(session: &JwtSession) -> AuthResult<Value> {
    let mut value = serde_json::to_value(session)?;
    if let Some(clock) = value.get("updatedAt") {
        let milliseconds = clock
            .as_f64()
            .ok_or_else(|| AuthError::internal("invalid cache clock"))?
            .to_string()
            .parse::<i64>()
            .map_err(database_error)?;
        let date = DateTime::from_timestamp_millis(milliseconds)
            .ok_or_else(|| AuthError::internal("invalid cache clock"))?;
        value["updatedAt"] = json!(date.to_rfc3339_opts(SecondsFormat::Millis, true));
        value["updatedAtType"] = json!("number");
    }
    Ok(value)
}
impl Application {
    async fn rows(&self) -> AuthResult<Vec<Jwk>> {
        self.database
            .query_all_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT * FROM fixtureJwtKeyring WHERE profile=? ORDER BY rowId",
                [self.profile.clone().into()],
            ))
            .await
            .map_err(database_error)?
            .into_iter()
            .map(stored)
            .collect()
    }
    fn record(&self, event: Value) -> AuthResult<()> {
        self.state
            .events
            .lock()
            .map_err(database_error)?
            .push(event);
        Ok(())
    }
    fn reject(&self, operation: &str) -> AuthResult<()> {
        let failed = self.state.failure.lock().map_err(database_error)?.clone();
        if let Some(failed) = failed.filter(|failed| failed.operation == operation) {
            return Err(if failed.kind == "api" {
                AuthError::Upstream {
                    status: 403,
                    code: "APPLICATION_KEYRING_DENIED",
                    message: "application denied keys",
                }
            } else if failed.kind == "api500" {
                AuthError::Api {
                    status: 500,
                    code: Some("APPLICATION_KEYRING_DENIED".into()),
                    message: "application denied keys".into(),
                }
            } else {
                AuthError::internal("application keyring failed")
            });
        }
        Ok(())
    }
    fn race(&self) -> AuthResult<Option<Arc<Race>>> {
        Ok(self.state.race.lock().map_err(database_error)?.clone())
    }
    async fn state(&self) -> AuthResult<Value> {
        Ok(
            json!({"keys":self.rows().await?.iter().map(observed).collect::<Vec<_>>(),"events":self.state.events.lock().map_err(database_error)?.clone()}),
        )
    }
}
#[async_trait::async_trait]
impl JwtKeyring for Application {
    async fn keys(&self, ctx: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
        let request = ctx.request;
        let scheduled = self.race()?;
        let marker = request
            .and_then(|request| request.headers.get("x-keyring-proof"))
            .map(String::as_str);
        if marker == Some("race-second") {
            if let Some(scheduled) = &scheduled {
                Race::wait(&scheduled.first).await?;
            }
        }
        let result = self.rows().await?;
        self.record(json!({"operation":"read","profile":self.profile,"context":context(ctx),"ids":result.iter().map(|key|&key.id).collect::<Vec<_>>()}))?;
        self.reject("read")?;
        if result.is_empty() && matches!(marker, Some("race-first" | "race-second")) {
            if let Some(scheduled) = scheduled {
                if marker == Some("race-first") {
                    let _previous = scheduled.first.send_replace(true);
                }
                let _waited =
                    tokio::time::timeout(std::time::Duration::from_secs(10), scheduled.both.wait())
                        .await
                        .map_err(database_error)?;
            }
        }
        Ok(result)
    }
    async fn create_key(&self, key: CreateJwk, ctx: &JwtKeyringContext<'_>) -> AuthResult<Jwk> {
        let request = ctx.request;
        if request
            .and_then(|request| request.headers.get("x-keyring-proof"))
            .is_some_and(|marker| marker == "race-second")
        {
            if let Some(scheduled) = self.race()? {
                Race::wait(&scheduled.second).await?;
            }
        }
        self.record(json!({"operation":"create","profile":self.profile,"context":context(ctx),"key":{"publicKey":serde_json::from_str::<Value>(&key.public_key)?,"privateKeyEncrypted":serde_json::from_str::<Value>(&key.private_key).is_ok_and(|value|value.is_string()),
            "createdAt":key.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),"expiresAt":key.expires_at.map(|value|value.to_rfc3339_opts(SecondsFormat::Millis,true)),"alg":key.alg,"crv":key.crv}}))?;
        self.reject("create")?;
        let _writer = self.state.writer.lock().await;
        let inserted=self.database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"INSERT INTO fixtureJwtKeyring(profile,publicKey,privateKey,createdAt,expiresAt,alg,crv) VALUES(?,?,?,?,?,?,?)",
            [self.profile.clone().into(),key.public_key.into(),key.private_key.into(),key.created_at.timestamp_millis().into(),key.expires_at.map(|value|value.timestamp_millis()).into(),key.alg.into(),key.crv.into()]))
            .await.map_err(database_error)?;
        let row_id = inserted.last_insert_id();
        let id = format!("application-key-{row_id}");
        self.database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE fixtureJwtKeyring SET id=? WHERE rowId=?",
                [id.clone().into(), row_id.into()],
            ))
            .await
            .map_err(database_error)?;
        self.rows()
            .await?
            .into_iter()
            .find(|key| key.id == id)
            .ok_or_else(|| AuthError::internal("persisted application key"))
    }
}
#[async_trait::async_trait]
impl DefineJwtPayload for Application {
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
        let session = snapshot(session)?;
        self.record(json!({"operation":"payload","profile":self.profile,"session":session}))?;
        self.reject("payload")?;
        json!({"iat":100,"exp":4_102_444_800_u64,"application":"external-keyring","snapshot":session})
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("application payload"))
    }
}
#[async_trait::async_trait]
impl DefineJwtSubject for Application {
    async fn subject(&self, session: &JwtSession) -> AuthResult<Option<String>> {
        self.record(
            json!({"operation":"subject","profile":self.profile,"session":snapshot(session)?}),
        )?;
        self.reject("subject")?;
        let input = serde_json::to_value(session)?;
        Ok(match self.mode {
            "empty-subject" => Some(String::new()),
            "null-subject" => None,
            "custom-cache" => Some(format!(
                "{}|version:{}|clock:{}",
                session.user.email.as_deref().unwrap_or_default(),
                input
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("absent"),
                if input.get("updatedAt").is_some_and(Value::is_number) {
                    "number"
                } else {
                    "undefined"
                }
            )),
            _ => session.user.email.clone(),
        })
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    operation: String,
    profile: Option<String>,
    failure: Option<Failure>,
    id: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    field: Option<String>,
    payload: Option<better_auth_core::utils::json::JsValue>,
    token: Option<String>,
    issuer: Option<String>,
    header: Option<Map<String, Value>>,
    signing_key_id: Option<String>,
    signing_algorithm: Option<JwtAlgorithm>,
    expiration: Option<Expiration>,
    #[serde(default)]
    absent_request: bool,
}
#[derive(Deserialize)]
struct Expiration {
    number: Option<f64>,
    #[serde(default)]
    nan: bool,
    nonfinite: Option<String>,
    date: Option<DateTime<Utc>>,
    milliseconds: Option<i64>,
}
impl Expiration {
    fn value(self) -> AuthResult<JwtExpiration> {
        if self.nan {
            return Ok(JwtExpiration::Numeric(f64::NAN));
        }
        if let Some(kind) = self.nonfinite {
            return Ok(JwtExpiration::Numeric(if kind == "positive" {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }));
        }
        if let Some(date) = self.date {
            return Ok(JwtExpiration::At(date));
        }
        if let Some(milliseconds) = self.milliseconds {
            return Ok(JwtExpiration::After(Duration::milliseconds(milliseconds)));
        }
        self.number
            .map(JwtExpiration::Numeric)
            .ok_or_else(|| AuthError::bad_request("expiration"))
    }
}
fn failure_response(error: AuthError) -> axum::response::Response {
    tracing::error!(%error,"Application keyring control failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message":"Internal server error"})),
    )
        .into_response()
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    database.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TABLE IF NOT EXISTS fixtureJwtKeyring(rowId INTEGER PRIMARY KEY AUTOINCREMENT,profile TEXT NOT NULL,id TEXT,publicKey TEXT NOT NULL,privateKey TEXT NOT NULL,createdAt INTEGER NOT NULL,expiresAt INTEGER,alg TEXT,crv TEXT)"))
        .await.map_err(database_error)?;
    let state = Arc::new(State::default());
    let mut profiles = HashMap::new();
    let mut router = Router::new();
    for mode in [
        "standard",
        "plain",
        "cache",
        "custom-cache",
        "empty-subject",
        "null-subject",
    ] {
        let name = format!("jwt-keyring-{mode}");
        let app = Arc::new(Application {
            profile: name.clone(),
            mode,
            database: database.clone(),
            state: state.clone(),
        });
        let mut options = JwtPluginConfig {
            keyring: Some(app.clone()),
            define_payload: Some(app.clone()),
            define_subject: Some(app.clone()),
            additional_key_pairs: vec![JwtKeyPairConfig {
                algorithm: JwtAlgorithm::Es256,
                modulus_length: None,
            }],
            ..Default::default()
        };
        if mode == "cache" {
            options.define_payload = None;
            options.define_subject = None;
        }
        if mode == "plain" {
            options.key_pair = JwtKeyPairConfig {
                algorithm: JwtAlgorithm::Rs256,
                modulus_length: Some(3072),
            };
            options.disable_private_key_encryption = true;
            options.rotation_interval = Some(Duration::hours(1));
            options.grace_period = Duration::hours(1);
        }
        let jwt = JwtPlugin::with_config(options);
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if matches!(mode, "cache" | "custom-cache") {
            config = config.session_cookie_cache(CookieCacheConfig {
                enabled: true,
                ..Default::default()
            });
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(true),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(jwt.clone())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        drop(profiles.insert(name, (auth, jwt, app)));
    }
    let profiles = Arc::new(profiles);
    Ok(router.route("/__test/jwt-keyring",post(move|headers:HeaderMap,body:Bytes|{
        let profiles=profiles.clone();let database=database.clone();let state=state.clone();
        async move {
            let result=async {
                let request_body=body.to_vec();
                let body:Control=better_auth_core::utils::json::from_slice(&body)?;
                let (auth,jwt,app)=profiles.get(body.profile.as_deref().unwrap_or("jwt-keyring-standard")).ok_or_else(||AuthError::bad_request("unknown keyring profile"))?;
                match body.operation.as_str() {
                    "reset"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DELETE FROM fixtureJwtKeyring")).await.map_err(database_error)?;database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DELETE FROM sqlite_sequence WHERE name='fixtureJwtKeyring'")).await.map_err(database_error)?;state.events.lock().map_err(database_error)?.clear();*state.failure.lock().map_err(database_error)?=None;*state.race.lock().map_err(database_error)?=None;}
                    "clear-events"=>state.events.lock().map_err(database_error)?.clear(),
                    "failure"=>*state.failure.lock().map_err(database_error)?=body.failure,
                    "race-arm"=>{*state.race.lock().map_err(database_error)?=Some(Arc::new(Race::new()));return Ok(json!({"armed":true}));},
                    "race-release"=>{if let Some(scheduled)=app.race()? {let _previous=scheduled.second.send_replace(true);}return Ok(json!({"released":true}));},
                    "expire"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE fixtureJwtKeyring SET expiresAt=? WHERE profile=? AND id=?",[body.expires_at.ok_or_else(||AuthError::bad_request("expiresAt"))?.timestamp_millis().into(),app.profile.clone().into(),body.id.into()])).await.map_err(database_error)?;},
                    "corrupt"=>{let (query,value)=if body.field.as_deref()==Some("public") {("UPDATE fixtureJwtKeyring SET publicKey=? WHERE profile=? AND id=?","corrupt")}else{("UPDATE fixtureJwtKeyring SET privateKey=? WHERE profile=? AND id=?","\"corrupt\"")};database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,query,[value.into(),app.profile.clone().into(),body.id.into()])).await.map_err(database_error)?;},
                    "legacy"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"UPDATE fixtureJwtKeyring SET alg=NULL,crv=NULL WHERE profile=? AND id=?",[app.profile.clone().into(),body.id.into()])).await.map_err(database_error)?;},
                    "delete"=>{database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"DELETE FROM fixtureJwtKeyring WHERE profile=? AND id=?",[app.profile.clone().into(),body.id.into()])).await.map_err(database_error)?;},
                    "verify"=>{let mut request=AuthRequest::new(HttpMethod::Post,"/__test/jwt-keyring");request.body=Some(request_body.clone());request.headers=headers.iter().filter_map(|(key,value)|value.to_str().ok().map(|value|(key.to_string(),value.to_owned()))).collect();return Ok(json!({"payload":jwt.verify_jwt(body.token.as_deref().ok_or_else(||AuthError::bad_request("token"))?,body.issuer.as_deref(),(!body.absent_request).then_some(&request),auth.context()).await?}));},
                    "sign"|"resolve-sign"|"create"|"api-sign"=>{
                        let mut request=AuthRequest::new(HttpMethod::Post,"/__test/jwt-keyring");
                        request.body=Some(request_body.clone());request.headers=headers.iter().filter_map(|(key,value)|value.to_str().ok().map(|value|(key.to_string(),value.to_owned()))).collect();
                        let mut options=JwtSignOptions {header:body.header,signing_key_id:body.signing_key_id,signing_algorithm:body.signing_algorithm,claims:body.expiration.map(|expiration|expiration.value().map(|expiration|JwtClaimsConfig {expiration,..Default::default()})).transpose()?,..Default::default()};
                        let request=(!body.absent_request).then_some(&request);
                        if body.operation=="create" {jwt.create_jwk(None,request,auth.context()).await?;return Ok(json!({"created":true}));}
                        let payload=body.payload.ok_or_else(||AuthError::bad_request("payload"))?;
                        if body.operation=="resolve-sign" {options.resolved_key=jwt.resolve_signing_key(&options,request,auth.context()).await?.map(Arc::new);}
                        return Ok(json!({"token":jwt.sign_jwt_json(&payload,&options,request,auth.context()).await?}));
                    }
                    "state"=>{},_=>return Err(AuthError::bad_request("unknown keyring operation")),
                }
                app.state().await
            }.await;
            match result {Ok(value)=>Json(value).into_response(),Err(error)=>failure_response(error)}
        }
    })))
}
