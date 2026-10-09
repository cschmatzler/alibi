//! Trusted bridge to the actual server-only password operation.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::password_management::set_password;
use alibi::plugins::{
    EmailPasswordConfig, EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi::utils::password::{PasswordHasher, ScryptHasher};
use alibi::{AuthRequest, CookieCacheConfig, HttpMethod};
use alibi::seaorm::{
    DatabaseConnection,
    sea_orm::{
        ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel,
        QueryFilter, QueryOrder, Set, Statement,
    },
    store::entities::{account, session, user},
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Barrier;
#[derive(Default)]
struct Application {
    mode: Mutex<String>,
    events: Mutex<Vec<Value>>,
    barrier: Mutex<Option<Arc<Barrier>>>,
    database: Option<DatabaseConnection>,
    ordinal: AtomicUsize,
    first_hash: Mutex<Option<String>>,
    watch_user_id: Mutex<String>,
}
#[async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let mode = self.mode.lock().unwrap().clone();
        let order = (mode == "barrier").then(|| self.ordinal.fetch_add(1, Ordering::SeqCst));
        let mut entered = json!({"stage":"hash-enter", "password":password});
        if let Some(order) = order {
            entered["order"] = json!(order);
        }
        self.events.lock().unwrap().push(entered);
        let hash = ScryptHasher.hash(password).await?;
        if mode == "barrier" {
            if order == Some(0) {
                *self.first_hash.lock().unwrap() = Some(hash.clone());
            }
            let barrier = self.barrier.lock().unwrap().clone().unwrap();
            let _ = barrier.wait().await;
            if order == Some(1) {
                let first = self.first_hash.lock().unwrap().clone().unwrap();
                let user = self.watch_user_id.lock().unwrap().clone();
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    let stored = account::Entity::find()
                        .filter(account::Column::UserId.eq(user.clone()))
                        .filter(account::Column::Password.eq(first.clone()))
                        .one(self.database.as_ref().unwrap())
                        .await
                        .map_err(database_error)?;
                    if stored.is_some() {
                        break;
                    }
                    if tokio::time::Instant::now() > deadline {
                        return Err(AuthError::internal(
                            "Actual credential write did not complete",
                        ));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        let mut completed = json!({"stage":"hash-result", "password":password, "hash":hash});
        if let Some(order) = order {
            completed["order"] = json!(order);
        }
        self.events.lock().unwrap().push(completed);
        if mode == "hash-error" {
            return Err(AuthError::internal(
                "Actual configured hash callback failed",
            ));
        }
        Ok(hash)
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        if *self.mode.lock().unwrap() == "schema-observe" {
            self.events
                .lock()
                .unwrap()
                .push(json!({"stage":"verify-enter","password":password}));
        }
        ScryptHasher.verify(hash, password).await
    }
}
fn database_error(error: alibi::seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
fn failure(error: AuthError) -> axum::response::Response {
    if error.status_code() == 500 {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message":"Internal server error"})),
        )
            .into_response()
    } else {
        error.into_response()
    }
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let app = Arc::new(Application {
        database: Some(database.clone()),
        ..Default::default()
    });
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in [
        "set-password-default",
        "set-password-policy",
        "set-password-cache",
        "set-password-schema",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name == "set-password-cache" {
            config = config.session_cookie_cache(CookieCacheConfig {
                enabled: true,
                max_age: 300.0,
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
                .plugin(EmailPasswordPlugin::with_config(EmailPasswordConfig {
                    password_min_length: if name == "set-password-policy" { 10 } else { 8 },
                    password_max_length: if name == "set-password-policy" {
                        20
                    } else {
                        128
                    },
                    password_hasher: Some(app.clone()),
                    enable_username: false,
                    ..Default::default()
                }))
                .plugin(alibi::plugins::PasswordManagementPlugin::with_config(
                    alibi::plugins::PasswordManagementConfig {
                        password_hasher: Some(app.clone()),
                        ..Default::default()
                    },
                ))
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name, auth);
    }
    let profiles = Arc::new(profiles);
    let state_profiles = profiles.clone();
    let state_app = app.clone();
    let state_db = database.clone();
    router=router.route("/__test/set-password/state",get(move ||{let profiles=state_profiles.clone();let app=state_app.clone();let db=state_db.clone();async move {
  let result:AuthResult<Value>=async {
   let auth=profiles.get("set-password-default").unwrap();
   let users=user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&db).await.map_err(database_error)?;
   let accounts=account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&db).await.map_err(database_error)?;
   let sessions=session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&db).await.map_err(database_error)?;
   let accounts=accounts.iter().map(|row|{let mut value=serde_json::to_value(alibi::wire::AccountView::from(row)).unwrap();value["password"]=json!(row.password);value}).collect::<Vec<_>>();
   Ok(json!({"users":users.iter().map(|row|auth.context().user_view(row)).collect::<Vec<_>>(),"accounts":accounts,"sessions":sessions.iter().map(|row|auth.context().session_view(row)).collect::<Vec<_>>(),"events":*app.events.lock().unwrap()}))
  }.await;match result{Ok(value)=>Json(value).into_response(),Err(error)=>failure(error)}
 }}));
    let handler = post(move |headers: HeaderMap, Json(body): Json<Value>| {
        let profiles = profiles.clone();
        let app = app.clone();
        let db = database.clone();
        async move {
            let mut request = AuthRequest::new(HttpMethod::Post, "/__test/set-password");
            for (name, value) in &headers {
                if let Ok(value) = value.to_str() {
                    let _ = request
                        .headers
                        .insert(name.as_str().to_owned(), value.to_owned());
                }
            }
            let operation:AuthResult<Value>=async {
    let profile=body.get("profile").and_then(Value::as_str).unwrap_or("set-password-default");let auth: &Arc<BetterAuth<TestSchema>>=profiles.get(profile).ok_or_else(||AuthError::bad_request("unknown fixture profile"))?;
    let op=body.get("operation").and_then(Value::as_str).unwrap_or_default();
    if op=="mode" {let mode=body.get("mode").and_then(Value::as_str).unwrap_or("normal");*app.mode.lock().unwrap()=mode.to_owned();app.events.lock().unwrap().clear();app.ordinal.store(0, Ordering::SeqCst);*app.first_hash.lock().unwrap()=None;*app.watch_user_id.lock().unwrap()=body.get("userId").and_then(Value::as_str).unwrap_or_default().to_owned();*app.barrier.lock().unwrap()=Some(Arc::new(Barrier::new(2)));return Ok(json!({"status":true,"mode":mode}));}
    if op=="misbind-credential" {let id=body.get("accountId").and_then(Value::as_str).unwrap_or_default();let row=account::Entity::find_by_id(id).one(&db).await.map_err(database_error)?.ok_or_else(||AuthError::bad_request("missing account"))?;let mut model=row.into_active_model();model.account_id=Set(body.get("userId").and_then(Value::as_str).unwrap_or_default().to_owned());model.password=Set(None);model.updated_at=Set(chrono::Utc::now());drop(model.update(&db).await.map_err(database_error)?);return Ok(json!({"status":true}));}
    if op=="clear-password" {let id=body.get("accountId").and_then(Value::as_str).unwrap_or_default();let row=account::Entity::find_by_id(id).one(&db).await.map_err(database_error)?.ok_or_else(||AuthError::bad_request("missing account"))?;let mut model=row.into_active_model();model.password=Set(None);model.updated_at=Set(chrono::Utc::now());drop(model.update(&db).await.map_err(database_error)?);return Ok(json!({"status":true}));}
    if op=="revoke" {auth.store().delete_session(body.get("token").and_then(Value::as_str).unwrap_or_default()).await?;return Ok(json!({"status":true}));}
    if op=="expire" {let token=body.get("token").and_then(Value::as_str).unwrap_or_default();let timestamp=body.get("expiresAt").and_then(Value::as_str).unwrap_or_default();let expires=chrono::DateTime::parse_from_rfc3339(timestamp).map_err(|error|AuthError::internal(error.to_string()))?.with_timezone(&chrono::Utc);let row=session::Entity::find().filter(session::Column::Token.eq(token)).one(&db).await.map_err(database_error)?.ok_or_else(||AuthError::bad_request("missing session"))?;let mut row=row.into_active_model();row.expires_at=Set(expires);row.updated_at=Set(expires);drop(row.update(&db).await.map_err(database_error)?);return Ok(json!({"status":true}));}
    if op!="set"{return Err(AuthError::bad_request("unknown operation"));}
    if let Some(token)=headers.get("x-test-virtual-token").and_then(|value|value.to_str().ok()){if let Some(physical)=auth.store().get_session(token).await?{let user=auth.store().get_user_by_id(&physical.user_id).await?.ok_or_else(||AuthError::bad_request("missing virtual user"))?;let view=auth.context().session_view(&physical);app.events.lock().unwrap().push(json!({"stage":"virtual-session","session":view,"user":auth.context().user_view(&user)}));request.set_virtual_session(view);}}
    let mode=app.mode.lock().unwrap().clone();let trigger=mode=="create-error"||mode=="update-error";
    if trigger{let verb=if mode=="create-error"{"INSERT"}else{"UPDATE"};db.execute_raw(Statement::from_string(DbBackend::Sqlite,format!("CREATE TEMP TRIGGER set_password_store_failure BEFORE {verb} ON accounts WHEN NEW.provider_id='credential' BEGIN SELECT RAISE(ABORT, 'Actual configured credential write failed'); END"))).await.map_err(database_error)?;}
    let result=set_password(&request,body.get("newPassword").and_then(Value::as_str).unwrap_or_default(),auth.context()).await;
    if trigger{db.execute_raw(Statement::from_string(DbBackend::Sqlite,"DROP TRIGGER set_password_store_failure")).await.map_err(database_error)?;}
    result?;Ok(json!({"status":true}))
   }.await;
            let mut response = match operation {
                Ok(value) => Json(value).into_response(),
                Err(error) => failure(error),
            };
            for (name, value) in request.take_response_headers().iter() {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::from_bytes(name.as_bytes()),
                    axum::http::HeaderValue::from_str(value),
                ) {
                    let _ = response.headers_mut().append(name, value);
                }
            }
            if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
                let _ = response.headers_mut().insert(
                    "content-type",
                    axum::http::HeaderValue::from_static("application/json;charset=utf-8"),
                );
            }
            response
        }
    });
    router = router
        .route("/__test/set-password", handler.clone())
        .route("/__test/server-api/set-password", handler);
    Ok(router)
}
