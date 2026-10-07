use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::api_key::{
    ApiKeyConfig, ApiKeyErrorCode, ApiKeyGenerationOptions, ApiKeyGenerator, ApiKeyReferences,
    ApiKeyStorage, ApiKeyStorageMode, ApiKeyVerificationError, CreateKeyRequest,
    KeyExpirationConfig, RateLimitDefaults, VerifyApiKey,
};
use alibi::plugins::{
    ApiKeyPlugin, EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi_core::{BackgroundTaskCompletion, BackgroundTaskHandler, store::CacheAdapter};
use alibi_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{oneshot, watch};

#[derive(Clone)]
struct Entry {
    value: String,
    expires_at: Option<i64>,
}
#[derive(Default)]
struct State {
    maps: HashMap<String, HashMap<String, Entry>>,
    generated: usize,
    failure: String,
    fail_store: String,
    hold_store: String,
    hash_reads: usize,
    hold_at: i64,
    capture_before_wait: bool,
    hold_operation: String,
    entered: usize,
    blocked: Vec<oneshot::Sender<()>>,
    active: usize,
}
#[derive(Clone)]
pub(crate) struct Application {
    state: Arc<Mutex<State>>,
    changed: watch::Sender<usize>,
}
impl Application {
    fn notify(&self) {
        self.changed.send_modify(|value| *value += 1);
    }
    fn release(&self) {
        let senders = {
            let mut state = self.state.lock().unwrap();
            state.hold_at = -1;
            state.hold_operation.clear();
            std::mem::take(&mut state.blocked)
        };
        for sender in senders {
            let _ = sender.send(());
        }
    }
    pub(crate) async fn reset(&self) {
        self.release();
        self.drain().await;
        *self.state.lock().unwrap() = State {
            hold_at: -1,
            maps: ["secondary", "custom", "isolated"]
                .into_iter()
                .map(str::to_owned)
                .chain((0..32).map(|group| format!("group-{group}")))
                .map(|name| (name, HashMap::new()))
                .collect(),
            ..Default::default()
        };
    }
    async fn drain(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            if self.state.lock().unwrap().active == 0 {
                return;
            }
            let _ = changed.changed().await;
        }
    }
    async fn wait(&self, count: usize) {
        let mut changed = self.changed.subscribe();
        loop {
            if self.state.lock().unwrap().entered >= count {
                return;
            }
            let _ = changed.changed().await;
        }
    }
    fn read(&self, store: &str, key: &str) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        let map = state.maps.get_mut(store).unwrap();
        if map.get(key).is_some_and(|entry| {
            entry
                .expires_at
                .is_some_and(|expiry| expiry <= Utc::now().timestamp_millis())
        }) {
            map.remove(key);
            return None;
        }
        map.get(key).map(|entry| entry.value.clone())
    }
    async fn snapshot(&self, database: &DatabaseConnection) -> Value {
        let maps = self.state.lock().unwrap().maps.clone();
        let mut result = Vec::new();
        for name in ["secondary", "custom", "isolated"]
            .into_iter()
            .map(str::to_owned)
            .chain((0..32).map(|group| format!("group-{group}")))
        {
            let mut entries = Vec::new();
            for (index, entry) in &maps[&name] {
                if !index.starts_with("api-key:") {
                    continue;
                }
                let mut value: Value = serde_json::from_str(&entry.value).unwrap();
                let (namespace, lookup, order) =
                    if let Some(reference) = index.strip_prefix("api-key:by-ref:") {
                        let email = database
                            .query_one_raw(Statement::from_sql_and_values(
                                DbBackend::Sqlite,
                                "SELECT email FROM users WHERE id=?",
                                [reference.into()],
                            ))
                            .await
                            .unwrap()
                            .and_then(|row| row.try_get::<String>("", "email").ok())
                            .unwrap_or_else(|| reference.to_owned());
                        let email = if email == reference {
                            database
                                .query_one_raw(Statement::from_sql_and_values(
                                    DbBackend::Sqlite,
                                    "SELECT slug FROM organization WHERE id=?",
                                    [reference.into()],
                                ))
                                .await
                                .unwrap()
                                .and_then(|row| row.try_get::<String>("", "slug").ok())
                                .unwrap_or(email)
                        } else {
                            email
                        };
                        value = json!(
                            value
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|id| json!({"id":id}))
                                .collect::<Vec<_>>()
                        );
                        ("reference", json!({"referenceId":reference}), email)
                    } else if let Some(id) = index.strip_prefix("api-key:by-id:") {
                        (
                            "id",
                            json!({"id":id}),
                            value["name"].as_str().unwrap_or("").to_owned(),
                        )
                    } else {
                        (
                            "hash",
                            json!({"key":index.strip_prefix("api-key:").unwrap()}),
                            value["name"].as_str().unwrap_or("").to_owned(),
                        )
                    };
                let expires = entry.expires_at.map(|date| {
                    chrono::DateTime::from_timestamp_millis(date)
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                });
                entries.push((format!("{namespace}:{order}"), json!({"namespace":namespace,"lookup":lookup,"value":value,"expiresAt":expires})));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            result.push(json!({"store":name,"entries":entries.into_iter().map(|(_,value)|value).collect::<Vec<_>>()}));
        }
        json!(result)
    }
}
impl BackgroundTaskHandler for Application {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        self.state.lock().unwrap().active += 1;
        let app = self.clone();
        tokio::spawn(async move {
            let _ = completion.await;
            app.state.lock().unwrap().active -= 1;
            app.notify();
        });
        Ok(())
    }
}
#[async_trait::async_trait]
impl ApiKeyGenerator for Application {
    async fn generate_key(&self, _: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        let mut state = self.state.lock().unwrap();
        state.generated += 1;
        Ok(format!(
            "public-application-storage-credential-{:08}",
            state.generated
        ))
    }
}
#[derive(Clone)]
struct Store {
    app: Application,
    name: String,
}
struct StorageActivity(Application);
impl Drop for StorageActivity {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.notify();
    }
}
impl Store {
    fn activity(&self) -> StorageActivity {
        self.app.state.lock().unwrap().active += 1;
        StorageActivity(self.app.clone())
    }
    async fn hold(&self, operation: &str) {
        let receiver = {
            let mut state = self.app.state.lock().unwrap();
            if state.hold_operation == operation && state.hold_store == self.name {
                let (sender, receiver) = oneshot::channel();
                state.blocked.push(sender);
                state.entered += 1;
                Some(receiver)
            } else {
                None
            }
        };
        if let Some(receiver) = receiver {
            self.app.notify();
            let _ = receiver.await;
        }
    }
    fn kind(key: &str) -> &'static str {
        if key.starts_with("api-key:by-id:") {
            "id"
        } else if key.starts_with("api-key:by-ref:") {
            "reference"
        } else {
            "hash"
        }
    }
    fn veto(&self, operation: &str) -> AuthResult<()> {
        let mut state = self.app.state.lock().unwrap();
        if state.failure == operation && state.fail_store == self.name {
            if operation != "get" {
                state.failure.clear();
            }
            return Err(AuthError::internal("application storage veto"));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl ApiKeyStorage for Store {
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        let _activity = self.activity();
        let capture = self.app.state.lock().unwrap().capture_before_wait;
        let captured = if capture {
            self.app.read(&self.name, key)
        } else {
            None
        };
        let receiver = {
            let mut state = self.app.state.lock().unwrap();
            if key.starts_with("api-key:")
                && !key.starts_with("api-key:by-")
                && self.name != "isolated"
            {
                state.hash_reads += 1;
                if state.hold_at == 0
                    || usize::try_from(state.hold_at).ok() == Some(state.hash_reads)
                {
                    let (sender, receiver) = oneshot::channel();
                    state.blocked.push(sender);
                    state.entered += 1;
                    Some(receiver)
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(receiver) = receiver {
            self.app.notify();
            let _ = receiver.await;
        }
        self.hold(&format!("get-{}", Self::kind(key))).await;
        self.veto("get")?;
        Ok(if capture {
            captured
        } else {
            self.app.read(&self.name, key)
        })
    }
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> AuthResult<()> {
        let _activity = self.activity();
        self.hold(&format!("set-{}", Self::kind(key))).await;
        self.veto(&format!("set-{}", Self::kind(key)))?;
        self.app
            .state
            .lock()
            .unwrap()
            .maps
            .get_mut(&self.name)
            .unwrap()
            .insert(
                key.to_owned(),
                Entry {
                    value: value.to_owned(),
                    expires_at: ttl
                        .map(|ttl| Utc::now().timestamp_millis() + ttl.num_milliseconds()),
                },
            );
        Ok(())
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        let _activity = self.activity();
        self.hold(&format!("delete-{}", Self::kind(key))).await;
        self.veto(&format!("delete-{}", Self::kind(key)))?;
        self.app
            .state
            .lock()
            .unwrap()
            .maps
            .get_mut(&self.name)
            .unwrap()
            .remove(key);
        Ok(())
    }
}
#[async_trait::async_trait]
impl CacheAdapter for Store {
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        ApiKeyStorage::get(self, key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> AuthResult<()> {
        ApiKeyStorage::set(self, key, value, Some(ttl)).await
    }
    async fn set_without_expiry(&self, key: &str, value: &str) -> AuthResult<()> {
        ApiKeyStorage::set(self, key, value, None).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        ApiKeyStorage::delete(self, key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        Ok(self.app.read(&self.name, key).is_some())
    }
    async fn expire(&self, key: &str, ttl: Duration) -> AuthResult<()> {
        if let Some(entry) = self
            .app
            .state
            .lock()
            .unwrap()
            .maps
            .get_mut(&self.name)
            .unwrap()
            .get_mut(key)
        {
            entry.expires_at = Some(Utc::now().timestamp_millis() + ttl.num_milliseconds());
        }
        Ok(())
    }
    async fn clear(&self) -> AuthResult<()> {
        self.app
            .state
            .lock()
            .unwrap()
            .maps
            .get_mut(&self.name)
            .unwrap()
            .clear();
        Ok(())
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Application)> {
    let (changed, _) = watch::channel(0);
    let app = Application {
        state: Arc::new(Mutex::new(State::default())),
        changed,
    };
    app.reset().await;
    let secondary = Arc::new(Store {
        app: app.clone(),
        name: "secondary".into(),
    });
    let custom = Arc::new(Store {
        app: app.clone(),
        name: "custom".into(),
    });
    let isolated = Arc::new(Store {
        app: app.clone(),
        name: "isolated".into(),
    });
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for (name, custom_mode, fallback, deferred) in [
        ("api-key-storage-secondary", false, false, false),
        ("api-key-storage-custom", true, false, false),
        ("api-key-storage-fallback", false, true, false),
        ("api-key-storage-custom-fallback", true, true, false),
        ("api-key-storage-deferred", true, false, true),
        ("api-key-storage-fallback-deferred", true, true, true),
        ("api-key-storage-many-groups", false, false, false),
    ] {
        let config = base
            .clone()
            .base_path(format!("/__test/profiles/{name}/api/auth"))
            .background_tasks(Arc::new(app.clone()));
        let settings = ApiKeyConfig {
            storage: ApiKeyStorageMode::SecondaryStorage,
            secondary_storage: Some(secondary.clone()),
            custom_storage: custom_mode.then(|| custom.clone() as Arc<dyn ApiKeyStorage>),
            fallback_to_database: fallback,
            defer_updates: deferred,
            enable_metadata: true,
            enable_session_for_api_keys: true,
            rate_limit: RateLimitDefaults {
                enabled: false,
                ..Default::default()
            },
            key_expiration: KeyExpirationConfig {
                min_expires_in: 0.0,
                ..Default::default()
            },
            custom_key_generator: Some(Arc::new(app.clone())),
            ..Default::default()
        };
        let mut plugin = ApiKeyPlugin::with_config(settings.clone())
            .configuration(ApiKeyConfig {
                config_id: "other".into(),
                ..settings.clone()
            })
            .configuration(ApiKeyConfig {
                config_id: "organization".into(),
                references: ApiKeyReferences::Organization,
                ..settings.clone()
            })
            .configuration(ApiKeyConfig {
                config_id: "isolated".into(),
                custom_storage: Some(isolated.clone()),
                ..settings.clone()
            });
        if name == "api-key-storage-many-groups" {
            let group_config = |group| ApiKeyConfig {
                config_id: format!("group-{group}"),
                custom_storage: Some(Arc::new(Store {
                    app: app.clone(),
                    name: format!("group-{group}"),
                })),
                ..settings.clone()
            };
            plugin = ApiKeyPlugin::with_config(group_config(0));
            for group in 1..32 {
                plugin = plugin.configuration(group_config(group));
            }
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config.clone(),
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::default())
                .plugin(plugin.clone())
                .build()
                .await?,
        );
        router = router.nest(
            config.base_path.as_str(),
            auth.clone().axum_router().with_state(auth.clone()),
        );
        profiles.insert(name.to_owned(), (auth, plugin));
    }
    let state_app = app.clone();
    let state_db = database.clone();
    router = router.route(
        "/__test/api-key-storage/state",
        get(move || {
            let app = state_app.clone();
            let database = state_db.clone();
            async move { Json(app.snapshot(&database).await) }
        }),
    );
    let sql_db = database.clone();
    router = router.route(
        "/__test/api-key-storage/database",
        get(move || {
            let database = sql_db.clone();
            async move {
                let rows = database
                    .query_all_raw(Statement::from_string(
                        DbBackend::Sqlite,
                "SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM api_keys ORDER BY name",
                    ))
                    .await
                    .unwrap();
                let result: Vec<_> = rows
                    .iter()
                    .map(|row| {
                        let mut value = json!({});
                        for (wire, column) in [
                            ("id", "id"),
                            ("name", "name"),
                            ("start", "start"),
                            ("startHex", "startHex"),
                            ("startType", "startType"),
                            ("prefix", "prefix"),
                            ("key", "key"),
                            ("referenceId", "reference_id"),
                            ("configId", "config_id"),
                            ("permissions", "permissions"),
                            ("createdAt", "created_at"),
                            ("updatedAt", "updated_at"),
                            ("expiresAt", "expires_at"),
                            ("lastRequest", "last_request"),
                            ("lastRefillAt", "last_refill_at"),
                        ] {
                            let data = row.try_get::<Option<String>>("", column).unwrap();
                            value[wire] = if [
                                "createdAt",
                                "updatedAt",
                                "expiresAt",
                                "lastRequest",
                                "lastRefillAt",
                            ]
                            .contains(&wire)
                            {
                                json!(data.map(|date| {
                                    chrono::DateTime::parse_from_rfc3339(&date)
                                        .unwrap()
                                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                                }))
                            } else {
                                json!(data)
                            };
                        }
                        for (wire, column) in [
                            ("remaining", "remaining"),
                            ("requestCount", "request_count"),
                            ("refillAmount", "refill_amount"),
                            ("refillInterval", "refill_interval"),
                            ("rateLimitMax", "rate_limit_max"),
                            ("rateLimitTimeWindow", "rate_limit_time_window"),
                        ] {
                            value[wire] = json!(row.try_get::<Option<f64>>("", column).unwrap());
                        }
                        for (wire, column) in [
                            ("enabled", "enabled"),
                            ("rateLimitEnabled", "rate_limit_enabled"),
                        ] {
                            value[wire] = json!(row.try_get::<bool>("", column).unwrap());
                        }
                        value["metadataText"] =
                            json!(row.try_get::<Option<String>>("", "metadata").unwrap());
                        value["metadata"] = row
                            .try_get::<Option<String>>("", "metadata")
                            .unwrap()
                            .map(|data| serde_json::from_str(&data).unwrap())
                            .unwrap_or(Value::Null);
                        value
                    })
                    .collect();
                Json(result)
            }
        }),
    );
    let create_profiles = Arc::new(profiles);
    let verify_profiles = create_profiles.clone();
    router = router.route(
        "/__test/api-key-storage/create",
        post(
            move |Query(query): Query<HashMap<String, String>>, Json(input): Json<Value>| {
                let profiles = create_profiles.clone();
                async move {
                    let (auth, plugin) = profiles.get(&query["profile"]).unwrap();
                    let input: CreateKeyRequest =
                        alibi_core::utils::json::from_value(input.into()).unwrap();
                    Json(plugin.create_key(auth.context(), &input).await.unwrap())
                }
            },
        ),
    );
    router=router.route("/__test/api-key-storage/verify",post(move |Query(query):Query<HashMap<String,String>>,Json(input):Json<Value>| {let profiles=verify_profiles.clone();async move {
        let (auth,plugin)=profiles.get(&query["profile"]).unwrap();
        let result=plugin.verify_api_key(&VerifyApiKey{key:input["key"].as_str().unwrap(),config_id:input["configId"].as_str(),permissions:input.get("permissions")},auth.context()).await;
        let body=match result {
            Ok(key)=>json!({"valid":true,"error":null,"key":key}),
            Err(error)=>{let error=match error {ApiKeyVerificationError::Validation(error)=>serde_json::to_value(error).unwrap(),ApiKeyVerificationError::Internal(AuthError::Api{code,message,..})=>json!({"code":code,"message":message}),_=>json!({"code":ApiKeyErrorCode::InvalidApiKey,"message":{"code":ApiKeyErrorCode::InvalidApiKey,"message":ApiKeyErrorCode::InvalidApiKey.message()}})};json!({"valid":false,"error":error,"key":null})},
        };Json(body).into_response()
    }}));
    let control_app = app.clone();
    router = router.route(
        "/__test/api-key-storage/control",
        post(move |Json(input): Json<Value>| {
            let app = control_app.clone();
            let database = database.clone();
            async move {
                match input["action"].as_str().unwrap() {
                    "reset" => app.reset().await,
                    "configure" => {
                        let mut state = app.state.lock().unwrap();
                        state.failure = input["failure"].as_str().unwrap_or("").to_owned();
                        state.fail_store = input["store"].as_str().unwrap_or("custom").to_owned();
                        state.hold_store = input["holdStore"]
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| state.fail_store.clone());
                        state.hold_at = input["holdAt"].as_i64().unwrap_or(-1);
                        state.capture_before_wait =
                            input["captureBeforeWait"].as_bool().unwrap_or(false);
                        state.hold_operation =
                            input["holdOperation"].as_str().unwrap_or("").to_owned();
                        state.hash_reads = 0;
                        state.entered = 0;
                    }
                    "wait" => {
                        app.wait(usize::try_from(input["count"].as_u64().unwrap()).unwrap())
                            .await
                    }
                    "release" => app.release(),
                    "drain" => app.drain().await,
                    "clear" => {
                        for map in app.state.lock().unwrap().maps.values_mut() {
                            map.retain(|index, _| !index.starts_with("api-key:"));
                        }
                    }
                    "expire-cache" => {
                        for map in app.state.lock().unwrap().maps.values_mut() {
                            for (index, entry) in map {
                                if index.starts_with("api-key:")
                                    && !index.starts_with("api-key:by-ref:")
                                    && serde_json::from_str::<Value>(&entry.value).unwrap()["id"]
                                        == input["keyId"]
                                {
                                    entry.expires_at = Some(0);
                                }
                            }
                        }
                    }
                    "patch" => {
                        if input["cache"] != false {
                            for map in app.state.lock().unwrap().maps.values_mut() {
                                for (index, entry) in map {
                                    if !index.starts_with("api-key:")
                                        || index.starts_with("api-key:by-ref:")
                                    {
                                        continue;
                                    }
                                    let mut row: Value =
                                        serde_json::from_str(&entry.value).unwrap();
                                    if row["id"] == input["keyId"] {
                                        row.as_object_mut()
                                            .unwrap()
                                            .extend(input["patch"].as_object().unwrap().clone());
                                        entry.value = serde_json::to_string(&row).unwrap();
                                    }
                                }
                            }
                        }
                        if input["database"] == true {
                            for (field, value) in input["patch"].as_object().unwrap() {
                                let column = match field.as_str() {
                                    "remaining" => "remaining",
                                    "expiresAt" => "expires_at",
                                    "lastRefillAt" => "last_refill_at",
                                    "refillAmount" => "refill_amount",
                                    "refillInterval" => "refill_interval",
                                    "name" => "name",
                                    _ => panic!("supported application column required"),
                                };
                                let value = if value.is_null() {
                                    None::<String>.into()
                                } else if ["expiresAt", "lastRefillAt"].contains(&field.as_str()) {
                                    chrono::DateTime::parse_from_rfc3339(value.as_str().unwrap())
                                        .unwrap()
                                        .with_timezone(&Utc)
                                        .into()
                                } else if let Some(number) = value.as_f64() {
                                    number.into()
                                } else {
                                    value.as_str().unwrap().to_owned().into()
                                };
                                database
                                    .execute_raw(Statement::from_sql_and_values(
                                        DbBackend::Sqlite,
                                        format!("UPDATE api_keys SET {column}=? WHERE id=?"),
                                        [value, input["keyId"].as_str().unwrap().to_owned().into()],
                                    ))
                                    .await
                                    .unwrap();
                            }
                        }
                    }
                    "misindex" => {
                        app.state
                            .lock()
                            .unwrap()
                            .maps
                            .get_mut(input["store"].as_str().unwrap())
                            .unwrap()
                            .insert(
                                format!(
                                    "api-key:by-ref:{}",
                                    input["referenceId"].as_str().unwrap()
                                ),
                                Entry {
                                    value: serde_json::to_string(&vec![&input["keyId"]]).unwrap(),
                                    expires_at: None,
                                },
                            );
                    }
                    _ => panic!("unknown storage control"),
                }
                let state = app.state.lock().unwrap();
                Json(json!({"entered":state.entered,"pending":state.blocked.len()}))
            }
        }),
    );
    Ok((router, app))
}
