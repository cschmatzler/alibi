use crate::TestSchema;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use better_auth::__private_core::{AuthRequest, HttpMethod};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::api_key::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyGenerationOptions, ApiKeyGenerator, ApiKeyGetter,
    ApiKeyValidator, ApiKeyVerificationError, CreateKeyRequest, KeyExpirationConfig,
    RateLimitDefaults, UpdateKeyRequest, VerifyApiKey,
};
use better_auth::plugins::{ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, QueryResult, Statement},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct Application {
    events: Arc<Mutex<Vec<Value>>>,
    mode: Arc<Mutex<String>>,
    serial: Arc<AtomicUsize>,
    config_id: String,
}
impl Application {
    fn failure(&self, stage: &str) -> AuthResult<()> {
        let mode = self.mode.lock().unwrap().clone();
        if mode == format!("{stage}-ordinary") {
            return Err(AuthError::internal(format!("Private {stage} failure")));
        }
        if mode == format!("{stage}-api") {
            return Err(AuthError::Api {
                status: 403,
                code: Some(format!("APPLICATION_{}_DENIED", stage.to_uppercase())),
                message: format!("Application {stage} denied"),
            });
        }
        if mode == format!("{stage}-public-500") {
            return Err(AuthError::Api {
                status: 500,
                code: Some(format!("APPLICATION_{}_FAILED", stage.to_uppercase())),
                message: format!("Application {stage} failed"),
            });
        }
        Ok(())
    }
    fn context(&self, context: &ApiKeyCallbackContext<'_>) -> Value {
        let body = context
            .verification_input
            .map(|input| {
                let mut body = json!({"key":input.key});
                if let Some(config_id) = input.config_id {
                    body["configId"] = json!(config_id);
                }
                if let Some(permissions) = input.permissions {
                    body["permissions"] = permissions.clone();
                }
                body
            })
            .or_else(|| {
                context.request.and_then(|request| {
                    request
                        .body
                        .as_deref()
                        .filter(|body| !body.is_empty())
                        .and_then(|body| {
                            better_auth::__private_core::utils::json::from_slice::<Value>(body).ok()
                        })
                })
            });
        json!({"requestPresent":context.request.is_some(),"method":context.request.map(|request|format!("{:?}",request.method()).to_uppercase()),"marker":context.request.and_then(|request|request.header("x-options-marker")),"body":body})
    }
    fn event(&self, kind: &str, key: &str, context: &ApiKeyCallbackContext<'_>) {
        let mut event = json!({"kind":kind,"configId":self.config_id,"key":key,"mode":*self.mode.lock().unwrap()});
        event
            .as_object_mut()
            .unwrap()
            .extend(self.context(context).as_object().unwrap().clone());
        self.events.lock().unwrap().push(event);
    }
}
#[async_trait::async_trait]
impl ApiKeyGenerator for Application {
    async fn generate_key(&self, input: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        let text = if input.length.is_nan() {
            "NaN".to_owned()
        } else if !input.length.is_finite() {
            if input.length.is_sign_negative() {
                "-Infinity".to_owned()
            } else {
                "Infinity".to_owned()
            }
        } else {
            better_auth::__private_core::utils::json::number_to_string(
                &serde_json::Number::from_f64(input.length).unwrap(),
            )?
        };
        self.events.lock().unwrap().push(json!({"kind":"generator","configId":self.config_id,"length":{"value":if input.length.is_finite(){Some(input.length)}else{None},"text":text},"prefix":input.prefix,"mode":*self.mode.lock().unwrap()}));
        self.failure("generator")?;
        Ok(format!(
            "{}application-owned-secret-{:06}",
            input.prefix.unwrap_or(""),
            self.serial.fetch_add(1, Ordering::SeqCst) + 1
        ))
    }
}
#[async_trait::async_trait]
impl ApiKeyValidator for Application {
    async fn validate(&self, context: &ApiKeyCallbackContext<'_>, key: &str) -> AuthResult<bool> {
        self.event("validator", key, context);
        self.failure("validator")?;
        Ok(*self.mode.lock().unwrap() != "validator-deny")
    }
}
impl ApiKeyGetter for Application {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>> {
        let key = context
            .request
            .and_then(|request| request.header("x-options-getter-session"))
            .cloned();
        if let Some(key) = &key {
            self.event("getter", key, context);
            self.failure("getter")?;
        }
        Ok(key)
    }
}

fn number(value: Option<&Value>, default: f64) -> f64 {
    match value {
        Some(Value::Number(number)) => number.as_f64().unwrap(),
        Some(Value::String(value)) => match value.as_str() {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            _ => value.parse().unwrap(),
        },
        _ => default,
    }
}
fn date(row: &QueryResult, field: &str) -> Option<String> {
    row.try_get::<Option<String>>("", field)
        .unwrap()
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(&value)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
}
fn persisted(row: &QueryResult) -> Value {
    let start = row
        .try_get::<Option<Vec<u8>>>("", "start")
        .unwrap()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    json!({
        "id":row.try_get::<String>("","id").unwrap(),"name":row.try_get::<Option<String>>("","name").unwrap(),"start":start,"prefix":row.try_get::<Option<String>>("","prefix").unwrap(),
        "key":row.try_get::<String>("","key").unwrap(),"referenceId":row.try_get::<String>("","reference_id").unwrap(),"configId":row.try_get::<String>("","config_id").unwrap(),
        "refillInterval":row.try_get::<Option<f64>>("","refill_interval").unwrap(),"refillAmount":row.try_get::<Option<f64>>("","refill_amount").unwrap(),"lastRefillAt":date(row,"last_refill_at"),
        "enabled":row.try_get::<bool>("","enabled").unwrap(),"rateLimitEnabled":row.try_get::<bool>("","rate_limit_enabled").unwrap(),"rateLimitTimeWindow":row.try_get::<Option<f64>>("","rate_limit_time_window").unwrap(),"rateLimitMax":row.try_get::<Option<f64>>("","rate_limit_max").unwrap(),
        "requestCount":row.try_get::<Option<f64>>("","request_count").unwrap(),"remaining":row.try_get::<Option<f64>>("","remaining").unwrap(),"lastRequest":date(row,"last_request"),"expiresAt":date(row,"expires_at"),"createdAt":date(row,"created_at"),"updatedAt":date(row,"updated_at"),
        "permissions":row.try_get::<Option<String>>("","permissions").unwrap(),"metadata":row.try_get::<Option<String>>("","metadata").unwrap(),"startHex":row.try_get::<String>("","startHex").unwrap(),"startType":row.try_get::<String>("","startType").unwrap(),
    })
}
fn error(error: AuthError) -> Value {
    match error {
        AuthError::Api {
            status,
            code,
            message,
        } => {
            let mut body = json!({"message":message});
            if let Some(code) = code {
                body["code"] = json!(code);
            }
            json!({"api":true,"status":status,"body":body,"message":message})
        }
        AuthError::Upstream {
            status,
            code,
            message,
        } => {
            json!({"api":true,"status":status,"body":{"code":code,"message":message},"message":message})
        }
        AuthError::Internal(message) => {
            json!({"api":false,"status":null,"body":null,"message":message})
        }
        error => json!({"api":false,"status":null,"body":null,"message":error.to_string()}),
    }
}
fn caught(error: AuthError) -> Value {
    let body = match error {
        AuthError::Api { code, message, .. } => {
            let mut body = json!({"message":message});
            if let Some(code) = code {
                body["code"] = json!(code);
            }
            body
        }
        AuthError::Upstream { code, message, .. } => json!({"code":code,"message":message}),
        _ => {
            json!({"code":"INVALID_API_KEY","message":{"code":"INVALID_API_KEY","message":"Invalid API key."}})
        }
    };
    json!({"valid":false,"error":body,"key":null})
}
#[derive(Clone)]
struct Fixture {
    auth: Arc<better_auth::BetterAuth<TestSchema>>,
    plugin: ApiKeyPlugin,
    database: DatabaseConnection,
    application: Application,
}
async fn state(State(fixture): State<Fixture>) -> Json<Value> {
    let rows=fixture.database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM api_keys ORDER BY name,id")).await.unwrap();
    Json(json!({"keys":rows.iter().map(persisted).collect::<Vec<_>>()}))
}
async fn events(State(fixture): State<Fixture>) -> Json<Value> {
    Json(json!(std::mem::take(
        &mut *fixture.application.events.lock().unwrap()
    )))
}
async fn mode(State(fixture): State<Fixture>, Json(input): Json<Value>) -> Json<Value> {
    let mode = input["mode"].as_str().unwrap().to_owned();
    *fixture.application.mode.lock().unwrap() = mode.clone();
    if input["reset"] == true {
        fixture.application.serial.store(0, Ordering::SeqCst);
        fixture.application.events.lock().unwrap().clear();
    }
    Json(json!({"mode":mode}))
}
async fn install(State(fixture): State<Fixture>, Json(input): Json<Value>) -> Json<Value> {
    for (field, value) in input["patch"].as_object().unwrap() {
        let column = match field.as_str() {
            "permissions" => "permissions",
            "referenceId" => "reference_id",
            "configId" => "config_id",
            _ => panic!("Unsupported installed field"),
        };
        let value = value.as_str().map(str::to_owned);
        fixture
            .database
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                format!("UPDATE api_keys SET {column}=? WHERE id=?"),
                [value.into(), input["keyId"].as_str().unwrap().into()],
            ))
            .await
            .unwrap();
    }
    Json(json!({"success":true}))
}
async fn create(
    State(fixture): State<Fixture>,
    Json(input): Json<CreateKeyRequest>,
) -> Json<Value> {
    Json(
        match fixture
            .plugin
            .create_key(fixture.auth.context(), &input)
            .await
        {
            Ok(key) => json!({"value":key,"error":null}),
            Err(cause) => json!({"value":null,"error":error(cause)}),
        },
    )
}
async fn update(
    State(fixture): State<Fixture>,
    Json(input): Json<UpdateKeyRequest>,
) -> Json<Value> {
    Json(
        match fixture
            .plugin
            .update_key(fixture.auth.context(), &input)
            .await
        {
            Ok(key) => json!({"value":key,"error":null}),
            Err(cause) => json!({"value":null,"error":error(cause)}),
        },
    )
}
async fn verify(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Json<Value> {
    let body = &input["input"];
    let query = VerifyApiKey {
        key: body["key"].as_str().unwrap(),
        config_id: body.get("configId").and_then(Value::as_str),
        permissions: body.get("permissions"),
    };
    let mut request = AuthRequest::new(HttpMethod::Post, "/__test/api-key-options/verify");
    request.body = Some(better_auth::__private_core::utils::json::to_vec(&input).unwrap());
    for (name, value) in headers {
        if let Some(name) = name {
            request
                .headers
                .insert(name.as_str().into(), value.to_str().unwrap().into());
        }
    }
    let result = if input["request"] == true {
        fixture
            .plugin
            .verify_api_key_with_request(&query, &request, fixture.auth.context())
            .await
    } else {
        fixture
            .plugin
            .verify_api_key(&query, fixture.auth.context())
            .await
    };
    Json(match result {
        Ok(key) => json!({"value":{"valid":true,"error":null,"key":key},"error":null}),
        Err(ApiKeyVerificationError::Validation(cause)) => {
            json!({"value":{"valid":false,"error":cause,"key":null},"error":null})
        }
        Err(ApiKeyVerificationError::Internal(cause)) => {
            json!({"value":caught(cause),"error":null})
        }
        Err(ApiKeyVerificationError::ExplicitValidator(cause)) => {
            json!({"value":null,"error":error(cause)})
        }
    })
}

pub(super) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let application = Application {
        events: Arc::new(Mutex::new(Vec::new())),
        mode: Arc::new(Mutex::new("normal".into())),
        serial: Arc::new(AtomicUsize::new(0)),
        config_id: String::new(),
    };
    let entries: Vec<Value> =
        serde_json::from_str(include_str!("../../api-key-options.json")).unwrap();
    let mut configurations = Vec::new();
    for entry in entries {
        let id = entry["id"].as_str().unwrap();
        let mut callbacks = application.clone();
        callbacks.config_id = id.into();
        configurations.push(ApiKeyConfig {
            config_id: id.into(),
            key_length: number(entry.get("keyLength"), 16.0),
            prefix: Some(entry["prefix"].as_str().unwrap_or("optKEY_").into()),
            api_key_headers: vec![format!("x-options-{id}")],
            enable_session_for_api_keys: entry["session"].as_bool().unwrap_or(true),
            disable_key_hashing: entry["hash"] == false,
            starting_characters_length: number(entry.get("start"), 6.0),
            store_starting_characters: entry["storeStart"].as_bool().unwrap_or(true),
            min_prefix_length: number(entry.get("minPrefix"), 1.0),
            max_prefix_length: number(entry.get("maxPrefix"), 32.0),
            min_name_length: number(entry.get("minName"), 1.0),
            max_name_length: number(entry.get("maxName"), 32.0),
            key_expiration: KeyExpirationConfig {
                default_expires_in: entry
                    .get("expiration")
                    .map(|value| number(Some(value), 0.0)),
                min_expires_in: number(entry.get("minExpiration"), 0.0),
                max_expires_in: number(entry.get("maxExpiration"), 365.0),
                ..Default::default()
            },
            rate_limit: RateLimitDefaults {
                enabled: false,
                ..Default::default()
            },
            enable_metadata: true,
            custom_key_generator: (entry["custom"] == true)
                .then(|| Arc::new(callbacks.clone()) as Arc<dyn ApiKeyGenerator>),
            custom_api_key_validator: (entry["validator"] == true)
                .then(|| Arc::new(callbacks.clone()) as Arc<dyn ApiKeyValidator>),
            custom_api_key_getter: (entry["getter"] == true)
                .then(|| Arc::new(callbacks) as Arc<dyn ApiKeyGetter>),
            ..Default::default()
        });
    }
    let mut iter = configurations.into_iter();
    let mut plugin = ApiKeyPlugin::with_config(iter.next().unwrap());
    for configuration in iter {
        plugin = plugin.configuration(configuration);
    }
    let path = "/__test/profiles/api-key-options/api/auth";
    let config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(SeaOrmStore::<TestSchema>::new(
                config.clone(),
                database.clone(),
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(plugin.clone())
            .build()
            .await?,
    );
    let controls = Router::new()
        .route("/__test/api-key-options/state", get(state))
        .route("/__test/api-key-options/events", get(events))
        .route("/__test/api-key-options/mode", post(mode))
        .route("/__test/api-key-options/install", post(install))
        .route("/__test/api-key-options/create", post(create))
        .route("/__test/api-key-options/update", post(update))
        .route("/__test/api-key-options/verify", post(verify))
        .with_state(Fixture {
            auth: auth.clone(),
            plugin,
            database,
            application,
        });
    Ok(Router::new()
        .nest(path, auth.clone().axum_router().with_state(auth))
        .merge(controls))
}
