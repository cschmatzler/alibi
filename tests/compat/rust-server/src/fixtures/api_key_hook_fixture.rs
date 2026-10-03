use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::__private_core::{AuthRequest, HttpMethod};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::api_key::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyGetter, ApiKeyValidator, ApiKeyVerificationError,
    CreateKeyRequest, RateLimitDefaults, UpdateKeyRequest, VerifyApiKey,
};
use better_auth::plugins::{ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;
struct Getter(Events);
impl ApiKeyGetter for Getter {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>> {
        let Some(request) = context.request else {
            return Ok(None);
        };
        let header = request.header("x-custom-api-key");
        let key = header
            .and_then(|value| value.strip_prefix("ApiKey "))
            .map(str::to_owned);
        if header.is_some() || request.path() == "/get-session" {
            self.0.lock().unwrap().push(json!({"kind":"getter", "configurationId":context.configuration_id, "provided":key.as_ref().is_some_and(|value|!value.is_empty())}));
        }
        Ok(key)
    }
}
struct Validator(Events);
#[async_trait::async_trait]
impl ApiKeyValidator for Validator {
    async fn validate(&self, context: &ApiKeyCallbackContext<'_>, key: &str) -> AuthResult<bool> {
        let policy = context
            .request
            .and_then(|request| request.header("x-key-policy"))
            .map(String::as_str)
            .unwrap_or("allow");
        self.0.lock().unwrap().push(json!({"kind":"validator", "configurationId":context.configuration_id, "policy":policy, "keyLength":key.encode_utf16().count(), "prefix":if key.starts_with("red_") {"red_"} else {"other"}}));
        Ok(policy != "deny" && (policy != "red-only" || key.starts_with("red_")))
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    key: String,
    config_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "better_auth::__private_core::utils::json::deserialize_optional_value"
    )]
    permissions: Option<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateQuery {
    user_id: String,
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let path = "/__test/profiles/api-key-hooks/api/auth";
    let configured = config.clone().base_path(path);
    let mut plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    for config_id in ["other", "hooks"] {
        plugin = plugin.configuration(ApiKeyConfig {
            config_id: config_id.to_owned(),
            enable_session_for_api_keys: config_id == "hooks",
            custom_api_key_getter: (config_id == "hooks")
                .then(|| Arc::new(Getter(events.clone())) as Arc<dyn ApiKeyGetter>),
            custom_api_key_validator: (config_id == "hooks")
                .then(|| Arc::new(Validator(events.clone())) as Arc<dyn ApiKeyValidator>),
            rate_limit: RateLimitDefaults {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        });
    }
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(configured.clone())
            .store(crate::backend::store::<TestSchema>(
                configured,
                database.clone(),
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(plugin.clone())
            .build()
            .await?,
    );
    let router = Router::new().nest(path, auth.clone().axum_router().with_state(auth.clone()));
    let create_auth = auth.clone();
    let create_plugin = plugin.clone();
    let update_auth = auth.clone();
    let update_plugin = plugin.clone();
    let controls = Router::new()
        .route("/__test/api-key-hook/events", get(move || {
            let events = events.clone();
            async move { Json(std::mem::take(&mut *events.lock().unwrap())) }
        }))
        .route("/__test/api-key-hook/state", get(move |Query(query): Query<StateQuery>| {
            let database = database.clone();
            async move {
                let rows = database.query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT id, reference_id, config_id, remaining, request_count, enabled FROM api_keys ORDER BY name",
                )).await.unwrap();
                let keys: Vec<Value> = rows.iter().map(|row| json!({
                    "id": row.try_get::<String>("", "id").unwrap(),
                    "referenceId": row.try_get::<String>("", "reference_id").unwrap(),
                    "configId": row.try_get::<String>("", "config_id").unwrap(),
                    "remaining": row.try_get::<Option<f64>>("", "remaining").unwrap(),
                    "requestCount": row.try_get::<Option<f64>>("", "request_count").unwrap(),
                    "enabled": row.try_get::<bool>("", "enabled").unwrap(),
                })).collect();
                let sessions = database.query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?",
                    [query.user_id.into()],
                )).await.unwrap().unwrap();
                Json(json!({"keys": keys, "sessions": {"count": sessions.try_get::<i64>("", "count").unwrap()}}))
            }
        }))
        .route("/__test/api-key-hook/create", post(move |Json(body): Json<CreateKeyRequest>| {
            let auth = create_auth.clone();
            let plugin = create_plugin.clone();
            async move {
                match plugin.create_key(auth.context(), &body).await {
                    Ok(key) => Json(serde_json::to_value(key).unwrap()).into_response(),
                    Err(error) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": error.to_string()}))).into_response(),
                }
            }
        }))
        .route("/__test/api-key-hook/update", post(move |Json(body): Json<UpdateKeyRequest>| {
            let auth = update_auth.clone();
            let plugin = update_plugin.clone();
            async move {
                match plugin.update_key(auth.context(), &body).await {
                    Ok(key) => Json(serde_json::to_value(key).unwrap()).into_response(),
                    Err(error) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": error.to_string()}))).into_response(),
                }
            }
        }))
        .route("/__test/api-key-hook/verify", post(move |headers: HeaderMap, Json(body): Json<VerifyBody>| {
            let auth = auth.clone();
            let plugin = plugin.clone();
            async move {
                let mut request = AuthRequest::new(HttpMethod::Post, "/__test/api-key-hook/verify");
                request.body = Some(better_auth::__private_core::utils::json::to_vec(&body).unwrap());
                for (key, value) in headers {
                    if let Some(key) = key {
                        request.headers.insert(key.as_str().to_owned(), value.to_str().unwrap().to_owned());
                    }
                }
                let input = VerifyApiKey {key: &body.key, config_id: body.config_id.as_deref(), permissions: body.permissions.as_ref()};
                match plugin.verify_api_key_with_request(&input, &request, auth.context()).await {
                    Ok(key) => Json(json!({"valid": true, "error": null, "key": key})).into_response(),
                    Err(ApiKeyVerificationError::Validation(error)) => Json(json!({"valid": false, "error": error, "key": null})).into_response(),
                    Err(ApiKeyVerificationError::Internal(error) | ApiKeyVerificationError::ExplicitValidator(error)) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": error.to_string()}))).into_response(),
                }
            }
        }));
    Ok(router.merge(controls))
}
