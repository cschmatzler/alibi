use crate::TestSchema;
use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::__private_core::utils::json;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::api_key::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyDefaultPermissions, ApiKeyGenerationOptions,
    ApiKeyGenerator, ApiKeyPermissions, ApiKeyVerificationError, CreateKeyRequest,
    KeyExpirationConfig, RateLimitDefaults, UpdateKeyRequest, VerifyApiKey,
};
use better_auth::plugins::{ApiKeyPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use serde::Deserialize;
use serde_json::{Value, json as value};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Events = Arc<Mutex<Vec<Value>>>;
#[derive(Clone)]
struct Application {
    events: Events,
    mode: Arc<Mutex<String>>,
    serial: Arc<AtomicUsize>,
    database: DatabaseConnection,
}
#[async_trait::async_trait]
impl ApiKeyGenerator for Application {
    async fn generate_key(&self, options: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        let mode = self.mode.lock().unwrap().clone();
        self.events.lock().unwrap().push(value!({"kind":"generator", "length":options.length, "prefix":options.prefix, "mode":mode}));
        match mode.as_str() {
            "generator-api" => Err(AuthError::Upstream {
                status: 403,
                code: "GENERATOR_DENIED",
                message: "Application generator denied",
            }),
            "generator-public-500" => Err(AuthError::Api {
                status: 500,
                code: Some("APPLICATION_GENERATION_DENIED".into()),
                message: "Application generation denied".into(),
            }),
            "generator-throw" => Err(AuthError::internal("Private generator failure")),
            "unicode" => Ok("😀abcdefghijklmnop".to_owned()),
            _ => Ok(format!(
                "{}generated-owned-secret-{:06}",
                options.prefix.unwrap_or(""),
                self.serial.fetch_add(1, Ordering::SeqCst) + 1
            )),
        }
    }
}
struct Permissions {
    application: Application,
}
#[async_trait::async_trait]
impl ApiKeyDefaultPermissions for Permissions {
    async fn default_permissions(
        &self,
        reference_id: &str,
        context: &ApiKeyCallbackContext<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        let mode = self.application.mode.lock().unwrap().clone();
        let explicit = context
            .request
            .and_then(|request| request.body_as_json::<json::JsValue>().ok())
            .and_then(|body| body.get("permissions").cloned())
            .map(|value| value.to_json_value().unwrap());
        self.application.events.lock().unwrap().push(value!({"kind":"permissions","configurationId":context.configuration_id,"reference":{"userId":reference_id},"requestPresent":context.request.is_some(),"explicit":explicit,"mode":mode}));
        match mode.as_str() {
            "permissions-api" => {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "PERMISSIONS_DENIED",
                    message: "Application permissions denied",
                });
            }
            "permissions-throw" => return Err(AuthError::internal("Private permissions failure")),
            _ => {}
        }
        let row = self
            .application
            .database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT name FROM users WHERE id = ?",
                [reference_id.into()],
            ))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?
            .unwrap();
        let name: String = row.try_get("", "name").unwrap();
        Ok(ApiKeyPermissions::from([
            (
                "zeta".into(),
                vec![if name == "Owner" {
                    "read".into()
                } else {
                    "foreign".into()
                }],
            ),
            ("10".into(), vec!["ten".into()]),
            ("2".into(), vec!["two".into()]),
            ("alpha".into(), vec![context.configuration_id.to_owned()]),
            (
                "$serde_json::private::RawValue".into(),
                vec!["literal".into()],
            ),
        ]))
    }
}
#[derive(Deserialize)]
struct Mode {
    mode: String,
    #[serde(default)]
    reset: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expire {
    key_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Verify {
    key: String,
    config_id: Option<String>,
    #[serde(default, deserialize_with = "json::deserialize_optional_value")]
    permissions: Option<Value>,
}

pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let application = Application {
        events: Arc::new(Mutex::new(Vec::new())),
        mode: Arc::new(Mutex::new("normal".into())),
        serial: Arc::new(AtomicUsize::new(0)),
        database: database.clone(),
    };
    let mut plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    });
    for id in ["generated", "plaintext"] {
        plugin = plugin.configuration(ApiKeyConfig {
            config_id: id.into(),
            disable_key_hashing: id == "plaintext",
            enable_session_for_api_keys: id == "generated",
            prefix: Some(if id == "generated" {
                "app_".into()
            } else {
                "raw_".into()
            }),
            key_length: if id == "generated" { 24.0 } else { 31.0 },
            starting_characters_length: 2.0,
            custom_key_generator: Some(Arc::new(application.clone())),
            default_permissions_callback: Some(Arc::new(Permissions {
                application: application.clone(),
            })),
            key_expiration: KeyExpirationConfig {
                min_expires_in: 0.0,
                ..Default::default()
            },
            rate_limit: RateLimitDefaults {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        });
    }
    plugin = plugin.configuration(ApiKeyConfig {
        config_id: "static".into(),
        key_length: 0.0,
        custom_key_generator: Some(Arc::new(application.clone())),
        rate_limit: RateLimitDefaults {
            enabled: false,
            ..Default::default()
        },
        default_permissions: Some(ApiKeyPermissions::from([
            ("zeta".into(), vec!["read".into()]),
            ("alpha".into(), vec!["write".into()]),
        ])),
        ..Default::default()
    });
    let path = "/__test/profiles/api-key-generation/api/auth";
    let config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
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
    let mut router = Router::new().nest(path, auth.clone().axum_router().with_state(auth.clone()));
    let events = application.events.clone();
    let mode = application.mode.clone();
    let serial = application.serial.clone();
    router = router
        .route(
            "/__test/api-key-generation/events",
            get(move || {
                let events = events.clone();
                async move { Json(std::mem::take(&mut *events.lock().unwrap())) }
            }),
        )
        .route(
            "/__test/api-key-generation/mode",
            post(move |Json(input): Json<Mode>| {
                let mode = mode.clone();
                async move {
                    *mode.lock().unwrap() = input.mode.clone();
                    if input.reset {
                        serial.store(0, Ordering::SeqCst);
                    }
                    Json(value!({"mode":input.mode}))
                }
            }),
        );
    let state_db = database.clone();
    router=router.route("/__test/api-key-generation/state",get(move||{let database=state_db.clone();async move{
        let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT id,name,reference_id,config_id,key,start,prefix,permissions,remaining,request_count,expires_at FROM api_keys ORDER BY name")).await.unwrap();
        let values:Vec<_>=rows.iter().map(|row|value!({"id":row.try_get::<String>("","id").unwrap(),"name":row.try_get::<Option<String>>("","name").unwrap(),"referenceId":row.try_get::<String>("","reference_id").unwrap(),"configId":row.try_get::<String>("","config_id").unwrap(),"key":row.try_get::<String>("","key").unwrap(),"start":row.try_get::<Option<String>>("","start").unwrap(),"prefix":row.try_get::<Option<String>>("","prefix").unwrap(),"permissions":row.try_get::<Option<String>>("","permissions").unwrap(),"remaining":row.try_get::<Option<f64>>("","remaining").unwrap(),"requestCount":row.try_get::<Option<f64>>("","request_count").unwrap(),"expiresAt":row.try_get::<Option<String>>("","expires_at").unwrap()})).collect();Json(values)
    }}));
    router = router.route(
        "/__test/api-key-generation/expire",
        post(move |Json(input): Json<Expire>| {
            let database = database.clone();
            async move {
                let _ = database
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        "UPDATE api_keys SET expires_at = ? WHERE id = ?",
                        ["1970-01-01T00:00:00.000Z".into(), input.key_id.into()],
                    ))
                    .await
                    .unwrap();
                Json(value!({"success":true}))
            }
        }),
    );
    let cleanup_auth = auth.clone();
    let cleanup_plugin = plugin.clone();
    router = router.route(
        "/__test/api-key-generation/cleanup",
        post(move || {
            let auth = cleanup_auth.clone();
            let plugin = cleanup_plugin.clone();
            async move { Json(plugin.delete_all_expired_api_keys(auth.context()).await) }
        }),
    );
    let create_auth = auth.clone();
    let create_plugin = plugin.clone();
    router = router.route(
        "/__test/api-key-generation/create",
        post(move |Json(body): Json<CreateKeyRequest>| {
            let auth = create_auth.clone();
            let plugin = create_plugin.clone();
            async move {
                match plugin.create_key(auth.context(), &body).await {
                    Ok(key) => Json(json::to_value(&key).unwrap()).into_response(),
                    Err(_) => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(value!({"message":"Internal server error"})),
                    )
                        .into_response(),
                }
            }
        }),
    );
    let update_auth = auth.clone();
    let update_plugin = plugin.clone();
    router = router.route(
        "/__test/api-key-generation/update",
        post(move |Json(body): Json<UpdateKeyRequest>| {
            let auth = update_auth.clone();
            let plugin = update_plugin.clone();
            async move {
                match plugin.update_key(auth.context(), &body).await {
                    Ok(key) => Json(json::to_value(&key).unwrap()).into_response(),
                    Err(_) => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(value!({"message":"Internal server error"})),
                    )
                        .into_response(),
                }
            }
        }),
    );
    Ok(router.route(
        "/__test/api-key-generation/verify",
        post(move |Json(body): Json<Verify>| {
            let auth = auth.clone();
            let plugin = plugin.clone();
            async move {
                let input = VerifyApiKey {
                    key: &body.key,
                    config_id: body.config_id.as_deref(),
                    permissions: body.permissions.as_ref(),
                };
                match plugin.verify_api_key(&input, auth.context()).await {
                    Ok(key) => Json(value!({"valid":true,"error":null,"key":key})).into_response(),
                    Err(ApiKeyVerificationError::Validation(error)) => {
                        Json(value!({"valid":false,"error":error,"key":null})).into_response()
                    }
                    Err(
                        ApiKeyVerificationError::Internal(_)
                        | ApiKeyVerificationError::ExplicitValidator(_),
                    ) => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(value!({"message":"Internal server error"})),
                    )
                        .into_response(),
                }
            }
        }),
    ))
}
