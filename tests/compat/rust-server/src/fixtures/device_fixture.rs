//! Trusted fixture controls for persisted OAuth device grants.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    DeviceAuthorizationPlugin, EmailPasswordPlugin, SessionManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr},
    store::entities::device_code,
};
use chrono::Duration;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
static CALLBACK_EVENTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSelector {
    device_code: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceExpiry {
    device_code: String,
    expires_at: DateTime<Utc>,
}
pub(crate) fn router(database: DatabaseConnection) -> Router<Arc<BetterAuth<TestSchema>>> {
    let read_database = database.clone();
    Router::new().route("/__test/device-callback-events", get(|| async { Json(std::mem::take(&mut *CALLBACK_EVENTS.lock().unwrap())) })).route("/__test/device-state",get(move |Query(body):Query<DeviceSelector>| {
  let database=read_database.clone();async move {
   match device_code::Entity::find().filter(device_code::Column::DeviceCode.eq(body.device_code)).one(&database).await {
    Ok(row)=>(StatusCode::OK,Json(row.map(|row|json!({"id":row.id,"deviceCode":row.device_code,"userCode":row.user_code,"userId":row.user_id,"status":row.status,"clientId":row.client_id,"scope":row.scope,"expiresAt":row.expires_at,"lastPolledAt":row.last_polled_at,"pollingInterval":row.polling_interval})).unwrap_or(Value::Null))),
    Err(error)=>(StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"message":error.to_string()})))
   }
  }
 })).route("/__test/expire-device",post(move |Json(body):Json<DeviceExpiry>| {
  let database=database.clone();async move {
   match device_code::Entity::update_many().filter(device_code::Column::DeviceCode.eq(body.device_code)).col_expr(device_code::Column::ExpiresAt,Expr::value(body.expires_at)).exec(&database).await {
    Ok(_)=>(StatusCode::OK,Json(json!({"status":true}))),
    Err(error)=>(StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"message":error.to_string()})))
   }
  }
 }))
}

pub(crate) async fn profiles(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let mut router = Router::new();
    for name in [
        "device-callback-success",
        "device-length-506",
        "device-custom",
        "device-configured",
        "device-unicode",
        "device-too-long",
        "device-empty",
        "device-fractional",
        "device-negative",
        "device-negative-interval",
        "device-generator-error",
        "device-user-generator-error",
        "device-validation-error",
        "device-request-error",
        "device-generator-throw",
        "device-user-generator-throw",
        "device-validation-throw",
        "device-request-throw",
    ] {
        let mut plugin = DeviceAuthorizationPlugin::new();
        match name {
            "device-callback-success" => {
                let callback_database = database.clone();
                plugin = plugin.on_device_auth_request(move |client_id, scope| {
                    let database = callback_database.clone();
                    async move {
                        let rows = device_code::Entity::find().filter(device_code::Column::ClientId.eq(&client_id)).all(&database).await.map_err(|error| AuthError::Internal(error.to_string()))?;
                        CALLBACK_EVENTS.lock().unwrap().push(json!({"clientId": client_id, "scope": scope, "persistedBeforeCallback": rows.len()}));
                        Ok(())
                    }
                });
            }
            "device-length-506" => { plugin = plugin.device_code_length(16); }
            "device-custom" => {
                plugin = plugin
                    .generate_device_code_async_with(|| async {
                        Ok("custom-device-🔐".to_owned())
                    })
                    .generate_user_code_async_with(|| async { Ok(" café-Code! ".to_owned()) });
            }
            "device-configured" => {
                plugin=plugin.expires_in(Duration::seconds(120)).interval(Duration::seconds(2)).verification_uri("https://verification.fixture/device?keep=a&user_code=old&keep=b&user_code=other#fragment").validate_client(|client| async move {Ok(client=="allowed-client")});
            }
            "device-unicode" => {
                plugin = plugin
                    .generate_device_code_async_with(|| async { Ok("😀".repeat(191)) })
                    .generate_user_code_with(|| "boundary-user".to_owned());
            }
            name if name.ends_with("-error") || name.ends_with("-throw") => {
                plugin = plugin
                    .generate_device_code_with(move || format!("{name}-code"))
                    .generate_user_code_with(move || format!("{name}-user"));
                plugin =
                    match name {
                        name if name.starts_with("device-generator-") => plugin
                            .generate_device_code_async_with(move || async move {
                                Err(callback_error(name))
                            }),
                        name if name.starts_with("device-user-generator-") => plugin
                            .generate_user_code_async_with(move || async move {
                                Err(callback_error(name))
                            }),
                        name if name.starts_with("device-validation-") => plugin
                            .validate_client(move |_| async move { Err(callback_error(name)) }),
                        name if name.starts_with("device-request-") => plugin
                            .on_device_auth_request(move |_, _| async move {
                                Err(callback_error(name))
                            }),
                        _ => plugin,
                    };
            }
            "device-empty" => {
                plugin = plugin
                    .generate_device_code_with(String::new)
                    .generate_user_code_async_with(|| async { Ok(String::new()) });
            }
            "device-fractional" => {
                plugin = plugin
                    .expires_in(Duration::milliseconds(1750))
                    .interval(Duration::milliseconds(250))
                    .verification_uri("/verify-relative");
            }
            "device-negative-interval" => {
                plugin = plugin
                    .expires_in(Duration::seconds(120))
                    .interval(Duration::milliseconds(-250));
            }
            "device-negative" => {
                plugin = plugin
                    .expires_in(Duration::milliseconds(-1250))
                    .interval(Duration::milliseconds(-250))
                    .verification_uri("");
            }
            "device-too-long" => {
                plugin =
                    plugin.generate_device_code_async_with(|| async { Ok("😀".repeat(192)) });
            }
            _ => {}
        }
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base.clone().base_path(&path);
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
                        .enable_username(false),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(plugin)
                .build()
                .await?,
        );
        let routes: Router<Arc<BetterAuth<TestSchema>>> =
            auth.clone().axum_router().with_state(auth);
        router = router.nest(&path, routes);
    }
    Ok(router)
}

fn callback_error(name: &str) -> AuthError {
    if name.ends_with("-throw") {
        return AuthError::internal("Private device callback failure");
    }
    AuthError::Api {
        status: 400,
        code: Some("DEVICE_CALLBACK_FAILED".into()),
        message: "Configured device callback failed".into(),
    }
}
