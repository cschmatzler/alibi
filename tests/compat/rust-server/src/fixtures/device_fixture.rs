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
static GENERATOR_EVENTS: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratorSelector { client_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceOwner { device_code: String, user_id: String }
pub(crate) fn router(database: DatabaseConnection) -> Router<Arc<BetterAuth<TestSchema>>> {
    let read_database = database.clone();

    let generator_database = database.clone();
    let owner_database = database.clone();
    Router::new().merge(super::application_device_grant_fixture::router(database.clone())).route("/__test/device-generator-state", get(move |Query(body): Query<GeneratorSelector>| { let database = generator_database.clone(); async move {
        match device_code::Entity::find().filter(device_code::Column::ClientId.eq(body.client_id)).all(&database).await {
            Ok(rows) => { let mut grants: Vec<Value> = rows.into_iter().map(|row| json!({"deviceCode":row.device_code,"userCode":row.user_code,"userId":row.user_id,"status":row.status,"clientId":row.client_id,"scope":row.scope})).collect(); grants.sort_by(|a,b| a["deviceCode"].as_str().cmp(&b["deviceCode"].as_str())); (StatusCode::OK,Json(json!({"events": std::mem::take(&mut *GENERATOR_EVENTS.lock().unwrap()), "grants":grants}))) },
            Err(error) => (StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"message":error.to_string()})))
        }
    }})).route("/__test/device-callback-events", get(|| async { Json(std::mem::take(&mut *CALLBACK_EVENTS.lock().unwrap())) })).route("/__test/device-state",get(move |Query(body):Query<DeviceSelector>| {
  let database=read_database.clone();async move {
   match device_code::Entity::find().filter(device_code::Column::DeviceCode.eq(body.device_code)).one(&database).await {
    Ok(row)=>(StatusCode::OK,Json(row.map(|row|json!({"id":row.id,"deviceCode":row.device_code,"userCode":row.user_code,"userId":row.user_id,"status":row.status,"clientId":row.client_id,"scope":row.scope,"expiresAt":row.expires_at,"lastPolledAt":row.last_polled_at,"pollingInterval":row.polling_interval})).unwrap_or(Value::Null))),
    Err(error)=>(StatusCode::INTERNAL_SERVER_ERROR,Json(json!({"message":error.to_string()})))
   }
  }
 })).route("/__test/device-owner", post(move |Json(body): Json<DeviceOwner>| {let database = owner_database.clone(); async move {
    match device_code::Entity::update_many().filter(device_code::Column::DeviceCode.eq(body.device_code)).col_expr(device_code::Column::UserId, Expr::value(body.user_id)).exec(&database).await {
      Ok(_) => (StatusCode::OK, Json(json!({"changed": true}))), Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": error.to_string()})))
    }
 }})).route("/__test/expire-device",post(move |Json(body):Json<DeviceExpiry>| {
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
    super::application_device_grant_fixture::initialize(&database).await?;
    let mut router = Router::new();
    for name in [
        "device-collision-retry",
        "device-collision-exhaustion",
        "device-callback-success",
        "device-grant",
        "device-length-507",
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
            "device-grant" => { plugin = plugin.interval(Duration::zero()).grant(super::application_device_grant_fixture::Grant); }
            "device-collision-retry" | "device-collision-exhaustion" => {
                let device_index = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let user_index = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let generate = move |kind: &str, index: usize| {
                    let values = if kind == "device" { ["retry-device-original", "retry-device-original", "retry-device-user-collision", "retry-device-later", "retry-device-third"] } else { ["retry-user-original", "retry-user-device-collision", "retry-user-original", "retry-user-later", "retry-user-third"] };
                    let value = if name == "device-collision-exhaustion" { format!("constant-{kind}") } else { values[index].to_owned() };
                    GENERATOR_EVENTS.lock().unwrap().push(json!({"kind":kind,"value":value}));
                    value
                };
                plugin = plugin.generate_device_code_async_with(move || { let index = device_index.fetch_add(1,std::sync::atomic::Ordering::SeqCst); async move { Ok(generate("device",index)) } }).generate_user_code_async_with(move || { let index = user_index.fetch_add(1,std::sync::atomic::Ordering::SeqCst); async move { Ok(generate("user",index)) } });
            }
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
            "device-length-507" => { plugin = plugin.user_code_length(4); }
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
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
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
            .plugin(alibi::plugins::open_api::OpenApiPlugin::new())
                .plugin(plugin);
        if name=="device-grant" {builder=builder.plugin(super::application_device_grant_fixture::ApplicationToken(database.clone()));}
        let auth=Arc::new(builder.build().await?);
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
