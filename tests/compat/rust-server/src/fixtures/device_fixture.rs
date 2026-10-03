//! Trusted fixture controls for persisted OAuth device grants.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    DeviceAuthorizationPlugin, EmailPasswordPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use better_auth_seaorm::{
    DatabaseConnection,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr},
    store::entities::device_code,
};
use chrono::Duration;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
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
    Router::new().route("/__test/device-state",get(move |Query(body):Query<DeviceSelector>| {
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
        "device-custom",
        "device-configured",
        "device-unicode",
        "device-too-long",
    ] {
        let mut plugin = DeviceAuthorizationPlugin::new();
        match name {
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
