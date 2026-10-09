//! Explicit session configurations and trusted persisted-clock controls.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
use alibi::plugins::multi_session::MultiSessionPlugin;
use alibi::plugins::one_time_token::OneTimeTokenPlugin;
use alibi::plugins::password_management::SendResetPassword;
use alibi::plugins::{
    AdminPlugin, EmailPasswordPlugin, OrganizationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::store::{CacheAdapter, MemoryCacheAdapter};
use alibi::seaorm::sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, sea_query::Expr,
};
use alibi::seaorm::store::entities::session;
use axum::{Json, Router, http::StatusCode, routing::post};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClock {
    token: String,
    expires_at: DateTime<Utc>,
    created_at: Option<DateTime<Utc>>,
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    reset_sender: Arc<dyn SendResetPassword>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut caches = HashMap::<String, Arc<dyn CacheAdapter>>::new();
    let mut id_databases = HashMap::new();
    let mut id_events = HashMap::new();
    for name in [
        "session-secondary-only",
        "session-secondary-preserve-only",
        "session-secondary-combined",
        "session-secondary-preserved",
        "id-strategy-uuid",
        "id-strategy-serial",
        "id-strategy-custom",
        "id-strategy-false",
        "id-strategy-throw",
        "stateless-refresh-compact",
        "stateless-refresh-jwt",
        "stateless-refresh-deferred",
        "stateless-refresh-v2",
        "stateless-refresh-jwt-v2",
        "session-update-age",
        "session-update-age-cache",
        "session-update-age-long",
        "session-deferred-update-age",
        "session-deferred",
        "session-no-refresh",
        "session-deferred-no-refresh",
        "session-no-freshness",
        "snake-casing",
        "session-cookie-cleanup",
        "account-unlink-all",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        let profile_database = if let Some(mode) = name.strip_prefix("id-strategy-") {
            let database = alibi::seaorm::sea_orm::Database::connect("sqlite::memory:")
                .await
                .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
            crate::backend::migrate(&database)
                .await
                .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
            id_databases.insert(mode.to_owned(), database.clone());
            let events = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
            id_events.insert(mode.to_owned(), events.clone());
            let sequence = std::sync::atomic::AtomicUsize::new(0);
            let mode = mode.to_owned();
            config.advanced.database.generate_id = Some(match mode.as_str() {
                "uuid" => alibi::config::DatabaseIdStrategy::Uuid,
                "serial" => alibi::config::DatabaseIdStrategy::Serial,
                _ => alibi::config::DatabaseIdStrategy::Custom(Arc::new(
                    move |model: &str, size: Option<usize>| {
                        let mut event = json!({"model":model});
                        if let Some(size) = size {
                            event["size"] = json!(size);
                        }
                        events.lock().unwrap().push(event);
                        if mode == "throw" {
                            return Err(alibi::AuthError::internal(
                                "Application ID generation failed",
                            ));
                        }
                        Ok(if mode == "false" {
                            None
                        } else {
                            Some(format!(
                                "{model}_application_{}",
                                sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
                            ))
                        })
                    },
                )),
            });
            database
        } else {
            database.clone()
        };
        if name.starts_with("session-secondary-") {
            let cache: Arc<dyn CacheAdapter> = Arc::new(MemoryCacheAdapter::new());
            config.session.secondary_storage = Some(cache.clone());
            config.verification.secondary_storage = Some(cache.clone());
            config.session.store_in_database =
                name.ends_with("combined") || name.ends_with("preserved");
            config.session.preserve_in_database = name.contains("preserve");
            drop(caches.insert(name.to_owned(), cache));
        }
        if name.starts_with("stateless-refresh-") {
            config.session = config.session.stateless();
            config.account.store_account_cookie = true;
            config.account.store_state_strategy = alibi::OAuthStateStrategy::Cookie;
            config.session.cookie_cache = Some(alibi::CookieCacheConfig {
                enabled: true,
                max_age: 5.0,
                strategy: if name.contains("jwt") {
                    alibi::CookieCacheStrategy::Jwt
                } else {
                    alibi::CookieCacheStrategy::Compact
                },
                version: Some(alibi::CookieCacheVersion::Literal(
                    if name.ends_with("v2") { "2" } else { "1" }.into(),
                )),
            });
            config.session.cookie_refresh_cache = alibi::CookieRefreshCache::UpdateAge(4.0);
        }
        if name.contains("update-age") {
            config.session.expires_in = chrono::Duration::seconds(3600);
            config.session.update_age =
                Some(chrono::Duration::seconds(if name.ends_with("-long") {
                    7200
                } else {
                    120
                }));
        }
        if name == "session-update-age-cache" {
            config.session.cookie_cache = Some(alibi::CookieCacheConfig {
                enabled: true,
                max_age: 300.0,
                ..Default::default()
            });
        }
        config.session.defer_session_refresh =
            name.starts_with("session-deferred") || name.ends_with("refresh-deferred");
        config.session.disable_session_refresh =
            name.ends_with("no-refresh") || name.starts_with("stateless-refresh-");
        if name == "session-no-freshness" {
            config.session.fresh_age = Some(chrono::Duration::zero());
        }
        if name == "session-cookie-cleanup" {
            config.account.store_account_cookie = true;
            config.account.store_state_strategy = alibi::config::OAuthStateStrategy::Cookie;
        }
        if name == "account-unlink-all" {
            config.account.account_linking.allow_unlinking_all = true;
        }
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                profile_database,
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new().send_reset_password(reset_sender.clone()))
            .plugin(
                UserManagementPlugin::new()
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .plugin(AdminPlugin::new())
            .plugin(TwoFactorPlugin::new())
            .plugin(OrganizationPlugin::new())
            .plugin(alibi::plugins::open_api::OpenApiPlugin::new());
        if name == "account-unlink-all" {
            builder = builder.plugin(alibi::plugins::AccountManagementPlugin::new());
        }
        if name.starts_with("session-secondary-") {
            builder = builder
                .plugin(MultiSessionPlugin::new())
                .plugin(OneTimeTokenPlugin::new())
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    enable_session_for_api_keys: true,
                    ..Default::default()
                }));
        }
        let auth = Arc::new(builder.build().await?);
        let routes = auth.clone().axum_router().with_state(auth);
        router = router.nest(&path, routes);
    }
    router = router.route("/__test/id-strategy/{mode}/state", axum::routing::get(move |axum::extract::Path(mode): axum::extract::Path<String>| {let database = id_databases[&mode].clone(); let events = id_events[&mode].clone(); async move {
        use alibi::seaorm::sea_orm::{ConnectionTrait, Statement};
        let read = async |table: &str, owner: bool| {
            let columns = if owner {"id, user_id"} else {"id"};
            let rows = database.query_all_raw(Statement::from_string(database.get_database_backend(), format!("SELECT {columns} FROM {table}"))).await.unwrap();
            rows.iter().map(|row| {let mut value = json!({"id": row.try_get::<String>("", "id").unwrap()}); if owner {value["userId"] = json!(row.try_get::<String>("", "user_id").unwrap());} value}).collect::<Vec<_>>()
        };
        Json(json!({"users": read("users",false).await, "accounts": read("accounts",true).await, "sessions": read("sessions",true).await, "verification": read("verifications",false).await, "events": *events.lock().unwrap()}))
    }}));
    let casing_database = database.clone();
    router = router.route("/__test/casing/state", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<HashMap<String,String>>| {let database = casing_database.clone(); async move {
        use alibi::seaorm::sea_orm::{ConnectionTrait, Statement};
        let id = query.get("userId").unwrap();
        let users = database.query_all_raw(Statement::from_sql_and_values(database.get_database_backend(), "SELECT id, name, email, email_verified FROM users WHERE id = ?", [id.clone().into()])).await.unwrap();
        let sessions = database.query_all_raw(Statement::from_sql_and_values(database.get_database_backend(), "SELECT user_id FROM sessions WHERE user_id = ?", [id.clone().into()])).await.unwrap();
        Json(serde_json::json!({"users": users.iter().map(|row| serde_json::json!({"id": row.try_get::<String>("","id").unwrap(), "name": row.try_get::<String>("","name").unwrap(), "email": row.try_get::<String>("","email").unwrap(), "verified": i32::from(row.try_get::<bool>("","email_verified").unwrap())})).collect::<Vec<_>>(), "sessions": sessions.iter().map(|row| serde_json::json!({"owner": row.try_get::<String>("","user_id").unwrap()})).collect::<Vec<_>>()}))
    }}));
    let caches = Arc::new(caches);
    router = router.route(
        "/__test/secondary-session/control",
        post(move |Json(body): Json<Value>| {
            let caches = caches.clone();
            async move {
                let profile = body
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let token = body
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let Some(cache) = caches.get(profile) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error":"Unknown profile"})),
                    );
                };
                let result = if body.get("action").and_then(Value::as_str) == Some("remove") {
                    cache.delete(token).await.map(|()| Value::Null)
                } else {
                    cache
                        .get(token)
                        .await
                        .map(|value| json!({"present":value.is_some()}))
                };
                match result {
                    Ok(value) => (StatusCode::OK, Json(value)),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":error.to_string()})),
                    ),
                }
            }
        }),
    );
    Ok(router.route(
        "/__test/expire-session",
        post(move |Json(body): Json<SessionClock>| {
            let database = database.clone();
            async move {
                let mut update = session::Entity::update_many()
                    .col_expr(session::Column::ExpiresAt, Expr::value(body.expires_at))
                    .filter(session::Column::Token.eq(body.token));
                if let Some(created_at) = body.created_at {
                    update = update.col_expr(session::Column::CreatedAt, Expr::value(created_at));
                }
                match update.exec(&database).await {
                    Ok(result) => (
                        StatusCode::OK,
                        Json(json!({"updated":result.rows_affected})),
                    ),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(Value::String(error.to_string())),
                    ),
                }
            }
        }),
    ))
}
