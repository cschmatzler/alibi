//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use axum::{Json, routing::{get, post}};
use alibi_core::store::SchemaMigrator;
use alibi_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule};
use alibi::plugins::EmailPasswordPlugin;
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use alibi_seaorm::DatabaseConnection;
use axum::Router;
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct HeaderQuota;
#[async_trait::async_trait]
impl RateLimitResolver for HeaderQuota {
    async fn resolve(
        &self,
        request: &alibi_core::AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        Ok(
            if request
                .headers
                .get("x-rate-bypass")
                .is_some_and(|value| value == "yes")
            {
                None
            } else {
                Some(EndpointRateLimit {
                    max_requests: 1.0,
                    window_seconds: if request
                        .headers
                        .get("x-rate-zero")
                        .is_some_and(|value| value == "yes")
                    {
                        0.0
                    } else {
                        inherited.window_seconds
                    },
                })
            },
        )
    }
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    outbox: otp_profiles::Outbox,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    #[cfg(feature = "seaorm")]
    let storage = Arc::new(alibi_seaorm::SeaOrmRateLimitStorage::new(database.clone()));
    #[cfg(not(feature = "seaorm"))]
    let storage = Arc::new(alibi_sqlx::SqlxRateLimitStorage::new(alibi_sqlx::SqlxPool::from(database.get_sqlite_connection_pool().clone())));
    storage.migrate().await?;
    let control_database = database.clone();
    let read_database = database.clone();
    let mut router = Router::new().route("/__test/rate-database-state", get(move || {
        let database = read_database.clone();
        async move {
            let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite, "SELECT key,count,last_request FROM rate_limit ORDER BY key")).await.unwrap();
            Json(rows.into_iter().map(|row| json!({"key": row.try_get::<String>("", "key").unwrap(), "count": row.try_get::<f64>("", "count").unwrap(), "lastRequest": row.try_get::<i64>("", "last_request").unwrap()})).collect::<Vec<_>>())
        }
    }));
    router = router.route("/__test/rate-database-control", post(move |Json(body): Json<Value>| {
        let database = control_database.clone();
        async move {
            let sql = if body["action"] == "disable" { "ALTER TABLE rate_limit RENAME TO fixtureRateLimitHeld" } else { "ALTER TABLE fixtureRateLimitHeld RENAME TO rate_limit" };
            database.execute_raw(Statement::from_string(DbBackend::Sqlite, sql)).await.unwrap();
            Json(json!({"status": true}))
        }
    }));
    let cache = Arc::new(alibi_core::MemoryCacheAdapter::new());
    for name in [
        "ordered",
        "default",
        "database-first",
        "database-second",
        "secondary-a",
        "secondary-b",
        "concurrent-memory",
        "concurrent-secondary-a",
        "concurrent-secondary-b",
    ] {
        let mut config = base.clone();
        config.base_path = format!("/__test/profiles/rate-limit-{name}/api/auth");
        let path = config.base_path.clone();
        let mut limits = RateLimitConfig::new().default_limit(
            Duration::from_secs(60),
            if name == "ordered" { 1 } else { 10000 },
        );
        if name.starts_with("database-") {
            limits = limits.storage(storage.clone()).endpoint("/get-session", Duration::from_secs(1), 2);
        }
        if name.contains("secondary") {
            limits = limits.storage(Arc::new(alibi_core::CacheRateLimitStorage::new(
                cache.clone(),
            )));
            if !name.starts_with("concurrent-") {
                limits = limits
                    .endpoint("/get-session", Duration::from_secs(1), 2)
                    .rule("/list-sessions", RateLimitRule::Disabled);
            }
        }
        if name.starts_with("concurrent-") {
            limits = limits.endpoint("/sign-up/email", Duration::from_secs(60), 3);
        }
        if name == "ordered" {
            limits = limits
                .endpoint("/sign-up/*", Duration::from_secs(60), 2)
                .endpoint("/sign-up/email", Duration::from_secs(60), 4)
                .rule(
                    "/get-session",
                    RateLimitRule::Dynamic(Arc::new(HeaderQuota)),
                )
                .rule("/list-sessions", RateLimitRule::Disabled);
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
            .rate_limit(limits)
            .plugin(EmailPasswordPlugin::new().enable_username(false));
        let builder = if name.starts_with("concurrent-") {
            builder
        } else {
            builder.plugin(otp_profiles::plugin(outbox.clone()))
        };
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let control_cache = cache.clone();
    router = router.route("/__test/rate-limit-secondary/control", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>| {let cache = control_cache.clone(); async move {
        use alibi_core::CacheAdapter;
        axum::Json(serde_json::json!({"value": cache.get(query.get("key").expect("requested key")).await.unwrap()}))
    }}));
    Ok(router)
}
