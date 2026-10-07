//! Public authentication requests with the genuine enabled limiter.
use crate::{TestSchema, otp_profiles};
use axum::{Router, Json, routing::get};
use alibi_core::store::SchemaMigrator;
use alibi_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::json;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{
    EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule,
};
use alibi::plugins::EmailPasswordPlugin;
use alibi::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use alibi_seaorm::DatabaseConnection;
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
    let read_database = database.clone();
    let mut router = Router::new().route("/__test/rate-database-state", get(move || {
        let database = read_database.clone();
        async move {
            let rows = database.query_all_raw(Statement::from_string(DbBackend::Sqlite, "SELECT key,count,last_request FROM rate_limit ORDER BY key")).await.unwrap();
            Json(rows.into_iter().map(|row| json!({"key": row.try_get::<String>("", "key").unwrap(), "count": row.try_get::<f64>("", "count").unwrap(), "lastRequest": row.try_get::<i64>("", "last_request").unwrap()})).collect::<Vec<_>>())
        }
    }));
    for name in ["ordered", "default", "database-first", "database-second"] {
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
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(limits)
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(otp_profiles::plugin(outbox.clone()))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
