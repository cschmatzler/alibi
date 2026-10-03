//! Atomic rolling rate limits persisted independently of an application's auth schema.

use crate::pool::{Exec, SqlxPool};
use crate::sql::Sql;
use crate::store::migrator::{Migration, apply};
use async_trait::async_trait;
use better_auth_core::store::SchemaMigrator;
use better_auth_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const RATE_LIMIT_SCHEMA: Migration = Migration {
    name: "m20261002_000001_rate_limit",
    sqlite: r#"CREATE TABLE IF NOT EXISTS "rate_limit" ( "key" varchar NOT NULL PRIMARY KEY, "count" double NOT NULL, "expires_at" integer, "last_request" integer NOT NULL );"#,
    postgres: r#"CREATE TABLE IF NOT EXISTS "rate_limit" ( "key" varchar NOT NULL PRIMARY KEY, "count" double precision NOT NULL, "expires_at" bigint, "last_request" bigint NOT NULL );"#,
};

/// One stored quota bucket.
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
pub struct RateLimitRow {
    pub key: String,
    pub count: f64,
    pub last_request: i64,
    pub expires_at: Option<i64>,
}

/// Shared database storage. Run [`SchemaMigrator::migrate`] before serving
/// requests; ordinary auth migrations do not create or claim its table.
/// Compare-and-swap predicates preserve quotas across independent application instances.
#[derive(Clone, Debug)]
pub struct SqlxRateLimitStorage {
    pool: SqlxPool,
    longest_window: Arc<AtomicU64>,
}

impl SqlxRateLimitStorage {
    #[must_use]
    pub fn new(pool: impl Into<SqlxPool>) -> Self {
        Self {
            pool: pool.into(),
            longest_window: Arc::new(AtomicU64::new(60.0_f64.to_bits())),
        }
    }

    const fn exec(&self) -> Exec<'_> {
        Exec::Pool(&self.pool)
    }

    fn expires_at(now: i64, window: f64) -> Option<i64> {
        if window <= 0.0 || window.is_nan() {
            return Some(now);
        }
        std::time::Duration::try_from_secs_f64(window)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .and_then(|milliseconds| now.checked_add(milliseconds))
    }

    async fn prune(&self, now: i64) {
        let window = f64::from_bits(self.longest_window.load(Ordering::Relaxed));
        let Some(cutoff) = std::time::Duration::try_from_secs_f64(window)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .and_then(|milliseconds| now.checked_sub(milliseconds))
        else {
            return;
        };
        let mut sql = Sql::with(self.exec().backend(), "DELETE FROM \"rate_limit\" WHERE ");
        sql.column("rate_limit", "last_request")
            .push(" < ")
            .bind(cutoff)
            .push(" AND ")
            .column("rate_limit", "expires_at")
            .push(" <= ")
            .bind(now);
        // Pruning failures do not undo a successful quota consumption. The
        // next admitted new/reset bucket retries cleanup without logging keys.
        if self.exec().execute(sql).await.is_err() {
            tracing::warn!("Rate-limit cleanup failed");
        }
    }
}

/// Installs the opt-in rate-limit table using its own migration ledger.
/// Migration errors are returned without serving requests on missing storage.
#[async_trait]
impl SchemaMigrator for SqlxRateLimitStorage {
    async fn migrate(&self) -> AuthResult<()> {
        apply(
            &self.pool,
            "better_auth_rate_limit_migrations",
            &[RATE_LIMIT_SCHEMA],
        )
        .await
    }
}

#[async_trait]
impl RateLimitStorage for SqlxRateLimitStorage {
    fn observe_window(&self, window: f64) {
        if window > 0.0 {
            // Positive IEEE-754 bit patterns have the same ordering as
            // their numeric values, so this is an atomic maximum in one step.
            _ = self
                .longest_window
                .fetch_max(window.to_bits(), Ordering::Relaxed);
        }
    }

    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.observe_window(rule.window_seconds);
        let backend = self.exec().backend();
        loop {
            let mut select = Sql::with(
                backend,
                "SELECT \"rate_limit\".\"key\", \"rate_limit\".\"count\", \"rate_limit\".\"last_request\", \"rate_limit\".\"expires_at\" FROM \"rate_limit\" WHERE ",
            );
            select
                .column("rate_limit", "key")
                .push(" = ")
                .bind(key)
                .push(" LIMIT 1");
            let observed = self.exec().fetch_optional::<RateLimitRow>(select).await?;
            let now = chrono::Utc::now().timestamp_millis();
            let Some(observed) = observed else {
                let mut insert = Sql::with(
                    backend,
                    "INSERT INTO \"rate_limit\" (\"key\", \"count\", \"last_request\", \"expires_at\") VALUES (",
                );
                insert
                    .bind(key)
                    .push(", ")
                    .bind(1.0_f64)
                    .push(", ")
                    .bind(now)
                    .push(", ")
                    .bind(Self::expires_at(now, rule.window_seconds))
                    .push(") ON CONFLICT (\"key\") DO NOTHING");
                if self.exec().execute(insert).await? == 1 {
                    self.prune(now).await;
                    return Ok(RateLimitDecision::Allowed);
                }
                continue;
            };
            let elapsed = chrono::Duration::milliseconds(now.saturating_sub(observed.last_request))
                .to_std()
                .map_or(0.0, |duration| duration.as_secs_f64());
            let expired = elapsed >= rule.window_seconds;
            if !expired
                && (rule.window_seconds.is_nan()
                    || rule.max_requests.is_nan()
                    || observed.count >= rule.max_requests)
            {
                return Ok(RateLimitDecision::Blocked {
                    retry_after: (rule.window_seconds - elapsed).ceil(),
                });
            }
            let next_count = if expired { 1.0 } else { observed.count + 1.0 };
            let mut update = Sql::with(backend, "UPDATE \"rate_limit\" SET \"count\" = ");
            update
                .bind(next_count)
                .push(", \"last_request\" = ")
                .bind(now)
                .push(", \"expires_at\" = ")
                .bind(Self::expires_at(now, rule.window_seconds))
                .push(" WHERE ")
                .column("rate_limit", "key")
                .push(" = ")
                .bind(key)
                .push(" AND ")
                .column("rate_limit", "last_request")
                .push(" = ")
                .bind(observed.last_request)
                .push(" AND ")
                .column("rate_limit", "count")
                .push(" = ")
                .bind(observed.count);
            if self.exec().execute(update).await? == 1 {
                if expired {
                    self.prune(now).await;
                }
                return Ok(RateLimitDecision::Allowed);
            }
        }
    }
}
