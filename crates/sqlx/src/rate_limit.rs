//! Atomic rolling rate limits persisted independently of an application's auth schema.

use crate::pool::{Exec, SqlxPool};
use crate::sql::Sql;
use crate::store::migrator::{Migration, apply};
use async_trait::async_trait;
use better_auth_core::middleware::rate_limit::bucket::{self, LongestWindow, Step};
use better_auth_core::store::SchemaMigrator;
use better_auth_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use std::sync::Arc;

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
    longest_window: Arc<LongestWindow>,
}

impl SqlxRateLimitStorage {
    #[must_use]
    pub fn new(pool: impl Into<SqlxPool>) -> Self {
        Self {
            pool: pool.into(),
            longest_window: Arc::new(LongestWindow::new()),
        }
    }

    const fn exec(&self) -> Exec<'_> {
        Exec::Pool(&self.pool)
    }

    async fn prune(&self, now: i64) {
        let Some(cutoff) = self.longest_window.prune_cutoff(now) else {
            return;
        };
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM \"rate_limit\" WHERE ");
        sql.compare("rate_limit", "last_request", " < ", cutoff);
        sql.push(" AND ");
        sql.compare("rate_limit", "expires_at", " <= ", now);
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
        self.longest_window.observe(window);
    }

    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.observe_window(rule.window_seconds);
        let backend = self.exec().engine();
        loop {
            let mut select = Sql::with(
                backend,
                "SELECT \"rate_limit\".\"key\", \"rate_limit\".\"count\", \"rate_limit\".\"last_request\", \"rate_limit\".\"expires_at\" FROM \"rate_limit\" WHERE ",
            );
            select.compare("rate_limit", "key", " = ", key);
            select.push(" LIMIT 1");
            let observed = self.exec().fetch_optional::<RateLimitRow>(select).await?;
            let now = chrono::Utc::now().timestamp_millis();
            let Some(observed) = observed else {
                let mut insert = Sql::with(
                    backend,
                    "INSERT INTO \"rate_limit\" (\"key\", \"count\", \"last_request\", \"expires_at\") VALUES (",
                );
                insert.bind(key);
                insert.push(", ");
                insert.bind(1.0_f64);
                insert.push(", ");
                insert.bind(now);
                insert.push(", ");
                insert.bind(bucket::expires_at(now, rule.window_seconds));
                insert.push(") ON CONFLICT (\"key\") DO NOTHING");
                if self.exec().execute(insert).await? == 1 {
                    self.prune(now).await;
                    return Ok(RateLimitDecision::Allowed);
                }
                continue;
            };
            let (count, reset) =
                match bucket::step(observed.count, observed.last_request, now, rule) {
                    Step::Blocked { retry_after } => {
                        return Ok(RateLimitDecision::Blocked { retry_after });
                    }
                    Step::Allowed { count, reset } => (count, reset),
                };
            let mut update = Sql::with(backend, "UPDATE \"rate_limit\" SET \"count\" = ");
            update.bind(count);
            update.push(", \"last_request\" = ");
            update.bind(now);
            update.push(", \"expires_at\" = ");
            update.bind(bucket::expires_at(now, rule.window_seconds));
            update.push(" WHERE ");
            update.compare("rate_limit", "key", " = ", key);
            update.push(" AND ");
            update.compare("rate_limit", "last_request", " = ", observed.last_request);
            update.push(" AND ");
            update.compare("rate_limit", "count", " = ", observed.count);
            if self.exec().execute(update).await? == 1 {
                if reset {
                    self.prune(now).await;
                }
                return Ok(RateLimitDecision::Allowed);
            }
        }
    }
}
