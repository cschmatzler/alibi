//! Atomic rolling rate limits persisted independently of an application's auth schema.

use crate::SqlxValue;
use crate::pool::{Exec, SqlxPool};
use crate::sql::Sql;
use crate::store::migrator::{Migration, apply};
use alibi_core::middleware::rate_limit::bucket::{self, Step};
use alibi_core::store::SchemaMigrator;
use alibi_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use async_trait::async_trait;

const RATE_LIMIT_SCHEMA: Migration = Migration {
    name: "m20261013_000003_typescript_rate_limit_schema",
    sqlite: alibi_schema_registry::SQLITE_RATE_LIMIT_SCHEMA,
    postgres: alibi_schema_registry::POSTGRES_RATE_LIMIT_SCHEMA,
};

/// One stored quota bucket.
#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
pub struct RateLimitRow {
    pub key: String,
    pub count: crate::Number,
    #[sqlx(rename = "lastRequest")]
    pub last_request: i64,
}

/// Shared database storage. Run [`SchemaMigrator::migrate`] before serving
/// requests; ordinary auth migrations do not create or claim its table.
/// Compare-and-swap predicates preserve quotas across independent application instances.
#[derive(Clone, Debug)]
pub struct SqlxRateLimitStorage {
    pool: SqlxPool,
}

impl SqlxRateLimitStorage {
    #[must_use]
    pub fn new(pool: impl Into<SqlxPool>) -> Self {
        Self { pool: pool.into() }
    }

    const fn exec(&self) -> Exec<'_> {
        Exec::pool(&self.pool)
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
    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        let backend = self.exec().engine();
        loop {
            let mut select = Sql::with(
                backend,
                "SELECT \"rateLimit\".\"key\", \"rateLimit\".\"count\", \"rateLimit\".\"lastRequest\" FROM \"rateLimit\" WHERE ",
            );
            select.compare("rateLimit", "key", " = ", key);
            select.push(" LIMIT 1");
            let observed = self.exec().fetch_optional::<RateLimitRow>(select).await?;
            let now = chrono::Utc::now().timestamp_millis();
            let Some(observed) = observed else {
                let mut insert = Sql::with(
                    backend,
                    "INSERT INTO \"rateLimit\" (\"id\", \"key\", \"count\", \"lastRequest\") VALUES (",
                );
                insert.bind(uuid::Uuid::new_v4().to_string());
                insert.push(", ");
                insert.bind(key);
                insert.push(", ");
                insert.bind(1_i32);
                insert.push(", ");
                insert.bind(now);
                insert.push(") ON CONFLICT (\"key\") DO NOTHING");
                if self.exec().execute(insert).await? == 1 {
                    return Ok(RateLimitDecision::Allowed);
                }
                continue;
            };
            let count = match bucket::step(observed.count.0, observed.last_request, now, rule) {
                Step::Blocked { retry_after } => {
                    return Ok(RateLimitDecision::Blocked { retry_after });
                }
                Step::Allowed { count, .. } => count,
            };
            let mut update = Sql::with(backend, "UPDATE \"rateLimit\" SET \"count\" = ");
            update.bind(crate::Number(count).into_sql_value());
            update.push(", \"lastRequest\" = ");
            update.bind(now);
            update.push(" WHERE ");
            update.compare("rateLimit", "key", " = ", key);
            update.push(" AND ");
            update.compare("rateLimit", "lastRequest", " = ", observed.last_request);
            update.push(" AND ");
            update.compare("rateLimit", "count", " = ", observed.count.into_sql_value());
            if self.exec().execute(update).await? == 1 {
                return Ok(RateLimitDecision::Allowed);
            }
        }
    }
}
