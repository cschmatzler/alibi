//! Atomic rolling rate limits persisted independently of an application's auth schema.

use async_trait::async_trait;
use better_auth_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use sea_orm::sea_query::{Alias, ColumnDef, DynIden, IntoIden, Table};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::prelude::{
    DbErr, MigrationName, MigrationTrait, MigratorTrait, SchemaManager,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

pub mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "rate_limit")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub key: String,
        pub count: f64,
        pub last_request: i64,
        pub expires_at: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Shared database storage. Call `migrate` before serving requests; ordinary
/// auth migrations do not create or claim its table.
/// Compare-and-swap predicates preserve quotas across independent application instances.
#[derive(Clone, Debug)]
pub struct SeaOrmRateLimitStorage {
    database: DatabaseConnection,
    longest_window: Arc<AtomicU64>,
}

impl SeaOrmRateLimitStorage {
    #[must_use]
    pub fn new(database: DatabaseConnection) -> Self {
        Self {
            database,
            longest_window: Arc::new(AtomicU64::new(60.0_f64.to_bits())),
        }
    }
    /// Install the opt-in rate-limit table using its own migration ledger.
    /// # Errors
    /// Returns the actual migration error without serving requests on missing storage.
    pub async fn migrate(&self) -> AuthResult<()> {
        RateLimitMigrator::up(&self.database, None)
            .await
            .map_err(crate::store::map_db_err)
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
        // Pruning failures do not undo a successful quota consumption. The
        // next admitted new/reset bucket retries cleanup without logging keys.
        if entity::Entity::delete_many()
            .filter(entity::Column::LastRequest.lt(cutoff))
            .filter(entity::Column::ExpiresAt.lte(now))
            .exec(&self.database)
            .await
            .is_err()
        {
            tracing::warn!("Rate-limit cleanup failed");
        }
    }
}

#[async_trait]
impl RateLimitStorage for SeaOrmRateLimitStorage {
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
        loop {
            let observed = entity::Entity::find_by_id(key)
                .one(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
            let now = chrono::Utc::now().timestamp_millis();
            let Some(observed) = observed else {
                let inserted = entity::Entity::insert(entity::ActiveModel {
                    key: Set(key.to_owned()),
                    count: Set(1.0),
                    last_request: Set(now),
                    expires_at: Set(Self::expires_at(now, rule.window_seconds)),
                })
                .on_conflict(
                    OnConflict::column(entity::Column::Key)
                        .do_nothing()
                        .to_owned(),
                )
                .try_insert()
                .exec(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
                if matches!(inserted, sea_orm::TryInsertResult::Inserted(_)) {
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
            let updated = entity::Entity::update_many()
                .col_expr(entity::Column::Count, Expr::value(next_count))
                .col_expr(entity::Column::LastRequest, Expr::value(now))
                .col_expr(
                    entity::Column::ExpiresAt,
                    Expr::value(Self::expires_at(now, rule.window_seconds)),
                )
                .filter(entity::Column::Key.eq(key))
                .filter(entity::Column::LastRequest.eq(observed.last_request))
                .filter(entity::Column::Count.eq(observed.count))
                .exec(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
            if updated.rows_affected == 1 {
                if expired {
                    self.prune(now).await;
                }
                return Ok(RateLimitDecision::Allowed);
            }
        }
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::middleware::{Middleware, RateLimitConfig, RateLimitMiddleware};
    use better_auth_core::{AuthRequest, HttpMethod};
    use sea_orm::{ConnectionTrait, Database};
    use std::{collections::HashMap, sync::Arc, time::Duration};

    async fn shared_database_contract(url: &str) {
        let first = Database::connect(url).await.unwrap();
        SeaOrmRateLimitStorage::new(first.clone())
            .migrate()
            .await
            .unwrap();
        let second = Database::connect(url).await.unwrap();
        let key = format!("198.51.100.1|/proof-{}-'", uuid::Uuid::new_v4());
        let rule = EndpointRateLimit {
            window_seconds: 0.35,
            max_requests: 3.0,
        };
        let stores = [
            SeaOrmRateLimitStorage::new(first.clone()),
            SeaOrmRateLimitStorage::new(second.clone()),
        ];
        for storage in &stores[..1] {
            _ = RateLimitMiddleware::new(RateLimitConfig::new().storage(Arc::new(storage.clone())))
                .with_plugin_rules(vec![better_auth_core::PluginRateLimit {
                    matches: |path| path == "/long-lived",
                    limit: EndpointRateLimit {
                        window_seconds: 180.0,
                        max_requests: 3.0,
                    },
                }]);
        }
        let now = chrono::Utc::now().timestamp_millis();
        let old_key = format!("stale-{key}");
        let protected_key = format!("protected-{key}");
        let protected = entity::Model {
            key: protected_key.clone(),
            count: 3.0,
            last_request: now - 121_000,
            expires_at: Some(now + 59_000),
        };
        _ = entity::Entity::insert_many([
            entity::ActiveModel {
                key: Set(old_key.clone()),
                count: Set(3.0),
                last_request: Set(now - 181_000),
                expires_at: Set(Some(now - 1_000)),
            },
            entity::ActiveModel {
                key: Set(protected_key.clone()),
                count: Set(protected.count),
                last_request: Set(protected.last_request),
                expires_at: Set(protected.expires_at),
            },
        ])
        .exec(&first)
        .await
        .unwrap();
        let infinite_key = format!("infinite-{key}");
        let infinite_rule = EndpointRateLimit {
            window_seconds: f64::INFINITY,
            max_requests: 1.0,
        };
        assert!(matches!(
            stores[0]
                .consume(&infinite_key, &infinite_rule)
                .await
                .unwrap(),
            RateLimitDecision::Allowed
        ));
        _ = entity::Entity::update_many()
            .col_expr(entity::Column::LastRequest, Expr::value(now - 181_000))
            .filter(entity::Column::Key.eq(&infinite_key))
            .exec(&first)
            .await
            .unwrap();
        let infinite = entity::Entity::find_by_id(&infinite_key)
            .one(&second)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(infinite.expires_at, None);
        // The independent shorter-window process performs cleanup without
        // retiring another process's long-lived or nonexpiring quota.
        assert!(matches!(
            stores[1]
                .consume(&format!("cleanup-{key}"), &rule)
                .await
                .unwrap(),
            RateLimitDecision::Allowed
        ));
        let results = futures_concurrent(&stores, &key, &rule).await;
        assert!(
            entity::Entity::find_by_id(&old_key)
                .one(&second)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            entity::Entity::find_by_id(&protected_key)
                .one(&second)
                .await
                .unwrap()
                .unwrap(),
            protected
        );
        assert_eq!(
            entity::Entity::find_by_id(&infinite_key)
                .one(&second)
                .await
                .unwrap()
                .unwrap(),
            infinite
        );
        assert!(
            matches!(stores[1].consume(&infinite_key, &infinite_rule).await.unwrap(), RateLimitDecision::Blocked { retry_after } if retry_after.is_infinite())
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, RateLimitDecision::Allowed))
                .count(),
            3
        );
        let before = entity::Entity::find_by_id(&key)
            .one(&first)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.count.to_string(), "3");
        assert!(matches!(
            stores[1].consume(&key, &rule).await.unwrap(),
            RateLimitDecision::Blocked { .. }
        ));
        assert_eq!(
            entity::Entity::find_by_id(&key)
                .one(&second)
                .await
                .unwrap()
                .unwrap(),
            before
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(matches!(
            stores[0].consume(&key, &rule).await.unwrap(),
            RateLimitDecision::Allowed
        ));
        let reset = entity::Entity::find_by_id(&key)
            .one(&second)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reset.count.to_string(), "1");
        assert!(reset.last_request > before.last_request);
        // An absent/misconfigured backend fails closed before endpoint dispatch.
        _ = first
            .execute_unprepared("DROP TABLE rate_limit")
            .await
            .unwrap();
        let middleware =
            RateLimitMiddleware::new(RateLimitConfig::new().storage(Arc::new(stores[0].clone())));
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_owned(),
            HashMap::new(),
            None,
            HashMap::new(),
        );
        let failure = middleware
            .before_request(&request)
            .await
            .unwrap_err()
            .to_auth_response();
        assert_eq!(failure.status, 500);
        assert!(!String::from_utf8_lossy(&failure.body).contains("rate_limit"));
        RateLimitMigrator::refresh(&first).await.unwrap();
        first.close().await.unwrap();
        second.close().await.unwrap();
    }

    async fn futures_concurrent(
        stores: &[SeaOrmRateLimitStorage; 2],
        key: &str,
        rule: &EndpointRateLimit,
    ) -> Vec<RateLimitDecision> {
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..32 {
            let storage = stores.get(index % 2).unwrap().clone();
            let key = key.to_owned();
            let rule = rule.clone();
            _ = tasks.spawn(async move { storage.consume(&key, &rule).await.unwrap() });
        }
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result.unwrap());
        }
        results
    }

    #[tokio::test]
    async fn independent_sqlite_instances_preserve_quota_expiry_and_fail_closed() {
        let path = std::env::temp_dir().join(format!(
            "better-auth-rate-limit-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        shared_database_contract(&format!("sqlite://{}?mode=rwc", path.display())).await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL database; drops its limiter table"]
    async fn independent_postgres_instances_preserve_quota_expiry_and_fail_closed() {
        shared_database_contract(&std::env::var("TEST_RATE_LIMIT_POSTGRES_URL").unwrap()).await;
    }
}
// LCOV_EXCL_STOP

/// Opt-in migrations, recorded separately from application authentication tables.
#[derive(Debug)]
pub struct RateLimitMigrator;

#[async_trait]
impl MigratorTrait for RateLimitMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(RateLimitSchema)]
    }
    fn migration_table_name() -> DynIden {
        Alias::new("better_auth_rate_limit_migrations").into_iden()
    }
}

struct RateLimitSchema;
impl MigrationName for RateLimitSchema {
    fn name(&self) -> &'static str {
        "m20261002_000001_rate_limit"
    }
}

impl MigrationTrait for RateLimitSchema {
    fn up<'a, 'b, 'future>(
        &'a self,
        manager: &'b SchemaManager<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'future>>
    where
        'a: 'future,
        'b: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            manager
                .create_table(
                    Table::create()
                        .table(Alias::new("rate_limit"))
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Alias::new("key"))
                                .string()
                                .not_null()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Alias::new("count")).double().not_null())
                        .col(ColumnDef::new(Alias::new("expires_at")).big_integer())
                        .col(
                            ColumnDef::new(Alias::new("last_request"))
                                .big_integer()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await
        })
    }
    fn down<'a, 'b, 'future>(
        &'a self,
        manager: &'b SchemaManager<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'future>>
    where
        'a: 'future,
        'b: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            manager
                .drop_table(
                    Table::drop()
                        .if_exists()
                        .table(Alias::new("rate_limit"))
                        .to_owned(),
                )
                .await
        })
    }
}
