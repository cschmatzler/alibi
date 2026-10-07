//! Atomic rolling rate limits persisted independently of an application's auth schema.

use alibi_core::middleware::rate_limit::bucket::{self, LongestWindow, Step};
use alibi_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use async_trait::async_trait;
use sea_orm::sea_query::{Alias, ColumnDef, DynIden, IntoIden, Table};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::prelude::{
    DbErr, MigrationName, MigrationTrait, MigratorTrait, SchemaManager,
};
use std::sync::Arc;

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
    longest_window: Arc<LongestWindow>,
}

impl SeaOrmRateLimitStorage {
    #[must_use]
    pub fn new(database: DatabaseConnection) -> Self {
        Self {
            database,
            longest_window: Arc::new(LongestWindow::new()),
        }
    }
    async fn prune(&self, now: i64) {
        let Some(cutoff) = self.longest_window.prune_cutoff(now) else {
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

/// Installs the opt-in rate-limit table using its own migration ledger.
/// Migration errors are returned without serving requests on missing storage.
#[async_trait]
impl alibi_core::store::SchemaMigrator for SeaOrmRateLimitStorage {
    async fn migrate(&self) -> AuthResult<()> {
        RateLimitMigrator::up(&self.database, None)
            .await
            .map_err(crate::store::map_db_err)
    }
}

#[async_trait]
impl RateLimitStorage for SeaOrmRateLimitStorage {
    fn observe_window(&self, window: f64) {
        self.longest_window.observe(window);
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
                    expires_at: Set(bucket::expires_at(now, rule.window_seconds)),
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
            let (next_count, reset) =
                match bucket::step(observed.count, observed.last_request, now, rule) {
                    Step::Blocked { retry_after } => {
                        return Ok(RateLimitDecision::Blocked { retry_after });
                    }
                    Step::Allowed { count, reset } => (count, reset),
                };
            let updated = entity::Entity::update_many()
                .col_expr(entity::Column::Count, Expr::value(next_count))
                .col_expr(entity::Column::LastRequest, Expr::value(now))
                .col_expr(
                    entity::Column::ExpiresAt,
                    Expr::value(bucket::expires_at(now, rule.window_seconds)),
                )
                .filter(entity::Column::Key.eq(key))
                .filter(entity::Column::LastRequest.eq(observed.last_request))
                .filter(entity::Column::Count.eq(observed.count))
                .exec(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
            if updated.rows_affected == 1 {
                if reset {
                    self.prune(now).await;
                }
                return Ok(RateLimitDecision::Allowed);
            }
        }
    }
}

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
