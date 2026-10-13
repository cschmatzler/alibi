//! Atomic rolling rate limits persisted independently of an application's auth schema.

use alibi_core::middleware::rate_limit::bucket::{self, Step};
use alibi_core::store::SchemaMigrator;
use alibi_core::{AuthResult, EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use async_trait::async_trait;
use sea_orm::ConnectionTrait;
use sea_orm::sea_query::{Alias, DynIden, IntoIden};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::prelude::{
    DbErr, MigrationName, MigrationTrait, MigratorTrait, SchemaManager,
};

pub mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "rateLimit")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub key: String,
        pub count: crate::Number,
        #[sea_orm(column_name = "lastRequest")]
        pub last_request: i64,
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
}

impl SeaOrmRateLimitStorage {
    #[must_use]
    pub fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

/// Installs the opt-in rate-limit table using its own migration ledger.
/// Migration errors are returned without serving requests on missing storage.
#[async_trait]
impl SchemaMigrator for SeaOrmRateLimitStorage {
    async fn migrate(&self) -> AuthResult<()> {
        RateLimitMigrator::up(&self.database, None)
            .await
            .map_err(crate::store::map_db_err)
    }
}

#[async_trait]
impl RateLimitStorage for SeaOrmRateLimitStorage {
    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        loop {
            let observed = entity::Entity::find()
                .filter(entity::Column::Key.eq(key))
                .one(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
            let now = chrono::Utc::now().timestamp_millis();
            let Some(observed) = observed else {
                let inserted = entity::Entity::insert(entity::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    key: Set(key.to_owned()),
                    count: Set(crate::Number(1.0)),
                    last_request: Set(now),
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
                    return Ok(RateLimitDecision::Allowed);
                }
                continue;
            };
            let next_count = match bucket::step(observed.count.0, observed.last_request, now, rule)
            {
                Step::Blocked { retry_after } => {
                    return Ok(RateLimitDecision::Blocked { retry_after });
                }
                Step::Allowed { count, .. } => count,
            };
            let next_count = crate::Number(next_count);
            let updated = entity::Entity::update_many()
                .col_expr(entity::Column::Count, Expr::value(next_count))
                .col_expr(entity::Column::LastRequest, Expr::value(now))
                .filter(entity::Column::Key.eq(key))
                .filter(entity::Column::LastRequest.eq(observed.last_request))
                .filter(entity::Column::Count.eq(observed.count))
                .exec(&self.database)
                .await
                .map_err(crate::store::map_db_err)?;
            if updated.rows_affected == 1 {
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
        "m20261013_000003_typescript_rate_limit_schema"
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
            let sql = match manager.get_database_backend() {
                sea_orm::DbBackend::Postgres => alibi_schema_registry::POSTGRES_RATE_LIMIT_SCHEMA,
                sea_orm::DbBackend::Sqlite => alibi_schema_registry::SQLITE_RATE_LIMIT_SCHEMA,
                _ => {
                    return Err(DbErr::Custom(
                        "Rate-limit migrations support SQLite and PostgreSQL".into(),
                    ));
                }
            };
            for statement in sql
                .split(';')
                .filter(|statement| !statement.trim().is_empty())
            {
                _ = manager
                    .get_connection()
                    .execute_unprepared(statement)
                    .await?;
            }
            Ok(())
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
                    sea_orm::sea_query::Table::drop()
                        .if_exists()
                        .table(Alias::new("rateLimit"))
                        .to_owned(),
                )
                .await
        })
    }
}
