#[cfg(test)]
mod tests;

use super::entities::api_key;
use sea_orm::{ConnectionTrait, DatabaseBackend};
use sea_orm_migration::prelude::*;

pub(super) struct ApiKeyNumbers;

impl MigrationName for ApiKeyNumbers {
    fn name(&self) -> &'static str {
        "m20260930_000001_api_key_numbers"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for ApiKeyNumbers {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return rebuild_sqlite(manager).await;
        }

        for column in [
            api_key::Column::RefillInterval,
            api_key::Column::RefillAmount,
            api_key::Column::RateLimitTimeWindow,
            api_key::Column::RateLimitMax,
            api_key::Column::RequestCount,
            api_key::Column::Remaining,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(api_key::Entity)
                        .modify_column(ColumnDef::new(column).double())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

async fn rebuild_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let transaction = manager.begin().await?;
    let database = transaction.get_connection();
    // REAL affinity converts existing integer values before SQLx decodes them as f64.
    for statement in [
        "DROP INDEX IF EXISTS idx_api_keys_reference_id",
        "DROP INDEX IF EXISTS idx_api_keys_config_id",
        "ALTER TABLE api_keys RENAME TO api_keys_integer",
    ] {
        let _ignored_execute_unprepared = database.execute_unprepared(statement).await?;
    }
    super::migrator::create_api_keys(&transaction).await?;
    let _ignored_execute_unprepared_2 = database
        .execute_unprepared(
            "INSERT INTO api_keys (id, name, start, prefix, key, reference_id, config_id,
            refill_interval, refill_amount, last_refill_at, enabled, rate_limit_enabled,
            rate_limit_time_window, rate_limit_max, request_count, remaining, last_request,
            expires_at, created_at, updated_at, permissions, metadata)
         SELECT id, name, start, prefix, key, reference_id, config_id,
            refill_interval, refill_amount, last_refill_at, enabled, rate_limit_enabled,
            rate_limit_time_window, rate_limit_max, request_count, remaining, last_request,
            expires_at, created_at, updated_at, permissions, metadata FROM api_keys_integer",
        )
        .await?;
    let _ignored_execute_unprepared_3 = database
        .execute_unprepared("DROP TABLE api_keys_integer")
        .await?;
    transaction.commit().await
}
