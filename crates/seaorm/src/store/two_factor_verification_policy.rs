use super::entities::two_factor;
use sea_orm::{DatabaseBackend, EntityName};
use sea_orm_migration::prelude::*;

pub(super) struct TwoFactorVerificationPolicy;

impl MigrationName for TwoFactorVerificationPolicy {
    fn name(&self) -> &'static str {
        "m20260930_000012_two_factor_verification_policy"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for TwoFactorVerificationPolicy {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for mut column in definitions(manager.get_database_backend()) {
            let name = column.get_column_name();
            if !manager
                .has_column(two_factor::Entity.table_name(), &name)
                .await?
            {
                manager
                    .alter_table(
                        Table::alter()
                            .table(two_factor::Entity)
                            .add_column(&mut column)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

pub(super) fn definitions(backend: DatabaseBackend) -> Vec<ColumnDef> {
    let mut verified = ColumnDef::new(two_factor::Column::Verified);
    let _ignored_default = verified.boolean().default(true);
    let mut count = ColumnDef::new(two_factor::Column::FailedVerificationCount);
    if backend == DatabaseBackend::Sqlite {
        let _ignored_integer = count.integer();
    } else {
        let _ignored_double = count.double();
    }
    let _ignored_default_2 = count.default(0);
    let mut locked = ColumnDef::new(two_factor::Column::LockedUntil);
    let _ignored_timestamp_with_time_zone = locked.timestamp_with_time_zone();
    vec![verified, count, locked]
}
