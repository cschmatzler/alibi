//! SIWE wallets support both bundled and application-owned core user entities.
//! Their owner check and cascade are performed by the store in a transaction,
//! rather than hardcoding the bundled `users` table into a foreign key.

use super::entities::wallet_address;
use sea_orm_migration::prelude::*;

pub(super) struct SiweWallets;

impl MigrationName for SiweWallets {
    fn name(&self) -> &str {
        "m20260930_000006_siwe_wallets"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for SiweWallets {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(wallet_address::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(wallet_address::Column::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::UserId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::Address)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::ChainId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::IsPrimary)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(wallet_address::Column::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_wallet_address_user")
                    .table(wallet_address::Entity)
                    .col(wallet_address::Column::UserId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
