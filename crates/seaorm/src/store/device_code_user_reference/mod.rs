//! Device authorization records use an unconstrained optional user reference.

#[cfg(test)]
mod tests;

#[cfg(test)]
use sea_orm::{DatabaseBackend, Statement};
use sea_orm_migration::prelude::*;

pub(super) struct DeviceCodeUserReference;

impl MigrationName for DeviceCodeUserReference {
    fn name(&self) -> &'static str {
        "m20260930_000006_device_code_user_reference"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for DeviceCodeUserReference {
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        super::user_reference::remove_auth_references(
            manager,
            &[super::user_reference::AuthReference::DeviceCode],
        )
        .await
    }
}
