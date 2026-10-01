//! Pinned user deletion retains plugin-owned two-factor records.
#[cfg(test)]
mod tests;

use sea_orm_migration::prelude::*;

pub(super) struct TwoFactorUserReference;

impl MigrationName for TwoFactorUserReference {
    fn name(&self) -> &'static str {
        "m20260930_000007_two_factor_user_reference"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for TwoFactorUserReference {
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
            &[super::user_reference::AuthReference::TwoFactor],
        )
        .await
    }
}
