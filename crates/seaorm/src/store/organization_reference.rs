//! Match the pinned default SQLite adapter's retained organization extension rows.
use sea_orm_migration::prelude::*;
pub(super) struct DetachOrganizationReferences;
impl MigrationName for DetachOrganizationReferences {
    fn name(&self) -> &'static str {
        "m20261001_000014_detach_organization_references"
    }
}
#[async_trait::async_trait]
impl MigrationTrait for DetachOrganizationReferences {
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
            &[
                super::user_reference::AuthReference::TeamOrganization,
                super::user_reference::AuthReference::OrganizationRoleOrganization,
            ],
        )
        .await
    }
}
