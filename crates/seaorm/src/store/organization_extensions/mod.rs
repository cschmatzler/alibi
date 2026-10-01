//! Install organization team and dynamic-role persistence for fresh and existing schemas.
#[cfg(test)]
mod tests;

use super::entities::{invitation, organization_role, team, team_member};

use sea_orm::{EntityName, Schema};

use sea_orm_migration::prelude::*;

pub(super) struct OrganizationExtensions;

impl MigrationName for OrganizationExtensions {
    fn name(&self) -> &'static str {
        "m20260930_000003_organization_extensions"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for OrganizationExtensions {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_connection().get_database_backend());
        let mut teams = schema.create_table_from_entity(team::Entity);
        let _ignored_if_not_exists = teams.if_not_exists();
        manager.create_table(teams).await?;
        let mut members = schema.create_table_from_entity(team_member::Entity);
        let _ignored_on_delete = members.if_not_exists().foreign_key(
            ForeignKey::create()
                .name("fk_team_member_team")
                .from(team_member::Entity, team_member::Column::TeamId)
                .to(team::Entity, team::Column::Id)
                .on_delete(ForeignKeyAction::Cascade),
        );
        manager.create_table(members).await?;
        let mut roles = schema.create_table_from_entity(organization_role::Entity);
        let _ignored_if_not_exists_2 = roles.if_not_exists();
        manager.create_table(roles).await?;
        if !manager
            .has_column(invitation::Entity.table_name(), "team_id")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(invitation::Entity)
                        .add_column(ColumnDef::new(invitation::Column::TeamId).string())
                        .to_owned(),
                )
                .await?;
        }
        for (name, table, column) in [
            ("idx_team_organization", "team", "organization_id"),
            ("idx_team_member_team", "team_member", "team_id"),
            ("idx_team_member_user", "team_member", "user_id"),
            (
                "idx_organization_role_org",
                "organization_role",
                "organization_id",
            ),
            ("idx_organization_role_role", "organization_role", "role"),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(Alias::new(table))
                        .col(Alias::new(column))
                        .if_not_exists()
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
