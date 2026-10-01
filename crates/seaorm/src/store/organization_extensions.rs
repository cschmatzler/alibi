//! Install organization team and dynamic-role persistence for fresh and existing schemas.
use super::entities::{invitation, organization_role, team, team_member};
use sea_orm::{EntityName, Schema};
use sea_orm_migration::prelude::*;

pub(super) struct OrganizationExtensions;
impl MigrationName for OrganizationExtensions {
    fn name(&self) -> &str {
        "m20260930_000003_organization_extensions"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
    use better_auth_core::store::{InvitationStore, OrganizationStore, UserStore};
    use better_auth_core::{AuthConfig, CreateInvitation, CreateOrganization, CreateUser};
    use chrono::{Duration, Utc};
    use sea_orm::{ConnectionTrait, Database, Statement};

    #[tokio::test]
    async fn upgrades_populated_invitation_schema_without_discarding_existing_rows()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        AuthMigrator::up(&database, Some(4)).await?;
        let manager = SchemaManager::new(&database);
        assert!(!manager.has_column("invitation", "team_id").await?);
        assert!(!manager.has_table("team").await?);
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("org-extension-upgrade-local-secret-at-least-32"),
            database.clone(),
        );
        let organization = store
            .create_organization(CreateOrganization::new("Existing", "existing-org"))
            .await?;
        let inviter = store
            .create_user(CreateUser::new().with_email("migration-inviter@example.com"))
            .await?;
        let now = Utc::now();
        let expiry = now + Duration::hours(1);
        let _ = database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),
            "INSERT INTO invitation (id, organization_id, email, role, status, inviter_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec!["existing-invitation".into(), organization.id.clone().into(), "invited@example.com".into(), "member".into(), "pending".into(), inviter.id.clone().into(), expiry.into(), now.into()])).await?;
        AuthMigrator::up(&database, None).await?;
        AuthMigrator::up(&database, None).await?;
        let existing = store
            .get_invitation_by_id("existing-invitation")
            .await?
            .ok_or_else(|| std::io::Error::other("Upgrade discarded invitation"))?;
        assert_eq!(existing.email, "invited@example.com");
        assert_eq!(existing.organization_id, organization.id);
        assert!(existing.team_id.is_none());
        let created = store
            .create_invitation(CreateInvitation::new(
                &organization.id,
                "new@example.com",
                "member",
                &inviter.id,
                expiry,
            ))
            .await?;
        assert!(created.team_id.is_none());
        for table in ["team", "team_member", "organization_role"] {
            assert!(manager.has_table(table).await?);
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl MigrationTrait for OrganizationExtensions {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_connection().get_database_backend());
        let mut teams = schema.create_table_from_entity(team::Entity);
        let _ = teams.if_not_exists();
        manager.create_table(teams).await?;
        let mut members = schema.create_table_from_entity(team_member::Entity);
        let _ = members.if_not_exists().foreign_key(
            ForeignKey::create()
                .name("fk_team_member_team")
                .from(team_member::Entity, team_member::Column::TeamId)
                .to(team::Entity, team::Column::Id)
                .on_delete(ForeignKeyAction::Cascade),
        );
        manager.create_table(members).await?;
        let mut roles = schema.create_table_from_entity(organization_role::Entity);
        let _ = roles.if_not_exists();
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
