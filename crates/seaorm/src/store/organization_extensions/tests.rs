use super::*;
use crate::store::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
use better_auth_core::store::{InvitationStore, OrganizationStore, UserStore};
use better_auth_core::{AuthConfig, CreateInvitation, CreateOrganization, CreateUser};
use chrono::{Duration, Utc};
use sea_orm::{ConnectionTrait, Database, Statement};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
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
    let _ignored_into = database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),
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
