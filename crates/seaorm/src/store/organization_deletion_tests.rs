//! Public deletion storage semantics and its independent transaction boundary.
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::{
    ApiKeyStore, InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, TeamStore,
    UserStore,
};
use better_auth_core::types::CreateOrganizationRole;
use better_auth_core::{
    AuthConfig, CreateApiKey, CreateInvitation, CreateMember, CreateOrganization, CreateTeam,
    CreateUser,
};
use chrono::{Duration, Utc};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
use std::collections::BTreeMap;

async fn physical(
    database: &DatabaseConnection,
) -> Result<BTreeMap<String, String>, sea_orm::DbErr> {
    let mut values = BTreeMap::new();
    for table in [
        "users",
        "organization",
        "member",
        "invitation",
        "team",
        "team_member",
        "organization_role",
        "api_keys",
    ] {
        let columns = database
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA table_xinfo(\"{table}\")"),
            ))
            .await?;
        let fields = columns
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        let object = fields
            .iter()
            .map(|name| {
                format!(
                    "'{}',\"{}\"",
                    name.replace('\'', "''"),
                    name.replace('\"', "\"\"")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let query = format!(
            "SELECT json_group_array(json_object({object})) AS snapshot FROM (SELECT * FROM \"{table}\" ORDER BY rowid)"
        );
        let row = database
            .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
            .await?
            .ok_or_else(|| sea_orm::DbErr::Custom("snapshot missing".into()))?;
        let _ = values.insert(table.to_owned(), row.try_get("", "snapshot")?);
    }
    Ok(values)
}
#[tokio::test]
async fn public_organization_delete_retains_extensions_and_rolls_back_all_scoped_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("organization-delete-store-local-proof-secret"),
        database.clone(),
    );
    let mut records = Vec::new();
    for slug in ["target", "unrelated"] {
        let user = store
            .create_user(CreateUser::new().with_email(format!("{slug}@deletion.fixture.test")))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new(slug, slug))
            .await?;
        let member = store
            .create_member(CreateMember {
                organization_id: org.id.clone(),
                user_id: user.id.clone(),
                role: "owner".into(),
            })
            .await?;
        let invitation = store
            .create_invitation(CreateInvitation::new(
                &org.id,
                format!("invited-{slug}@deletion.fixture.test"),
                "member",
                &user.id,
                Utc::now() + Duration::days(1),
            ))
            .await?;
        let team = store
            .create_team(CreateTeam {
                name: slug.into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await?;
        let _ = store.add_team_member(&team.id, &user.id, None).await?;
        let _ = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.id.clone(),
                role: "retained".into(),
                permission: Default::default(),
            })
            .await?;
        let _ = store
            .create_api_key(CreateApiKey {
                reference_id: org.id.clone(),
                config_id: "organization".into(),
                name: Some(slug.into()),
                prefix: None,
                key_hash: format!("{slug}-local-key-hash"),
                start: None,
                expires_at: None,
                remaining: None,
                rate_limit_enabled: false,
                rate_limit_time_window: None,
                rate_limit_max: None,
                refill_interval: None,
                refill_amount: None,
                permissions: None,
                metadata: None,
                enabled: true,
            })
            .await?;
        records.push((org, member, invitation));
    }
    let before = physical(&database).await?;
    let _ = database.execute_unprepared("CREATE TRIGGER app_refuse_organization_delete BEFORE DELETE ON organization WHEN OLD.slug='target' BEGIN SELECT RAISE(ABORT,'application deletion denied'); END").await?;
    assert!(store.delete_organization(&records[0].0.id).await.is_err());
    assert_eq!(
        physical(&database).await?,
        before,
        "a failed final organization write must roll back members/invitations and retain every key/extension row"
    );
    let _ = database
        .execute_unprepared("DROP TRIGGER app_refuse_organization_delete")
        .await?;
    store.delete_organization(&records[0].0.id).await?;
    assert!(
        store
            .get_organization_by_id(&records[0].0.id)
            .await?
            .is_none()
    );
    assert!(store.get_member_by_id(&records[0].1.id).await?.is_none());
    assert!(
        store
            .get_invitation_by_id(&records[0].2.id)
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_organization_by_id(&records[1].0.id)
            .await?
            .as_ref()
            .map(|org| &org.slug),
        Some(&records[1].0.slug)
    );
    assert!(store.get_member_by_id(&records[1].1.id).await?.is_some());
    assert!(
        store
            .get_invitation_by_id(&records[1].2.id)
            .await?
            .is_some()
    );
    let after = physical(&database).await?;
    for table in [
        "users",
        "team",
        "team_member",
        "organization_role",
        "api_keys",
    ] {
        assert_eq!(
            after[table], before[table],
            "retained {table} rows must preserve all physical fields"
        );
    }
    store.delete_organization("missing-organization").await?;
    assert_eq!(
        physical(&database).await?,
        after,
        "missing organization deletion is a scoped no-op"
    );
    Ok(())
}
