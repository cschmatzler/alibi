//! Public optional member updates distinguish genuine absence and SQL failures.
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::{MemberStore, OrganizationStore, UserStore};
use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateUser};
use sea_orm::{ConnectionTrait, Database};

#[tokio::test]
async fn optional_member_role_updates_distinguish_missing_rows_from_write_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("optional-member-role-public-store-secret"),
        database.clone(),
    );
    let organization = store
        .create_organization(CreateOrganization::new("Roles", "roles"))
        .await?;
    let mut members = Vec::new();
    for name in ["target", "foreign"] {
        let user = store
            .create_user(CreateUser::new().with_email(format!("{name}@role.fixture.test")))
            .await?;
        members.push(
            store
                .create_member(CreateMember {
                    organization_id: organization.id.clone(),
                    user_id: user.id,
                    role: name.into(),
                })
                .await?,
        );
    }
    let target = &members[0];
    let foreign = &members[1];
    let updated = store
        .update_member_role_if_present(&target.id, "admin")
        .await?
        .ok_or_else(|| {
            std::io::Error::other("existing member update must return its actual row")
        })?;
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.id, target.id);
    assert_eq!(updated.user_id, target.user_id);
    assert_eq!(updated.organization_id, target.organization_id);
    assert_eq!(updated.created_at, target.created_at);
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    let _=database.execute_unprepared("CREATE TRIGGER veto_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(ABORT,'optional member storage veto'); END").await?;
    assert!(
        store
            .update_member_role_if_present(&target.id, "must-not-persist")
            .await
            .is_err(),
        "storage veto is not missing-row success"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    let _ = database
        .execute_unprepared("DROP TRIGGER veto_optional_member")
        .await?;
    let _=database.execute_unprepared("CREATE TRIGGER ignore_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(IGNORE); END").await?;
    assert!(
        store
            .update_member_role_if_present(&target.id, "ignored")
            .await?
            .is_none(),
        "actual zero-row update is absence"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    store.delete_member(&target.id).await?;
    assert!(
        store
            .update_member_role_if_present(&target.id, "deleted")
            .await?
            .is_none()
    );
    assert!(
        store
            .update_member_role(&target.id, "deleted")
            .await
            .is_err(),
        "original operation preserves missing-row error"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&foreign.id).await?)?,
        serde_json::to_value(Some(foreign))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&organization.id).await?)?,
        serde_json::to_value(Some(&organization))?
    );
    Ok(())
}
