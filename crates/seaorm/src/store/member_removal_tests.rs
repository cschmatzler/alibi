//! Captured member deletion preserves phase ordering, rollback and adapter pages.
use super::{
    SeaOrmStore,
    bundled_schema::BundledSchema,
    entities::{member, team, team_member},
    migrator::run_migrations,
};
use better_auth_core::store::{MemberStore, OrganizationStore, TeamStore, UserStore};
use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateTeam, CreateUser};
use sea_orm::{ConnectionTrait, Database, DbBackend, EntityTrait, QueryOrder, Statement};

type TestResult = Result<(), Box<dyn std::error::Error>>;
async fn rows(
    db: &sea_orm::DatabaseConnection,
) -> Result<
    (
        Vec<member::Model>,
        Vec<team::Model>,
        Vec<team_member::Model>,
    ),
    sea_orm::DbErr,
> {
    Ok((
        member::Entity::find()
            .order_by_asc(member::Column::Id)
            .all(db)
            .await?,
        team::Entity::find()
            .order_by_asc(team::Column::Id)
            .all(db)
            .await?,
        team_member::Entity::find()
            .order_by_asc(team_member::Column::Id)
            .all(db)
            .await?,
    ))
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn captured_member_deletion_orders_writes_and_distinguishes_veto_ignore_and_absence()
-> TestResult {
    let db = Database::connect("sqlite::memory:").await?;
    run_migrations(&db).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("captured-member-deletion-public-store-secret"),
        db.clone(),
    );
    let owner = store
        .create_user(CreateUser::new().with_email("target@member-delete.fixture.test"))
        .await?;
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@member-delete.fixture.test"))
        .await?;
    let organization = store
        .create_organization(CreateOrganization::new("Own", "own"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other", "other"))
        .await?;
    let member = store
        .create_member(CreateMember {
            organization_id: organization.id.clone(),
            user_id: owner.id.clone(),
            role: "victim".into(),
        })
        .await?;
    let unrelated = store
        .create_member(CreateMember {
            organization_id: other.id.clone(),
            user_id: foreign.id.clone(),
            role: "foreign".into(),
        })
        .await?;
    let own_team = store
        .create_team(CreateTeam {
            name: "Own team".into(),
            organization_id: organization.id.clone(),
            updated_at: None,
        })
        .await?;
    let other_team = store
        .create_team(CreateTeam {
            name: "Other team".into(),
            organization_id: other.id.clone(),
            updated_at: None,
        })
        .await?;
    drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
    drop(
        store
            .add_team_member(&own_team.id, &foreign.id, None)
            .await?,
    );
    drop(
        store
            .add_team_member(&other_team.id, &owner.id, None)
            .await?,
    );
    let before = rows(&db).await?;
    let _ignored_execute_unprepared=db.execute_unprepared("CREATE TRIGGER member_veto BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(ABORT,'member deletion veto'); END").await?;
    let member_error = store
        .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("real member SQL veto must fail"))?;
    assert!(member_error.to_string().contains("member deletion veto"));
    assert_eq!(
        rows(&db).await?,
        before,
        "member veto must preserve all member/team rows"
    );
    let _ignored_execute_unprepared_2 = db.execute_unprepared("DROP TRIGGER member_veto").await?;
    let _ignored_execute_unprepared_3=db.execute_unprepared("CREATE TRIGGER team_veto BEFORE DELETE ON team_member WHEN OLD.user_id=(SELECT id FROM users WHERE email='target@member-delete.fixture.test') BEGIN SELECT RAISE(ABORT,'team deletion veto'); END").await?;
    let team_error = store
        .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("real later team SQL veto must fail"))?;
    assert!(team_error.to_string().contains("team deletion veto"));
    assert_eq!(
        rows(&db).await?,
        before,
        "later team veto must roll back the member deletion"
    );
    let _ignored_execute_unprepared_4 = db.execute_unprepared("DROP TRIGGER team_veto").await?;
    let _ignored_execute_unprepared_5=db.execute_unprepared("CREATE TRIGGER ignored_member BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(IGNORE); END").await?;
    store
        .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
        .await?;
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&member.id).await?)?,
        serde_json::to_value(Some(member.clone()))?,
        "ignored deletion is successful with member retained"
    );
    assert!(
        store
            .get_team_member(&own_team.id, &owner.id)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&own_team.id, &foreign.id)
            .await?
            .is_some()
    );
    assert_eq!(
        store
            .get_team(Some(&organization.id), &own_team.id)
            .await?
            .map(|team| team.member_count),
        Some(1)
    );
    let _ignored_execute_unprepared_6 =
        db.execute_unprepared("DROP TRIGGER ignored_member").await?;
    drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
    let _ignored_execute_unprepared_7=db.execute_unprepared("CREATE TRIGGER phase_guard BEFORE DELETE ON team_member WHEN EXISTS(SELECT 1 FROM member WHERE user_id=OLD.user_id AND role='victim') BEGIN SELECT RAISE(ABORT,'member must be deleted first'); END").await?;
    store
        .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
        .await?;
    assert!(store.get_member_by_id(&member.id).await?.is_none());
    assert!(
        store
            .get_team_member(&own_team.id, &owner.id)
            .await?
            .is_none()
    );
    let _ignored_execute_unprepared_8 = db.execute_unprepared("DROP TRIGGER phase_guard").await?;
    drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
    store
        .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
        .await?;
    assert!(
        store
            .get_team_member(&own_team.id, &owner.id)
            .await?
            .is_none(),
        "captured cleanup still runs after genuine row absence"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&unrelated.id).await?)?,
        serde_json::to_value(Some(unrelated))?
    );
    assert_eq!(store.get_user_by_id(&owner.id).await?, Some(owner.clone()));
    assert_eq!(store.get_user_by_id(&foreign.id).await?, Some(foreign));
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&organization.id).await?)?,
        serde_json::to_value(Some(organization.clone()))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
        serde_json::to_value(Some(other.clone()))?
    );
    let final_rows = rows(&db).await?;
    assert_eq!(
        final_rows.0,
        before
            .0
            .into_iter()
            .filter(|row| row.id != member.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        final_rows.2,
        before
            .2
            .into_iter()
            .filter(|row| !(row.team_id == own_team.id && row.user_id == owner.id))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        final_rows.1,
        before
            .1
            .into_iter()
            .map(|mut row| {
                if row.id == own_team.id {
                    row.member_count -= 1;
                }
                row
            })
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn contextual_deletion_uses_original_scope_and_unsorted_configured_pages() -> TestResult {
    let db = Database::connect("sqlite::memory:").await?;
    run_migrations(&db).await?;
    let mut config = AuthConfig::new("member-deletion-pages-public-store-secret");
    config.advanced.database.default_find_many_limit = 1;
    let store = SeaOrmStore::<BundledSchema>::new(config, db.clone());
    let user = store
        .create_user(CreateUser::new().with_email("page-target@member-delete.fixture.test"))
        .await?;
    let other_user = store
        .create_user(CreateUser::new().with_email("page-other@member-delete.fixture.test"))
        .await?;
    let org = store
        .create_organization(CreateOrganization::new("Page", "page"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other page", "other-page"))
        .await?;
    let first = store
        .create_member(CreateMember {
            organization_id: org.id.clone(),
            user_id: user.id.clone(),
            role: "owner".into(),
        })
        .await?;
    let second = store
        .create_member(CreateMember {
            organization_id: org.id.clone(),
            user_id: other_user.id.clone(),
            role: "owner".into(),
        })
        .await?;
    let _ignored_into = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE member SET created_at=? WHERE id=?",
            ["2030-01-01T00:00:00Z".into(), first.id.clone().into()],
        ))
        .await?;
    let _ignored_into_2 = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE member SET created_at=? WHERE id=?",
            ["2000-01-01T00:00:00Z".into(), second.id.clone().into()],
        ))
        .await?;
    assert_eq!(
        store
            .list_organization_members_page(&org.id, 1)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![first.id.clone()],
        "adapter page follows physical insertion rather than timestamp ordering"
    );
    assert_eq!(
        store
            .list_organization_members(&org.id)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![second.id.clone(), first.id.clone()],
        "existing sorted API stays unchanged"
    );
    let mut teams = Vec::new();
    for name in ["First physical", "Second physical"] {
        let team = store
            .create_team(CreateTeam {
                name: name.into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await?;
        drop(store.add_team_member(&team.id, &user.id, None).await?);
        teams.push(team);
    }
    let [first_team, second_team] = teams.as_slice() else {
        return Err(
            std::io::Error::other("two actual team creations must return their rows").into(),
        );
    };
    let before = rows(&db).await?;
    let _ignored_into_3 = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE member SET organization_id=?, user_id=? WHERE id=?",
            [
                other.id.clone().into(),
                other_user.id.clone().into(),
                first.id.clone().into(),
            ],
        ))
        .await?;
    store
        .delete_member_with_context(&first.id, &org.id, &user.id, false)
        .await?;
    let after_disabled = rows(&db).await?;
    assert_eq!(after_disabled.1, before.1);
    assert_eq!(
        after_disabled.2, before.2,
        "disabled teams retain their real legacy memberships"
    );
    store
        .delete_member_with_context(&first.id, &org.id, &user.id, true)
        .await?;
    assert!(
        store
            .get_team_member(&first_team.id, &user.id)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second_team.id, &user.id)
            .await?
            .is_some(),
        "teams outside the actual configured page remain"
    );
    let final_rows = rows(&db).await?;
    assert_eq!(
        final_rows.1,
        before
            .1
            .into_iter()
            .map(|mut row| {
                if row.id == first_team.id {
                    row.member_count -= 1;
                }
                row
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        final_rows.2,
        before
            .2
            .into_iter()
            .filter(|row| row.team_id != first_team.id)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .get_member_by_id(&second.id)
            .await?
            .map(|row| row.role),
        Some("owner".into())
    );
    assert_eq!(store.get_user_by_id(&user.id).await?, Some(user));
    assert_eq!(
        store.get_user_by_id(&other_user.id).await?,
        Some(other_user)
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&org.id).await?)?,
        serde_json::to_value(Some(org))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
        serde_json::to_value(Some(other))?
    );
    Ok(())
}
