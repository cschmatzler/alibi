//! Member identities, physical pages, captured deletion and optional updates.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::AuthConfig;
use alibi::store::SchemaMigrator;
use alibi::store::{
    ListOrganizationMembersParams, MemberPageQuery, MemberStore, OrganizationStore, TeamStore,
    UserStore,
};
use alibi::{AuthError, AuthUser, CreateMember, CreateOrganization, CreateTeam, CreateUser};
use std::sync::Arc;

backend_tests!(
    organization_list_pages_physical_members_before_joining_and_keeps_full_peer_rows,
    independent_connections_admit_distinct_member_ids_for_the_same_pair,
    captured_member_deletion_orders_writes_and_distinguishes_veto_ignore_and_absence,
    contextual_deletion_uses_original_scope_and_unsorted_configured_pages,
    optional_member_role_updates_distinguish_missing_rows_from_write_errors,
    query_organization_members_applies_filter_sort_and_pagination,
    public_numeric_pages_bind_raw_limits_and_keep_insertion_order_filtered_count_and_full_state,
);
postgres_tests!(
    organization_list_pages_physical_members_before_joining_and_keeps_full_peer_rows,
    independent_connections_admit_distinct_member_ids_for_the_same_pair,
    query_organization_members_applies_filter_sort_and_pagination,
    public_numeric_pages_bind_raw_limits_and_keep_insertion_order_filtered_count_and_full_state,
);

const TEAM_TABLES: [&str; 3] = ["member", "team", "team_member"];

fn rows(snapshot: &str) -> TestResult<Vec<serde_json::Value>> {
    Ok(serde_json::from_str(snapshot)?)
}

async fn organization_list_pages_physical_members_before_joining_and_keeps_full_peer_rows<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>("physical-member-page-secret").await?;
    let user = store
        .create_user(CreateUser::new().with_email("target@member-page.test"))
        .await?;
    let user = user.id().into_owned();
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@member-page.test"))
        .await?;
    let old = store
        .create_organization(CreateOrganization::new("Old", "older-member-page"))
        .await?;
    let new = store
        .create_organization(CreateOrganization::new("New", "newer-member-page"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other", "foreign-member-page"))
        .await?;
    for (id, date) in [
        (&old.id, "2020-01-01T00:00:00Z"),
        (&new.id, "2021-01-01T00:00:00Z"),
    ] {
        db.set_timestamp("organization", "created_at", ("id", id), date.parse()?)
            .await?;
    }
    let old = store
        .get_organization_by_id(&old.id)
        .await?
        .ok_or("older organization missing")?;
    let new = store
        .get_organization_by_id(&new.id)
        .await?
        .ok_or("newer organization missing")?;
    let first = store
        .create_member(CreateMember::new(&new.id, &user, "member"))
        .await?;
    let second = store
        .create_member(CreateMember::new(&old.id, &user, "owner"))
        .await?;
    let duplicate = store
        .create_member(CreateMember::new(&new.id, &user, "admin"))
        .await?;
    let peer = store
        .create_member(CreateMember::new(&other.id, foreign.id(), "owner"))
        .await?;
    let foreign_before = serde_json::to_value((&peer, &other, &foreign))?;
    for (limit, expected) in [
        (100, vec![new.clone(), old.clone(), new.clone()]),
        (2, vec![new.clone(), old.clone()]),
        (1, vec![new.clone()]),
        (0, vec![]),
    ] {
        let mut configured = AuthConfig::new("physical-member-page-secret");
        configured.advanced.database.default_find_many_limit = limit;
        let paged = B::store(Arc::new(configured), &connection);
        assert_eq!(
            serde_json::to_value(paged.list_user_organizations(&user).await?)?,
            serde_json::to_value(expected)?,
            "membership page {limit} must retain multiplicity, full output and admission order"
        );
    }
    assert_eq!(
        serde_json::to_value(store.get_member(&new.id, &user).await?)?,
        serde_json::to_value(Some(first.clone()))?,
        "first physical member stays authoritative; duplicate role is not unioned"
    );
    let team = store
        .create_team(CreateTeam {
            name: "Owned team".into(),
            organization_id: new.id.clone(),
            updated_at: None,
        })
        .await?;
    let peer_team = store
        .create_team(CreateTeam {
            name: "Foreign team".into(),
            organization_id: other.id.clone(),
            updated_at: None,
        })
        .await?;
    drop(store.add_team_member(&team.id, &user, None).await?);
    drop(
        store
            .add_team_member(&team.id, foreign.id().as_ref(), None)
            .await?,
    );
    drop(store.add_team_member(&peer_team.id, &user, None).await?);
    let foreign_team_before = store.get_team(Some(&other.id), &peer_team.id).await?;
    let foreign_link_before = store.get_team_member(&peer_team.id, &user).await?;
    store
        .delete_member_with_context(&duplicate.id, &new.id, &user, true)
        .await?;
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&first.id).await?)?,
        serde_json::to_value(Some(first))?
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&second.id).await?)?,
        serde_json::to_value(Some(second))?
    );
    assert!(store.get_member_by_id(&duplicate.id).await?.is_none());
    assert!(store.get_team_member(&team.id, &user).await?.is_none());
    assert!(
        store
            .get_team_member(&team.id, foreign.id().as_ref())
            .await?
            .is_some()
    );
    assert_eq!(
        store
            .get_team(Some(&new.id), &team.id)
            .await?
            .map(|team| team.member_count),
        Some(1)
    );
    assert_eq!(
        serde_json::to_value(store.get_team(Some(&other.id), &peer_team.id).await?)?,
        serde_json::to_value(foreign_team_before)?
    );
    assert_eq!(
        serde_json::to_value(store.get_team_member(&peer_team.id, &user).await?)?,
        serde_json::to_value(foreign_link_before)?
    );
    assert_eq!(
        serde_json::to_value((
            store
                .get_member_by_id(&peer.id)
                .await?
                .ok_or("peer missing")?,
            store
                .get_organization_by_id(&other.id)
                .await?
                .ok_or("peer organization missing")?,
            store
                .get_user_by_id(foreign.id().as_ref())
                .await?
                .ok_or("foreign user missing")?
        ))?,
        foreign_before
    );
    B::close(connection).await
}

async fn independent_connections_admit_distinct_member_ids_for_the_same_pair<B: Backend>(
    db: Db,
) -> TestResult {
    let (first_db, first) = db
        .migrated::<B>("independent-member-admission-secret")
        .await?;
    let second_db = B::connect(&db.url, None).await?;
    let second = B::store(
        Arc::new(AuthConfig::new("independent-member-admission-secret")),
        &second_db,
    );
    let user = first
        .create_user(CreateUser::new().with_email("concurrent@member-pair.test"))
        .await?;
    let user = user.id().into_owned();
    let foreign = first
        .create_user(CreateUser::new().with_email("foreign@member-race.test"))
        .await?;
    let org = first
        .create_organization(CreateOrganization::new("Concurrent", "concurrent-pair"))
        .await?;
    let other = first
        .create_organization(CreateOrganization::new("Foreign", "foreign-race-pair"))
        .await?;
    let peer = first
        .create_member(CreateMember::new(&other.id, foreign.id(), "owner"))
        .await?;
    let results = tokio::join!(
        first.create_member(CreateMember::new(&org.id, &user, "member")),
        second.create_member(CreateMember::new(&org.id, &user, "admin")),
    );
    let a = results.0?;
    let b = results.1?;
    assert_ne!(a.id, b.id);
    assert_eq!(first.count_organization_members(&org.id).await?, 2);
    let rows = first.list_organization_members(&org.id).await?;
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.user_id, user);
        assert_eq!(row.organization_id, org.id);
    }
    assert_eq!(
        serde_json::to_value(second.get_member_by_id(&a.id).await?)?,
        serde_json::to_value(Some(a))?
    );
    assert_eq!(
        serde_json::to_value(first.get_member_by_id(&b.id).await?)?,
        serde_json::to_value(Some(b))?
    );
    assert_eq!(
        serde_json::to_value(second.get_member_by_id(&peer.id).await?)?,
        serde_json::to_value(Some(peer))?
    );
    B::close(first_db).await?;
    B::close(second_db).await
}

async fn captured_member_deletion_orders_writes_and_distinguishes_veto_ignore_and_absence<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("captured-member-deletion-public-store-secret")
        .await?;
    let owner = store
        .create_user(CreateUser::new().with_email("target@member-delete.fixture.test"))
        .await?;
    let owner_id = owner.id().into_owned();
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@member-delete.fixture.test"))
        .await?;
    let foreign_id = foreign.id().into_owned();
    let organization = store
        .create_organization(CreateOrganization::new("Own", "own"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other", "other"))
        .await?;
    let member = store
        .create_member(CreateMember {
            organization_id: organization.id.clone(),
            user_id: owner_id.clone(),
            role: "victim".into(),
        })
        .await?;
    let unrelated = store
        .create_member(CreateMember {
            organization_id: other.id.clone(),
            user_id: foreign_id.clone(),
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
    drop(store.add_team_member(&own_team.id, &owner_id, None).await?);
    drop(
        store
            .add_team_member(&own_team.id, &foreign_id, None)
            .await?,
    );
    drop(
        store
            .add_team_member(&other_team.id, &owner_id, None)
            .await?,
    );
    let before = db.tables(&TEAM_TABLES).await?;
    _ = db.execute("CREATE TRIGGER member_veto BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(ABORT,'member deletion veto'); END", &[]).await?;
    let member_error = store
        .delete_member_with_context(&member.id, &organization.id, &owner_id, true)
        .await
        .err()
        .ok_or("real member SQL veto must fail")?;
    assert!(member_error.to_string().contains("member deletion veto"));
    assert_eq!(
        db.tables(&TEAM_TABLES).await?,
        before,
        "member veto must preserve all member/team rows"
    );
    _ = db.execute("DROP TRIGGER member_veto", &[]).await?;
    _ = db.execute("CREATE TRIGGER team_veto BEFORE DELETE ON team_member WHEN OLD.user_id=(SELECT id FROM users WHERE email='target@member-delete.fixture.test') BEGIN SELECT RAISE(ABORT,'team deletion veto'); END", &[]).await?;
    let team_error = store
        .delete_member_with_context(&member.id, &organization.id, &owner_id, true)
        .await
        .err()
        .ok_or("real later team SQL veto must fail")?;
    assert!(team_error.to_string().contains("team deletion veto"));
    assert_eq!(
        db.tables(&TEAM_TABLES).await?,
        before,
        "later team veto must roll back the member deletion"
    );
    _ = db.execute("DROP TRIGGER team_veto", &[]).await?;
    _ = db.execute("CREATE TRIGGER ignored_member BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(IGNORE); END", &[]).await?;
    store
        .delete_member_with_context(&member.id, &organization.id, &owner_id, true)
        .await?;
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&member.id).await?)?,
        serde_json::to_value(Some(member.clone()))?,
        "ignored deletion is successful with member retained"
    );
    assert!(
        store
            .get_team_member(&own_team.id, &owner_id)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&own_team.id, &foreign_id)
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
    _ = db.execute("DROP TRIGGER ignored_member", &[]).await?;
    drop(store.add_team_member(&own_team.id, &owner_id, None).await?);
    _ = db.execute("CREATE TRIGGER phase_guard BEFORE DELETE ON team_member WHEN EXISTS(SELECT 1 FROM member WHERE user_id=OLD.user_id AND role='victim') BEGIN SELECT RAISE(ABORT,'member must be deleted first'); END", &[]).await?;
    store
        .delete_member_with_context(&member.id, &organization.id, &owner_id, true)
        .await?;
    assert!(store.get_member_by_id(&member.id).await?.is_none());
    assert!(
        store
            .get_team_member(&own_team.id, &owner_id)
            .await?
            .is_none()
    );
    _ = db.execute("DROP TRIGGER phase_guard", &[]).await?;
    drop(store.add_team_member(&own_team.id, &owner_id, None).await?);
    store
        .delete_member_with_context(&member.id, &organization.id, &owner_id, true)
        .await?;
    assert!(
        store
            .get_team_member(&own_team.id, &owner_id)
            .await?
            .is_none(),
        "captured cleanup still runs after genuine row absence"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&unrelated.id).await?)?,
        serde_json::to_value(Some(unrelated))?
    );
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&owner_id).await?)?,
        serde_json::to_value(Some(&owner))?
    );
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&foreign_id).await?)?,
        serde_json::to_value(Some(&foreign))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&organization.id).await?)?,
        serde_json::to_value(Some(organization.clone()))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
        serde_json::to_value(Some(other.clone()))?
    );
    let after = db.tables(&TEAM_TABLES).await?;
    assert_eq!(
        rows(&after[0])?,
        rows(&before[0])?
            .into_iter()
            .filter(|row| row["id"] != member.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rows(&after[1])?,
        rows(&before[1])?
            .into_iter()
            .map(|mut row| {
                if row["id"] == own_team.id.as_str() {
                    row["member_count"] = (row["member_count"].as_i64().unwrap() - 1).into();
                }
                row
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rows(&after[2])?,
        rows(&before[2])?
            .into_iter()
            .filter(|row| !(row["team_id"] == own_team.id.as_str()
                && row["user_id"] == owner_id.as_str()))
            .collect::<Vec<_>>()
    );
    B::close(connection).await
}

async fn contextual_deletion_uses_original_scope_and_unsorted_configured_pages<B: Backend>(
    db: Db,
) -> TestResult {
    let connection = B::connect(&db.url, None).await?;
    let mut config = AuthConfig::new("member-deletion-pages-public-store-secret");
    config.advanced.database.default_find_many_limit = 1;
    let store = B::store(Arc::new(config), &connection);
    store.migrate().await?;
    let user = store
        .create_user(CreateUser::new().with_email("page-target@member-delete.fixture.test"))
        .await?;
    let user_id = user.id().into_owned();
    let other_user = store
        .create_user(CreateUser::new().with_email("page-other@member-delete.fixture.test"))
        .await?;
    let other_user_id = other_user.id().into_owned();
    let org = store
        .create_organization(CreateOrganization::new("Page", "page"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other page", "other-page"))
        .await?;
    let first = store
        .create_member(CreateMember {
            organization_id: org.id.clone(),
            user_id: user_id.clone(),
            role: "owner".into(),
        })
        .await?;
    let second = store
        .create_member(CreateMember {
            organization_id: org.id.clone(),
            user_id: other_user_id.clone(),
            role: "owner".into(),
        })
        .await?;
    for (id, date) in [
        (&first.id, "2030-01-01T00:00:00Z"),
        (&second.id, "2000-01-01T00:00:00Z"),
    ] {
        db.set_timestamp("member", "created_at", ("id", id), date.parse()?)
            .await?;
    }
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
        drop(store.add_team_member(&team.id, &user_id, None).await?);
        teams.push(team);
    }
    let [first_team, second_team] = teams.as_slice() else {
        return Err("two actual team creations must return their rows".into());
    };
    let before = db.tables(&TEAM_TABLES).await?;
    _ = db
        .execute(
            "UPDATE member SET organization_id=$1, user_id=$2 WHERE id=$3",
            &[&other.id, &other_user_id, &first.id],
        )
        .await?;
    store
        .delete_member_with_context(&first.id, &org.id, &user_id, false)
        .await?;
    let after_disabled = db.tables(&TEAM_TABLES).await?;
    assert_eq!(after_disabled[1], before[1]);
    assert_eq!(
        after_disabled[2], before[2],
        "disabled teams retain their real memberships"
    );
    store
        .delete_member_with_context(&first.id, &org.id, &user_id, true)
        .await?;
    assert!(
        store
            .get_team_member(&first_team.id, &user_id)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second_team.id, &user_id)
            .await?
            .is_some(),
        "teams outside the actual configured page remain"
    );
    let after = db.tables(&TEAM_TABLES).await?;
    assert_eq!(
        rows(&after[1])?,
        rows(&before[1])?
            .into_iter()
            .map(|mut row| {
                if row["id"] == first_team.id.as_str() {
                    row["member_count"] = (row["member_count"].as_i64().unwrap() - 1).into();
                }
                row
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        rows(&after[2])?,
        rows(&before[2])?
            .into_iter()
            .filter(|row| row["team_id"] != first_team.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .get_member_by_id(&second.id)
            .await?
            .map(|row| row.role),
        Some("owner".into())
    );
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&user_id).await?)?,
        serde_json::to_value(Some(&user))?
    );
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&other_user_id).await?)?,
        serde_json::to_value(Some(&other_user))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&org.id).await?)?,
        serde_json::to_value(Some(org))?
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
        serde_json::to_value(Some(other))?
    );
    B::close(connection).await
}

async fn optional_member_role_updates_distinguish_missing_rows_from_write_errors<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("optional-member-role-public-store-secret")
        .await?;
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
                    user_id: user.id().into_owned(),
                    role: name.into(),
                })
                .await?,
        );
    }
    let (target, foreign) = (&members[0], &members[1]);
    let updated = store
        .update_member_role_if_present(&target.id, "admin")
        .await?
        .ok_or("existing member update must return its actual row")?;
    assert_eq!(updated.role, "admin");
    assert_eq!(updated.id, target.id);
    assert_eq!(updated.user_id, target.user_id);
    assert_eq!(updated.organization_id, target.organization_id);
    assert_eq!(updated.created_at, target.created_at);
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    _ = db.execute("CREATE TRIGGER veto_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(ABORT,'optional member storage veto'); END", &[]).await?;
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
    _ = db.execute("DROP TRIGGER veto_optional_member", &[]).await?;
    _ = db.execute("CREATE TRIGGER ignore_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(IGNORE); END", &[]).await?;
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
    B::close(connection).await
}

async fn query_organization_members_applies_filter_sort_and_pagination<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("test-secret-key-at-least-32-chars-long")
        .await?;
    let org_id = "org-1".to_owned();
    drop(
        store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(org_id.clone()),
                name: "Org".to_owned(),
                slug: "org".to_owned(),
                logo: None,
                metadata: None,
            })
            .await?,
    );
    for (id, role) in [
        ("user-owner", "owner"),
        ("user-member", "member"),
        ("user-admin", "admin"),
    ] {
        drop(
            store
                .create_user(CreateUser {
                    id: Some(id.to_owned()),
                    email: Some(format!("{role}@example.com")),
                    ..CreateUser::default()
                })
                .await?,
        );
    }
    for (id, role) in [
        ("user-owner", "owner"),
        ("user-member", "member"),
        ("user-admin", "admin"),
    ] {
        drop(
            store
                .create_member(CreateMember::new(&org_id, id, role))
                .await?,
        );
    }
    let (members, total) = store
        .query_organization_members(&ListOrganizationMembersParams {
            organization_id: org_id,
            limit: Some(1),
            offset: Some(1),
            sort_by: Some("role".to_owned()),
            sort_direction: Some("asc".to_owned()),
            filter_field: Some("role".to_owned()),
            filter_value: Some("owner".to_owned()),
            filter_operator: Some("ne".to_owned()),
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, "member");
    B::close(connection).await
}

async fn numeric_page_snapshot(db: &Db) -> TestResult<Option<String>> {
    if db.is_postgres() {
        return db.text(
            "SELECT json_build_object('members',(SELECT json_agg(r ORDER BY id) FROM member r),'users',(SELECT json_agg(r ORDER BY id) FROM users r),'organizations',(SELECT json_agg(r ORDER BY id) FROM organization r))::text",
            &[],
        ).await;
    }
    db.text(
        "SELECT json_object('members',(SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at)) FROM (SELECT rowid,* FROM member ORDER BY rowid)),'users',(SELECT json_group_array(json_object('id',id,'email',email,'created',created_at,'updated',updated_at)) FROM (SELECT * FROM users ORDER BY rowid)),'organizations',(SELECT json_group_array(json_object('id',id,'name',name,'created',created_at)) FROM (SELECT * FROM organization ORDER BY rowid)))",
        &[],
    )
    .await
}

async fn public_numeric_pages_bind_raw_limits_and_keep_insertion_order_filtered_count_and_full_state<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>("raw-member-page-secret").await?;
    let owner = store
        .create_user(CreateUser::new().with_email("owner@numeric-page.test"))
        .await?
        .id()
        .into_owned();
    let target = store
        .create_user(CreateUser::new().with_email("target@numeric-page.test"))
        .await?
        .id()
        .into_owned();
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@numeric-page.test"))
        .await?
        .id()
        .into_owned();
    let own = store
        .create_organization(CreateOrganization::new("Owned", "numeric-owned"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other", "numeric-other"))
        .await?;
    let first = store
        .create_member(CreateMember::new(&own.id, &owner, "owner"))
        .await?;
    let second = store
        .create_member(CreateMember::new(&own.id, &target, "member"))
        .await?;
    let peer = store
        .create_member(CreateMember::new(&other.id, &foreign, "owner"))
        .await?;
    // Contradict timestamp order with insertion order so an implicit createdAt
    // sort cannot accidentally satisfy the actual page contract.
    for (id, date) in [
        (&first.id, "2021-01-01T00:00:00Z"),
        (&second.id, "2020-01-01T00:00:00Z"),
    ] {
        db.set_timestamp("member", "created_at", ("id", id), date.parse()?)
            .await?;
    }
    let first = store
        .get_member_by_id(&first.id)
        .await?
        .ok_or("first missing")?;
    let second = store
        .get_member_by_id(&second.id)
        .await?
        .ok_or("second missing")?;
    let before = numeric_page_snapshot(&db).await?;
    for (limit, offset, expected) in [
        (1.0, 0.0, vec![first.clone()]),
        (1.0, 1.0, vec![second.clone()]),
        (-1.0, 0.0, vec![first.clone(), second.clone()]),
        (-0.0, 0.0, vec![]),
    ] {
        if db.is_postgres() && limit < 0.0 {
            assert!(matches!(
                store
                    .query_organization_members_page(&MemberPageQuery {
                        organization_id: own.id.clone(),
                        limit: Some(limit),
                        offset: Some(offset),
                        ..Default::default()
                    })
                    .await,
                Err(AuthError::Database(_))
            ));
            continue;
        }
        let (rows, total) = store
            .query_organization_members_page(&MemberPageQuery {
                organization_id: own.id.clone(),
                limit: Some(limit),
                offset: Some(offset),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 2);
        assert_eq!(serde_json::to_value(rows)?, serde_json::to_value(expected)?);
    }
    let (filtered, total) = store
        .query_organization_members_page(&MemberPageQuery {
            organization_id: own.id.clone(),
            limit: Some(1.0),
            filter_field: Some("role".into()),
            filter_value: Some("member".into()),
            filter_operator: Some("eq".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 1);
    assert_eq!(
        serde_json::to_value(filtered)?,
        serde_json::to_value(vec![second])?
    );
    for (limit, offset) in [
        (1.5, 0.0),
        (f64::INFINITY, 0.0),
        (f64::NEG_INFINITY, 0.0),
        (f64::NAN, 0.0),
        (1.0, 0.5),
    ] {
        assert!(
            matches!(
                store
                    .query_organization_members_page(&MemberPageQuery {
                        organization_id: own.id.clone(),
                        limit: Some(limit),
                        offset: Some(offset),
                        ..Default::default()
                    })
                    .await,
                Err(AuthError::Database(_))
            ),
            "the database must validate actual raw binding, not round/cap it"
        );
    }
    if db.is_postgres() {
        for (number, expected_error) in [
            (-1.0, "must not be negative"),
            (f64::NAN, "\"NaN\""),
            (f64::INFINITY, "\"Infinity\""),
            (f64::NEG_INFINITY, "\"-Infinity\""),
            (1e-7, "\"1e-7\""),
            (1e21, "\"1e+21\""),
            (1e20, "\"100000000000000000000\""),
        ] {
            for (limit, offset) in [(Some(number), None), (Some(1.0), Some(number))] {
                let error = store
                    .query_organization_members_page(&MemberPageQuery {
                        organization_id: own.id.clone(),
                        limit,
                        offset,
                        ..Default::default()
                    })
                    .await
                    .err()
                    .ok_or("invalid page unexpectedly succeeded")?;
                assert!(matches!(error, AuthError::Database(_)));
                assert!(
                    error.to_string().contains(expected_error),
                    "{number}: {error}"
                );
            }
        }
        // The public Number has already rounded 9007199254740993 to this value.
        // PostgreSQL parses the resulting decimal integer without float8 rounding.
        let (rows, total) = store
            .query_organization_members_page(&MemberPageQuery {
                organization_id: own.id.clone(),
                limit: Some(9007199254740992.0),
                offset: Some(0.0),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        let (rows, total) = store
            .query_organization_members_page(&MemberPageQuery {
                organization_id: own.id.clone(),
                limit: Some(1.0),
                offset: Some(9007199254740992.0),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 2);
        assert!(rows.is_empty());
    }
    let ids = vec![target.clone(), owner.clone()];
    if db.is_postgres() {
        assert!(matches!(
            store.list_users_by_ids_page(&ids, -1.0).await,
            Err(AuthError::Database(_))
        ));
    }
    let returned = store
        .list_users_by_ids_page(&ids, if db.is_postgres() { 2.0 } else { -1.0 })
        .await?;
    assert_eq!(returned.len(), 2);
    assert!(
        returned
            .iter()
            .all(|user| ids.contains(&user.id().into_owned()))
    );
    assert_eq!(store.list_users_by_ids_page(&ids, -0.0).await?.len(), 0);
    assert_eq!(store.list_users_by_ids_page(&ids, 1.0).await?.len(), 1);
    for limit in [1.5, f64::INFINITY, f64::NAN] {
        assert!(matches!(
            store.list_users_by_ids_page(&ids, limit).await,
            Err(AuthError::Database(_))
        ));
    }
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&peer.id).await?)?,
        serde_json::to_value(Some(peer))?
    );
    assert_eq!(
        numeric_page_snapshot(&db).await?,
        before,
        "all read pages and genuine SQL failures preserve owner/foreign physical records and date bytes"
    );
    B::close(connection).await
}
