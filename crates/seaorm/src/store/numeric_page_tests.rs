//! Public adapter pages preserve numeric binding and physical rows independently
//! of HTTP query parsing or organization authorization.
#![expect(
    clippy::panic_in_result_fn,
    reason = "native public storage proof propagates setup failures"
)]
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::store::{MemberPageQuery, MemberStore, OrganizationStore, UserStore};
use better_auth_core::{AuthConfig, AuthError, CreateMember, CreateOrganization, CreateUser};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
type TestResult = Result<(), Box<dyn std::error::Error>>;
async fn snapshot(db: &DatabaseConnection) -> Result<String, sea_orm::DbErr> {
    db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
        "SELECT json_object('members',(SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at)) FROM (SELECT rowid,* FROM member ORDER BY rowid)),'users',(SELECT json_group_array(json_object('id',id,'email',email,'created',created_at,'updated',updated_at)) FROM (SELECT * FROM users ORDER BY rowid)),'organizations',(SELECT json_group_array(json_object('id',id,'name',name,'created',created_at)) FROM (SELECT * FROM organization ORDER BY rowid))) AS snapshot"))
        .await?.ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?.try_get("", "snapshot")
}
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn public_numeric_pages_bind_raw_limits_and_keep_insertion_order_filtered_count_and_full_state()
-> TestResult {
    let db = Database::connect("sqlite::memory:").await?;
    run_migrations(&db).await?;
    let store =
        SeaOrmStore::<BundledSchema>::new(AuthConfig::new("raw-member-page-secret"), db.clone());
    let owner = store
        .create_user(CreateUser::new().with_email("owner@numeric-page.test"))
        .await?;
    let target = store
        .create_user(CreateUser::new().with_email("target@numeric-page.test"))
        .await?;
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@numeric-page.test"))
        .await?;
    let own = store
        .create_organization(CreateOrganization::new("Owned", "numeric-owned"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Other", "numeric-other"))
        .await?;
    let first = store
        .create_member(CreateMember::new(&own.id, &owner.id, "owner"))
        .await?;
    let second = store
        .create_member(CreateMember::new(&own.id, &target.id, "member"))
        .await?;
    let peer = store
        .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
        .await?;
    // Contradict timestamp order with insertion order so an implicit legacy
    // createdAt sort cannot accidentally satisfy the actual page contract.
    for (id, date) in [
        (&first.id, "2021-01-01 00:00:00+00:00"),
        (&second.id, "2020-01-01 00:00:00+00:00"),
    ] {
        _ = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE member SET created_at=? WHERE id=?",
                [date.into(), id.clone().into()],
            ))
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
    let before = snapshot(&db).await?;
    for (limit, offset, expected) in [
        (1.0, 0.0, vec![first.clone()]),
        (1.0, 1.0, vec![second.clone()]),
        (-1.0, 0.0, vec![first.clone(), second.clone()]),
        (-0.0, 0.0, vec![]),
    ] {
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
            "SQLite must validate actual raw binding, not round/cap it"
        );
    }
    let ids = vec![target.id.clone(), owner.id.clone()];
    let returned = store.list_users_by_ids_page(&ids, -1.0).await?;
    assert_eq!(returned.len(), 2);
    assert!(returned.iter().all(|user| ids.contains(&user.id)));
    assert!(store.list_users_by_ids_page(&ids, -0.0).await?.is_empty());
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
        snapshot(&db).await?,
        before,
        "all read pages and genuine SQL failures preserve owner/foreign physical records and date bytes"
    );
    Ok(())
}
