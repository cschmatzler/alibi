//! Installed member identities and physical membership pages remain authoritative.
#![expect(
    clippy::panic_in_result_fn,
    reason = "native persistence tests assert invariants while propagating setup failures"
)]
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
use better_auth_core::store::{MemberStore, OrganizationStore, TeamStore, UserStore};
use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateTeam, CreateUser};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use sea_orm_migration::{MigratorTrait, SchemaManager};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const UPGRADE: &str = "m20261001_000015_member_pair_multiplicity";

async fn scalar(db: &DatabaseConnection, sql: &str) -> Result<String, sea_orm::DbErr> {
    db.query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
        .await?
        .ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?
        .try_get("", "value")
}

#[tokio::test]
async fn installed_member_upgrade_preserves_rows_and_application_schema_then_allows_duplicates()
-> TestResult {
    let db = Database::connect("sqlite::memory:").await?;
    let prior = AuthMigrator::migrations()
        .iter()
        .take_while(|migration| migration.name() != UPGRADE)
        .count();
    AuthMigrator::up(&db, Some(u32::try_from(prior)?)).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("installed-member-multiplicity-secret"),
        db.clone(),
    );
    let user = store
        .create_user(CreateUser::new().with_email("installed@member-pair.test"))
        .await?;
    let foreign = store
        .create_user(CreateUser::new().with_email("foreign@member-pair.test"))
        .await?;
    let org = store
        .create_organization(CreateOrganization::new("Installed", "installed-pair"))
        .await?;
    let other = store
        .create_organization(CreateOrganization::new("Foreign", "foreign-pair"))
        .await?;
    let original = store
        .create_member(CreateMember::new(&org.id, &user.id, "owner"))
        .await?;
    let peer = store
        .create_member(CreateMember::new(&other.id, &foreign.id, "member"))
        .await?;
    assert!(
        store
            .create_member(CreateMember::new(&org.id, &user.id, "admin"))
            .await
            .is_err(),
        "the actual installed pair constraint must exist before upgrade"
    );
    for sql in [
        "ALTER TABLE member ADD COLUMN app_note TEXT NOT NULL DEFAULT 'kept,bytes' CHECK(app_note <> 'blocked')",
        "CREATE INDEX app_member_note ON member(app_note) WHERE app_note IS NOT NULL",
        "CREATE TABLE app_member_audit(id TEXT)",
        "CREATE TRIGGER app_member_changes AFTER UPDATE ON member BEGIN INSERT INTO app_member_audit VALUES(NEW.id); END",
        "CREATE VIEW app_members AS SELECT id,app_note FROM member",
    ] {
        let _ = db.execute_unprepared(sql).await?;
    }
    let row_sql = "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM member ORDER BY rowid)";
    let schema_sql = "SELECT json_group_array(json_object('type',type,'name',name,'sql',sql)) AS value FROM (SELECT type,name,sql FROM sqlite_schema WHERE (tbl_name='member' OR name='app_members') AND name <> 'idx_member_org_user_unique' ORDER BY type,name)";
    let before = (scalar(&db, row_sql).await?, scalar(&db, schema_sql).await?);
    AuthMigrator::up(&db, None).await?;
    assert_eq!(
        (scalar(&db, row_sql).await?, scalar(&db, schema_sql).await?),
        before,
        "index removal must preserve physical IDs, rowids, date/text bytes and unrelated schema"
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&original.id).await?)?,
        serde_json::to_value(Some(original.clone()))?
    );
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&peer.id).await?)?,
        serde_json::to_value(Some(peer.clone()))?
    );
    let second = store
        .create_member(CreateMember::new(&org.id, &user.id, "admin"))
        .await?;
    assert_ne!(second.id, original.id);
    assert_eq!(store.count_organization_members(&org.id).await?, 2);
    assert_eq!(
        serde_json::to_value(store.get_member(&org.id, &user.id).await?)?,
        serde_json::to_value(Some(original.clone()))?
    );
    let changed = store.update_member_role(&second.id, "member").await?;
    assert_eq!(changed.id, second.id);
    assert_eq!(
        serde_json::to_value(store.get_member_by_id(&original.id).await?)?,
        serde_json::to_value(Some(original))?
    );
    assert_eq!(
        scalar(
            &db,
            "SELECT json_group_array(id) AS value FROM app_member_audit"
        )
        .await?,
        serde_json::to_string(&vec![second.id.clone()])?
    );
    assert!(
        db.execute_unprepared("UPDATE member SET app_note='blocked'")
            .await
            .is_err()
    );
    let before_repeat=(scalar(&db,row_sql).await?,scalar(&db,schema_sql).await?,scalar(&db,"SELECT json_group_array(version) AS value FROM (SELECT version FROM better_auth_migrations ORDER BY version)").await?);
    AuthMigrator::up(&db, None).await?;
    let migration = AuthMigrator::migrations()
        .into_iter()
        .find(|migration| migration.name() == UPGRADE)
        .ok_or("member pair migration missing")?;
    // Exercise the absence guard itself, independently of the migration ledger.
    migration.up(&SchemaManager::new(&db)).await?;
    migration.up(&SchemaManager::new(&db)).await?;
    assert_eq!((scalar(&db,row_sql).await?,scalar(&db,schema_sql).await?,scalar(&db,"SELECT json_group_array(version) AS value FROM (SELECT version FROM better_auth_migrations ORDER BY version)").await?),before_repeat);
    Ok(())
}

#[tokio::test]
async fn organization_list_pages_physical_members_before_joining_and_keeps_full_peer_rows()
-> TestResult {
    let db = Database::connect("sqlite::memory:").await?;
    AuthMigrator::up(&db, None).await?;
    // A published SQLite installation already has this unconstrained shape.
    // It isolates consumer behavior from whether the upgrade itself ran.
    let _ = db
        .execute_unprepared("DROP INDEX IF EXISTS idx_member_org_user_unique")
        .await?;
    let config = AuthConfig::new("physical-member-page-secret");
    let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
    let user = store
        .create_user(CreateUser::new().with_email("target@member-page.test"))
        .await?;
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
        (&old.id, "2020-01-01 00:00:00+00:00"),
        (&new.id, "2021-01-01 00:00:00+00:00"),
    ] {
        let _ = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE organization SET created_at=? WHERE id=?",
                [date.into(), id.clone().into()],
            ))
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
        .create_member(CreateMember::new(&new.id, &user.id, "member"))
        .await?;
    let second = store
        .create_member(CreateMember::new(&old.id, &user.id, "owner"))
        .await?;
    let duplicate = store
        .create_member(CreateMember::new(&new.id, &user.id, "admin"))
        .await?;
    let peer = store
        .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
        .await?;
    let foreign_before = serde_json::to_value((&peer, &other, &foreign))?;
    for (limit, expected) in [
        (100, vec![new.clone(), old.clone(), new.clone()]),
        (2, vec![new.clone(), old.clone()]),
        (1, vec![new.clone()]),
        (0, vec![]),
    ] {
        let mut configured = config.clone();
        configured.advanced.database.default_find_many_limit = limit;
        let paged = SeaOrmStore::<BundledSchema>::new(configured, db.clone());
        assert_eq!(
            serde_json::to_value(paged.list_user_organizations(&user.id).await?)?,
            serde_json::to_value(expected)?,
            "membership page {limit} must retain multiplicity, full output and admission order"
        );
    }
    assert_eq!(
        serde_json::to_value(store.get_member(&new.id, &user.id).await?)?,
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
    let _ = store.add_team_member(&team.id, &user.id, None).await?;
    let _ = store.add_team_member(&team.id, &foreign.id, None).await?;
    let _ = store.add_team_member(&peer_team.id, &user.id, None).await?;
    let foreign_team_before = store.get_team(Some(&other.id), &peer_team.id).await?;
    let foreign_link_before = store.get_team_member(&peer_team.id, &user.id).await?;
    store
        .delete_member_with_context(&duplicate.id, &new.id, &user.id, true)
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
    assert!(store.get_team_member(&team.id, &user.id).await?.is_none());
    assert!(
        store
            .get_team_member(&team.id, &foreign.id)
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
        serde_json::to_value(store.get_team_member(&peer_team.id, &user.id).await?)?,
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
                .get_user_by_id(&foreign.id)
                .await?
                .ok_or("foreign user missing")?
        ))?,
        foreign_before
    );
    Ok(())
}

#[tokio::test]
async fn independent_connections_admit_distinct_member_ids_for_the_same_pair() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "member-multiplicity-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let first_db = Database::connect(&url).await?;
    AuthMigrator::up(&first_db, None).await?;
    let config = AuthConfig::new("independent-member-admission-secret");
    let first = SeaOrmStore::<BundledSchema>::new(config.clone(), first_db.clone());
    let second_db = Database::connect(&url).await?;
    let second = SeaOrmStore::<BundledSchema>::new(config, second_db.clone());
    let user = first
        .create_user(CreateUser::new().with_email("concurrent@member-pair.test"))
        .await?;
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
        .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
        .await?;
    let results = tokio::join!(
        first.create_member(CreateMember::new(&org.id, &user.id, "member")),
        second.create_member(CreateMember::new(&org.id, &user.id, "admin")),
    );
    let a = results.0?;
    let b = results.1?;
    assert_ne!(a.id, b.id);
    assert_eq!(first.count_organization_members(&org.id).await?, 2);
    let rows = first.list_organization_members(&org.id).await?;
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.user_id, user.id);
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
    first_db.close().await?;
    second_db.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
