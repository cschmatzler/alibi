//! Installed two-table migration: byte preservation and atomic rollback.
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
use better_auth_core::store::OrganizationStore;
use better_auth_core::{AuthConfig, CreateOrganization};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;

async fn snapshot(database: &DatabaseConnection) -> Result<Vec<(String, String)>, sea_orm::DbErr> {
    let mut rows = Vec::new();
    for (name, query) in [
        (
            "schema",
            "SELECT json_group_array(json_object('type',type,'name',name,'table',tbl_name,'sql',sql)) AS value FROM (SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name IN ('team','organization_role','team_link','app_org_scope') OR name='app_teams' ORDER BY type,name)",
        ),
        (
            "teams",
            "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'name',name,'count',member_count,'created',created_at,'updated',updated_at,'note',app_note,'label',app_label)) AS value FROM (SELECT rowid,* FROM team ORDER BY rowid)",
        ),
        (
            "roles",
            "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'role',role,'permission',permission,'created',created_at,'updated',updated_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM organization_role ORDER BY rowid)",
        ),
        (
            "ledger",
            "SELECT json_group_array(json_object('version',version,'applied',applied_at)) AS value FROM (SELECT * FROM better_auth_migrations ORDER BY version)",
        ),
    ] {
        let row = database
            .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
            .await?
            .ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?;
        rows.push((name.into(), row.try_get("", "value")?));
    }
    Ok(rows)
}
async fn installed() -> Result<(DatabaseConnection, String), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    AuthMigrator::up(&database, None).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("org-reference-upgrade-local-secret-at-least32"),
        database.clone(),
    );
    let org = store
        .create_organization(CreateOrganization::new("Existing", "existing"))
        .await?;
    for sql in [
        "DELETE FROM better_auth_migrations WHERE version='m20261001_000014_detach_organization_references'",
        "DROP TABLE team_member",
        "DROP TABLE team",
        "DROP TABLE organization_role",
        "CREATE TABLE app_org_scope(id TEXT PRIMARY KEY)",
        "CREATE TABLE team(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL,organization_id TEXT NOT NULL,member_count BIGINT NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT,app_note TEXT DEFAULT 'has,comma' CHECK(app_note <> 'blocked'),app_label TEXT GENERATED ALWAYS AS (name || ':' || app_note) VIRTUAL,CONSTRAINT fk_team_organization FOREIGN KEY(organization_id) REFERENCES organization(id) ON DELETE CASCADE,CONSTRAINT app_team_scope FOREIGN KEY(organization_id) REFERENCES app_org_scope(id))",
        "CREATE TABLE organization_role(id TEXT PRIMARY KEY NOT NULL,organization_id TEXT NOT NULL,role TEXT NOT NULL,permission TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT,app_note TEXT DEFAULT 'retained' CHECK(app_note <> 'forbidden'),CONSTRAINT fk_organization_role_organization FOREIGN KEY(organization_id) REFERENCES organization(id) ON DELETE CASCADE,CONSTRAINT app_role_scope FOREIGN KEY(organization_id) REFERENCES app_org_scope(id))",
        "CREATE INDEX app_team_note ON team(app_note) WHERE app_note IS NOT NULL",
        "CREATE INDEX app_role_note ON organization_role(app_note)",
        "CREATE TABLE app_team_audit(id TEXT)",
        "CREATE TRIGGER app_team_changes AFTER UPDATE ON team BEGIN INSERT INTO app_team_audit VALUES(NEW.id); END",
        "CREATE TABLE team_link(team_id TEXT REFERENCES team(id))",
        "CREATE VIEW app_teams AS SELECT id,app_note,app_label FROM team",
    ] {
        let _ = database.execute_unprepared(sql).await?;
    }
    let _ = database
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO app_org_scope VALUES (?)",
            vec![org.id.clone().into()],
        ))
        .await?;
    let _ = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO team(rowid,id,name,organization_id,member_count,created_at,app_note) VALUES(97,'installed-team','Existing Team',?,1,'2026-01-02 03:04:05.125','kept,bytes')",vec![org.id.clone().into()])).await?;
    let _ = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO organization_role(rowid,id,organization_id,role,permission,created_at,app_note) VALUES(103,'installed-role',?,'retained-role','{ \"team\" : [\"create\"] }','2026-01-02 03:04:05.125','role-bytes')",vec![org.id.clone().into()])).await?;
    let _ = database
        .execute_unprepared("INSERT INTO team_link VALUES('installed-team')")
        .await?;
    Ok((database, org.id))
}
#[tokio::test]
async fn installed_organization_references_preserve_rows_and_unrelated_constraints()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, organization_id) = installed().await?;
    let before = snapshot(&database).await?;
    AuthMigrator::up(&database, None).await?;
    AuthMigrator::up(&database, None).await?;
    let after = snapshot(&database).await?;
    assert_eq!(before[1], after[1]);
    assert_eq!(before[2], after[2]);
    for table in ["team", "organization_role"] {
        let rows = database
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA foreign_key_list('{table}')"),
            ))
            .await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<String>("", "table")?, "app_org_scope");
    }
    let row = database
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT app_label FROM app_teams WHERE id='installed-team'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("view disappeared"))?;
    assert_eq!(
        row.try_get::<String>("", "app_label")?,
        "Existing Team:kept,bytes"
    );
    assert!(
        database
            .execute_unprepared("UPDATE team SET app_note='blocked' WHERE id='installed-team'")
            .await
            .is_err()
    );
    let _ = database
        .execute_unprepared("UPDATE team SET app_note='changed' WHERE id='installed-team'")
        .await?;
    let trigger = database
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT id FROM app_team_audit",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("trigger disappeared"))?;
    assert_eq!(trigger.try_get::<String>("", "id")?, "installed-team");
    assert!(
        database
            .execute_unprepared("INSERT INTO team_link VALUES('missing-team')")
            .await
            .is_err()
    );
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("org-reference-upgrade-local-secret-at-least32"),
        database.clone(),
    );
    store.delete_organization(&organization_id).await?;
    assert!(
        store
            .get_organization_by_id(&organization_id)
            .await?
            .is_none()
    );
    for table in ["team", "organization_role"] {
        let row = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT COUNT(*) AS count FROM {table}"),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("count disappeared"))?;
        assert_eq!(row.try_get::<i64>("", "count")?, 1);
    }
    Ok(())
}
#[tokio::test]
async fn second_organization_reference_failure_rolls_back_first_table_and_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, _) = installed().await?;
    for sql in [
        "PRAGMA ignore_check_constraints=ON",
        "UPDATE organization_role SET app_note='forbidden' WHERE id='installed-role'",
        "PRAGMA ignore_check_constraints=OFF",
    ] {
        let _ = database.execute_unprepared(sql).await?;
    }
    let before = snapshot(&database).await?;
    let failure = AuthMigrator::up(&database, None)
        .await
        .expect_err("the second table copy must reject its legacy check-violating row");
    assert!(failure.to_string().contains("CHECK constraint failed"));
    assert_eq!(
        snapshot(&database).await?,
        before,
        "both recreated tables, exact bytes and migration ledger must roll back"
    );
    for (pragma, expected) in [
        ("foreign_keys", 1_i64),
        ("legacy_alter_table", 0),
        ("ignore_check_constraints", 0),
    ] {
        let row = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA {pragma}"),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("pragma disappeared"))?;
        assert_eq!(row.try_get::<i64>("", pragma)?, expected);
    }
    let temporary = database
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM sqlite_schema WHERE name LIKE '%__user_reference'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("schema count disappeared"))?;
    assert_eq!(temporary.try_get::<i64>("", "count")?, 0);
    assert!(
        database
            .execute_unprepared("INSERT INTO team_link VALUES('another-missing')")
            .await
            .is_err()
    );
    let _ = database
        .execute_unprepared(
            "UPDATE organization_role SET app_note='repaired' WHERE id='installed-role'",
        )
        .await?;
    AuthMigrator::up(&database, None).await?;
    Ok(())
}
