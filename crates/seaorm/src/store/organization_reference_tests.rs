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
            "application_scopes",
            "SELECT json_group_array(json_object('rowid',rowid,'id',id)) AS value FROM (SELECT rowid,* FROM app_org_scope ORDER BY rowid)",
        ),
        (
            "application_links",
            "SELECT json_group_array(json_object('rowid',rowid,'team',team_id)) AS value FROM (SELECT rowid,* FROM team_link ORDER BY rowid)",
        ),
        (
            "application_audit",
            "SELECT json_group_array(json_object('rowid',rowid,'id',id)) AS value FROM (SELECT rowid,* FROM app_team_audit ORDER BY rowid)",
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
async fn installed_at(
    url: &str,
) -> Result<(DatabaseConnection, String), Box<dyn std::error::Error>> {
    let mut options = sea_orm::ConnectOptions::new(url);
    let _configured = options.max_connections(1);
    let database = Database::connect(options).await?;
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
        let _ignored_execute_unprepared = database.execute_unprepared(sql).await?;
    }
    let _ignored_into = database
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO app_org_scope VALUES (?)",
            vec![org.id.clone().into()],
        ))
        .await?;
    let _ignored_into_2 = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO team(rowid,id,name,organization_id,member_count,created_at,app_note) VALUES(97,'installed-team','Existing Team',?,1,'2026-01-02 03:04:05.125','kept,bytes')",vec![org.id.clone().into()])).await?;
    let _ignored_into_3 = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO organization_role(rowid,id,organization_id,role,permission,created_at,app_note) VALUES(103,'installed-role',?,'retained-role','{ \"team\" : [\"create\"] }','2026-01-02 03:04:05.125','role-bytes')",vec![org.id.clone().into()])).await?;
    let _ignored_execute_unprepared_2 = database
        .execute_unprepared("INSERT INTO team_link VALUES('installed-team')")
        .await?;
    Ok((database, org.id))
}
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn installed_organization_references_preserve_rows_and_unrelated_constraints()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, organization_id) = installed_at("sqlite::memory:").await?;
    let before = snapshot(&database).await?;
    AuthMigrator::up(&database, None).await?;
    AuthMigrator::up(&database, None).await?;
    let after = snapshot(&database).await?;
    assert_eq!(
        (*(before)
            .get(1)
            .expect("fixture contains the requested index")),
        (*(after)
            .get(1)
            .expect("fixture contains the requested index"))
    );
    assert_eq!(
        (*(before)
            .get(2)
            .expect("fixture contains the requested index")),
        (*(after)
            .get(2)
            .expect("fixture contains the requested index"))
    );
    for table in ["team", "organization_role"] {
        let rows = database
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("PRAGMA foreign_key_list('{table}')"),
            ))
            .await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (*(rows)
                .first()
                .expect("fixture contains the requested index"))
            .try_get::<String>("", "table")?,
            "app_org_scope"
        );
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
    let _ignored_execute_unprepared_3 = database
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
        let row_2 = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT COUNT(*) AS count FROM {table}"),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("count disappeared"))?;
        assert_eq!(row_2.try_get::<i64>("", "count")?, 1);
    }
    Ok(())
}
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn second_organization_reference_failure_rolls_back_first_table_and_settings()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, _) = installed_at("sqlite::memory:").await?;
    for sql in [
        "PRAGMA ignore_check_constraints=ON",
        "UPDATE organization_role SET app_note='forbidden' WHERE id='installed-role'",
        "PRAGMA ignore_check_constraints=OFF",
    ] {
        let _ignored_execute_unprepared_4 = database.execute_unprepared(sql).await?;
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
    let _ignored_execute_unprepared_5 = database
        .execute_unprepared(
            "UPDATE organization_role SET app_note='repaired' WHERE id='installed-role'",
        )
        .await?;
    AuthMigrator::up(&database, None).await?;
    Ok(())
}

// A real application-owned driver delegates the installed migration, then pauses
// before SeaORM owns the ledger insert. No production timing hook is needed.
struct PausedMigration(std::sync::Arc<tokio::sync::Notify>);
impl sea_orm_migration::MigrationName for PausedMigration {
    fn name(&self) -> &str {
        "m20261001_000014_detach_organization_references"
    }
}
#[async_trait::async_trait]
impl sea_orm_migration::MigrationTrait for PausedMigration {
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires the manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &sea_orm_migration::SchemaManager) -> Result<(), sea_orm::DbErr> {
        sea_orm_migration::MigrationTrait::up(
            &super::organization_reference::DetachOrganizationReferences,
            manager,
        )
        .await?;
        self.0.notify_one();
        std::future::pending().await
    }
}
struct PausedDriver(std::sync::Arc<tokio::sync::Notify>);
#[async_trait::async_trait]
impl sea_orm_migration::MigratorTraitSelf for PausedDriver {
    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        <AuthMigrator as MigratorTrait>::migrations()
            .into_iter()
            .map(|migration| {
                if migration.name() == "m20261001_000014_detach_organization_references" {
                    Box::new(PausedMigration(self.0.clone()))
                        as Box<dyn sea_orm_migration::MigrationTrait>
                } else {
                    migration
                }
            })
            .collect()
    }
    fn migration_table_name(&self) -> sea_orm::DynIden {
        <AuthMigrator as MigratorTrait>::migration_table_name()
    }
}
fn require(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message).into())
    }
}
struct DatabaseFile(std::path::PathBuf);
impl Drop for DatabaseFile {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn committed_rebuild_recovers_after_real_ledger_veto_and_driver_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    for cancel in [false, true] {
        let file = DatabaseFile(std::env::temp_dir().join(format!(
            "better-auth-ledger-{}.sqlite",
            uuid::Uuid::new_v4()
        )));
        let url = format!("sqlite://{}?mode=rwc", file.0.display());
        let (database, _) = installed_at(&url).await?;
        let before = snapshot(&database).await?;
        if cancel {
            let committed = std::sync::Arc::new(tokio::sync::Notify::new());
            let driver = PausedDriver(committed.clone());
            let worker_database = database.clone();
            let worker = tokio::spawn(async move {
                sea_orm_migration::MigratorTraitSelf::up(&driver, &worker_database, None).await
            });
            tokio::time::timeout(std::time::Duration::from_secs(10), committed.notified()).await?;
            worker.abort();
            require(
                worker.await.is_err_and(|error| error.is_cancelled()),
                "driver did not cancel after committed rebuild",
            )?;
        } else {
            let _created = database.execute_unprepared("CREATE TRIGGER veto_auth_ledger BEFORE INSERT ON better_auth_migrations WHEN NEW.version='m20261001_000014_detach_organization_references' BEGIN SELECT RAISE(ABORT,'application ledger veto'); END").await?;
            let failure = AuthMigrator::up(&database, None).await;
            require(
                failure.is_err_and(|error| error.to_string().contains("application ledger veto")),
                "ledger SQL veto did not reach the actual migration driver",
            )?;
        }
        // Reopen independently: observing the writer alone cannot prove commit.
        let observer = Database::connect(&url).await?;
        let completed = snapshot(&observer).await?;
        require(
            before
                .iter()
                .filter(|(name, _)| name != "schema")
                .eq(completed.iter().filter(|(name, _)| name != "schema")),
            "rebuild changed installed row bytes or recorded an uncompleted ledger entry",
        )?;
        require(
            before != completed,
            "failure happened before the schema rebuild committed",
        )?;
        for query in [
            "PRAGMA foreign_key_list('team')",
            "PRAGMA foreign_key_list('organization_role')",
        ] {
            let keys = observer
                .query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                .await?;
            require(
                keys.len() == 1
                    && keys.first().is_some_and(|key| {
                        key.try_get::<String>("", "table")
                            .is_ok_and(|name| name == "app_org_scope")
                    }),
                "completed rebuild failed to preserve the independent application foreign key",
            )?;
        }
        for (query, name, expected) in [
            ("PRAGMA foreign_keys", "foreign_keys", 1_i64),
            ("PRAGMA legacy_alter_table", "legacy_alter_table", 0),
        ] {
            let row = database
                .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                .await?
                .ok_or_else(|| std::io::Error::other("missing connection setting"))?;
            require(
                row.try_get::<i64>("", name)? == expected,
                "committed helper returned an altered connection setting",
            )?;
        }
        require(
            database
                .execute_unprepared("INSERT INTO team_link VALUES('missing-after-ledger-failure')")
                .await
                .is_err(),
            "foreign-key enforcement was lost",
        )?;
        if !cancel {
            let _dropped = database
                .execute_unprepared("DROP TRIGGER veto_auth_ledger")
                .await?;
        }
        AuthMigrator::up(&database, None).await?;
        let retried = snapshot(&observer).await?;
        require(
            completed
                .iter()
                .filter(|(name, _)| name != "ledger")
                .eq(retried.iter().filter(|(name, _)| name != "ledger")),
            "retry rebuilt an already completed schema or changed application rows",
        )?;
        AuthMigrator::up(&database, None).await?;
        require(
            snapshot(&observer).await? == retried,
            "second retry changed rows, schema or ledger",
        )?;
        let ledger = observer.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "SELECT COUNT(*) AS count FROM better_auth_migrations WHERE version='m20261001_000014_detach_organization_references'")).await?.ok_or_else(|| std::io::Error::other("missing migration ledger"))?;
        require(
            ledger.try_get::<i64>("", "count")? == 1,
            "completed retry did not record exactly one migration",
        )?;
        let _updated = database
            .execute_unprepared(
                "UPDATE team SET app_note='changed-after-retry' WHERE id='installed-team'",
            )
            .await?;
        let trigger = observer
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM app_team_audit",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("installed trigger disappeared"))?;
        require(
            trigger.try_get::<String>("", "id")? == "installed-team",
            "installed trigger no longer observes application updates",
        )?;
        require(
            database
                .execute_unprepared("UPDATE team SET app_note='blocked' WHERE id='installed-team'")
                .await
                .is_err(),
            "installed CHECK constraint disappeared",
        )?;
        observer.close().await?;
        database.close().await?;
    }
    Ok(())
}
