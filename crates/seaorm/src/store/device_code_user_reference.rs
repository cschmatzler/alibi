//! Device authorization records use an unconstrained optional user reference.

use super::nullable_user_flags::sql_tokens;
use sea_orm::sqlx::{Connection, Row, SqliteConnection};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseExecutor, Statement};
use sea_orm_migration::prelude::*;

pub(super) struct DeviceCodeUserReference;

impl MigrationName for DeviceCodeUserReference {
    fn name(&self) -> &str {
        "m20260930_000006_device_code_user_reference"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for DeviceCodeUserReference {
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        match connection.get_database_backend() {
            DatabaseBackend::Postgres => {
                let _ = connection
                    .execute_unprepared(
                        "ALTER TABLE device_code DROP CONSTRAINT IF EXISTS fk_device_code_user_id",
                    )
                    .await?;
                Ok(())
            }
            DatabaseBackend::Sqlite => {
                let rows = connection
                    .query_all_raw(Statement::from_string(
                        DatabaseBackend::Sqlite,
                        "PRAGMA foreign_key_list('device_code')",
                    ))
                    .await?;
                let mut has_user_reference = false;
                for row in rows {
                    has_user_reference |= row.try_get::<String>("", "from")? == "user_id";
                }
                if !has_user_reference {
                    return Ok(());
                }
                rebuild_sqlite_device_codes(manager).await
            }
            backend => Err(DbErr::Custom(format!(
                "device-code user-reference migration does not support {backend:?}"
            ))),
        }
    }
}

fn sqlx_error(error: sea_orm::sqlx::Error) -> DbErr {
    DbErr::Migration(format!("Device user reference: {error}"))
}

async fn rebuild_sqlite_device_codes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let DatabaseExecutor::Connection(database) = manager.get_connection() else {
        return Err(DbErr::Migration(
            "SQLite device user references must be migrated outside an existing transaction"
                .to_owned(),
        ));
    };
    let mut connection = database
        .get_sqlite_connection_pool()
        .acquire()
        .await
        .map_err(sqlx_error)?;
    let foreign_keys: i64 = sea_orm::sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let legacy_alter_table: i64 = sea_orm::sqlx::query_scalar("PRAGMA legacy_alter_table")
        .fetch_one(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    // Cancellation/error must never return a connection with foreign keys
    // disabled to the pool. Successful restoration returns it explicitly.
    connection.close_on_drop();
    let _ = sea_orm::sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    // Existing views temporarily refer to the dropped name inside this
    // transaction. Legacy rename validation leaves those definitions intact
    // until the replacement restores that same name.
    let _ = sea_orm::sqlx::query("PRAGMA legacy_alter_table = ON")
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let result = rebuild_device_transaction(&mut connection).await;
    let _ = sea_orm::sqlx::query(&format!("PRAGMA foreign_keys = {foreign_keys}"))
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let _ = sea_orm::sqlx::query(&format!("PRAGMA legacy_alter_table = {legacy_alter_table}"))
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let restored: i64 = sea_orm::sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let restored_legacy: i64 = sea_orm::sqlx::query_scalar("PRAGMA legacy_alter_table")
        .fetch_one(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    if restored != foreign_keys || restored_legacy != legacy_alter_table {
        return Err(DbErr::Migration(
            "Unable to restore SQLite foreign-key and rename settings".to_owned(),
        ));
    }
    connection.return_to_pool().await;
    result
}

async fn rebuild_device_transaction(connection: &mut SqliteConnection) -> Result<(), DbErr> {
    let mut transaction = connection.begin().await.map_err(sqlx_error)?;
    let outcome = async {
        let sql: String = sea_orm::sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name='device_code'").fetch_one(&mut *transaction).await.map_err(sqlx_error)?;
        let statements: Vec<String> = sea_orm::sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE tbl_name='device_code' AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name").fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        let body = sql_tokens(&sql)?.into_iter().find(|span| sql[span.clone()].starts_with('(')).ok_or_else(|| DbErr::Migration("Missing device table definition".to_owned()))?;
        let definitions = &sql[body.start+1..body.end-1];
        let mut kept = Vec::new();
        let mut start = 0;
        let mut removed = 0;
        for end in sql_tokens(definitions)?.into_iter().filter(|span| &definitions[span.clone()] == ",").map(|span| (span.start,span.end)).chain(std::iter::once((definitions.len(),definitions.len()))) {
            let definition = &definitions[start..end.0];
            let tokens = sql_tokens(definition)?;
            let target = matches!(tokens.as_slice(), [constraint,name,foreign,key,..] if definition[constraint.clone()].eq_ignore_ascii_case("CONSTRAINT") && definition[name.clone()].trim_matches(['\"','\'','`','[',']']).eq_ignore_ascii_case("fk_device_code_user_id") && definition[foreign.clone()].eq_ignore_ascii_case("FOREIGN") && definition[key.clone()].eq_ignore_ascii_case("KEY"));
            if target { removed += 1; } else { kept.push(definition); }
            start = end.1;
        }
        if removed != 1 { return Err(DbErr::Migration("Unable to safely remove the installed device user constraint".to_owned())); }
        let rewritten = format!("CREATE TABLE \"device_code__user_reference\" ({}){}", kept.join(","), &sql[body.end..]);
        let columns = sea_orm::sqlx::query("PRAGMA table_xinfo(\"device_code\")").fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        let mut copied = columns.iter().filter(|row| row.get::<i64,_>("hidden") == 0).map(|row| format!("\"{}\"",row.get::<String,_>("name").replace('\"',"\"\""))).collect::<Vec<_>>();
        let suffix = &sql[body.end..];
        let without_rowid = sql_tokens(suffix)?.windows(2).any(|pair| matches!(pair, [without,rowid] if suffix[without.clone()].eq_ignore_ascii_case("WITHOUT") && suffix[rowid.clone()].eq_ignore_ascii_case("ROWID")));
        if !without_rowid && let Some(alias) = ["rowid","_rowid_","oid"].into_iter().find(|alias| !columns.iter().any(|row| row.get::<String,_>("name").eq_ignore_ascii_case(alias))) { copied.insert(0,format!("\"{alias}\"")); }
        let copied = copied.join(",");
        let _ = sea_orm::sqlx::query(&rewritten).execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query(&format!("INSERT INTO \"device_code__user_reference\" ({copied}) SELECT {copied} FROM \"device_code\"")).execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query("DROP TABLE \"device_code\"").execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query("ALTER TABLE \"device_code__user_reference\" RENAME TO \"device_code\"").execute(&mut *transaction).await.map_err(sqlx_error)?;
        for statement in statements { let _ = sea_orm::sqlx::query(&statement).execute(&mut *transaction).await.map_err(sqlx_error)?; }
        let violations = sea_orm::sqlx::query("PRAGMA foreign_key_check").fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        if !violations.is_empty() { return Err(DbErr::Migration("Device migration would invalidate foreign-key relationships".to_owned())); }
        Ok(())
    }.await;
    match outcome {
        Ok(()) => transaction.commit().await.map_err(sqlx_error),
        Err(error) => {
            transaction.rollback().await.map_err(sqlx_error)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        SeaOrmStore, bundled_schema::BundledSchema, entities::device_code, migrator::AuthMigrator,
    };
    use better_auth_core::store::DeviceCodeStore;
    use better_auth_core::{AuthConfig, CreateDeviceCode};
    use chrono::Utc;
    use sea_orm::{Database, EntityTrait};

    #[tokio::test]
    async fn sqlite_upgrade_preserves_device_records_and_unconstrained_user_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        AuthMigrator::up(&database, Some(4)).await?;
        let now = Utc::now();
        let _ = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO users (id, email_verified, two_factor_enabled, banned, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec!["existing-user".into(), false.into(), false.into(), false.into(), serde_json::json!({}).into(), now.into(), now.into()]
        )).await?;
        // Recreate the installed table shape from before this migration.
        let _ = database
            .execute_unprepared("DROP TABLE device_code")
            .await?;
        let _ = database.execute_unprepared(
            "CREATE TABLE device_code (id TEXT PRIMARY KEY NOT NULL, device_code TEXT NOT NULL UNIQUE, user_code TEXT NOT NULL UNIQUE, user_id TEXT, expires_at TIMESTAMP NOT NULL, status TEXT NOT NULL, last_polled_at TIMESTAMP, polling_interval BIGINT, client_id TEXT, scope TEXT, CONSTRAINT fk_device_code_user_id FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"
        ).await?;
        for statement in [
            "CREATE INDEX idx_device_code_device_code ON device_code(device_code)",
            "CREATE INDEX idx_device_code_user_code ON device_code(user_code)",
            "CREATE INDEX idx_device_code_user_id ON device_code(user_id)",
            "CREATE INDEX idx_device_code_expires_at ON device_code(expires_at)",
            "ALTER TABLE device_code ADD COLUMN app_note TEXT DEFAULT 'installed' CHECK(app_note <> 'forbidden')",
            "ALTER TABLE device_code ADD COLUMN app_label TEXT GENERATED ALWAYS AS (client_id || ':' || app_note) VIRTUAL",
            "CREATE INDEX app_device_scope ON device_code(scope) WHERE scope IS NOT NULL",
            "CREATE TABLE device_audit (code_id TEXT)",
            "CREATE TRIGGER app_device_audit AFTER UPDATE ON device_code BEGIN INSERT INTO device_audit VALUES(NEW.id); END",
            "CREATE TABLE device_link (code_id TEXT REFERENCES device_code(id))",
            "CREATE VIEW app_devices AS SELECT id, app_note, app_label FROM device_code",
        ] {
            let _ = database.execute_unprepared(statement).await?;
        }
        let expiry = now + chrono::Duration::minutes(10);
        let _ = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO device_code (id, device_code, user_code, user_id, expires_at, status, last_polled_at, polling_interval, client_id, scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec!["existing-code".into(), "device-old".into(), "USEROLD".into(), "existing-user".into(), expiry.into(), "pending".into(), now.into(), 7_i64.into(), "client".into(), "openid profile".into()]
        )).await?;
        let _ = database
            .execute_unprepared("INSERT INTO device_link VALUES ('existing-code')")
            .await?;
        // Force failure after copying/dropping/recreating the table: the final
        // integrity check must reject an unrelated installed invalid reference.
        for statement in [
            "PRAGMA foreign_keys=OFF",
            "INSERT INTO device_link VALUES ('missing-code')",
            "PRAGMA foreign_keys=ON",
        ] {
            let _ = database.execute_unprepared(statement).await?;
        }
        let failure = AuthMigrator::up(&database, None)
            .await
            .expect_err("invalid installed relationship must roll back the replacement");
        assert!(
            failure
                .to_string()
                .contains("Device migration would invalidate foreign-key relationships")
        );
        let old_constraints = database
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA foreign_key_list('device_code')",
            ))
            .await?;
        assert_eq!(old_constraints.len(), 1);
        let preserved = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT app_note FROM app_devices WHERE id='existing-code'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("rollback lost installed device row/view"))?;
        assert_eq!(preserved.try_get::<String>("", "app_note")?, "installed");
        let temporary=database.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,"SELECT count(*) AS remaining FROM sqlite_schema WHERE name='device_code__user_reference'")).await?.ok_or_else(|| std::io::Error::other("missing schema count"))?;
        assert_eq!(temporary.try_get::<i64>("", "remaining")?, 0);
        let settings=database.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,"SELECT (SELECT foreign_keys FROM pragma_foreign_keys) AS fk, (SELECT legacy_alter_table FROM pragma_legacy_alter_table) AS legacy")).await?.ok_or_else(|| std::io::Error::other("missing connection settings"))?;
        assert_eq!(settings.try_get::<i64>("", "fk")?, 1);
        assert_eq!(settings.try_get::<i64>("", "legacy")?, 0);
        let _ = database
            .execute_unprepared("DELETE FROM device_link WHERE code_id='missing-code'")
            .await?;
        AuthMigrator::up(&database, None).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("device-reference-upgrade-local-secret-32-chars"),
            database,
        );
        let old = store
            .get_device_code_by_device_code("device-old")
            .await?
            .ok_or_else(|| std::io::Error::other("migration lost device code"))?;
        assert_eq!(old.user_id.as_deref(), Some("existing-user"));
        assert_eq!(old.last_polled_at, Some(now));
        assert_eq!(old.polling_interval, Some(7));
        assert_eq!(old.scope.as_deref(), Some("openid profile"));
        let projected = store
            .connection()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT app_note, app_label FROM app_devices WHERE id='existing-code'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("lost app device projection"))?;
        assert_eq!(projected.try_get::<String>("", "app_note")?, "installed");
        assert_eq!(
            projected.try_get::<String>("", "app_label")?,
            "client:installed"
        );
        assert!(
            store
                .connection()
                .execute_unprepared(
                    "UPDATE device_code SET app_note='forbidden' WHERE id='existing-code'"
                )
                .await
                .is_err()
        );
        let _ = store
            .connection()
            .execute_unprepared(
                "UPDATE device_code SET app_note='retained' WHERE id='existing-code'",
            )
            .await?;
        let audit = store
            .connection()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT code_id FROM device_audit",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("lost app trigger"))?;
        assert_eq!(audit.try_get::<String>("", "code_id")?, "existing-code");
        assert!(
            store
                .connection()
                .execute_unprepared("INSERT INTO device_link VALUES ('unknown-code')")
                .await
                .is_err()
        );

        let input = CreateDeviceCode {
            device_code: "device-new".to_owned(),
            user_code: "USERNEW".to_owned(),
            user_id: Some("nonexistent-user".to_owned()),
            expires_at: expiry,
            status: "pending".to_owned(),
            last_polled_at: None,
            polling_interval: Some(5),
            client_id: Some("client".to_owned()),
            scope: None,
        };
        assert!(store.create_device_code(input.clone()).await.is_ok());
        assert!(store.create_device_code(input).await.is_err());
        let _ = store
            .connection()
            .execute_unprepared("DELETE FROM users WHERE id = 'existing-user'")
            .await?;
        assert!(
            device_code::Entity::find_by_id("existing-code")
                .one(store.connection())
                .await?
                .is_some()
        );
        let foreign_keys = store
            .connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA foreign_key_list('device_code')",
            ))
            .await?;
        assert!(foreign_keys.is_empty());
        let indexes = store
            .connection()
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "PRAGMA index_list('device_code')",
            ))
            .await?;
        let names = indexes
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        for expected in [
            "idx_device_code_device_code",
            "idx_device_code_user_code",
            "idx_device_code_user_id",
            "idx_device_code_expires_at",
            "app_device_scope",
        ] {
            assert!(names.iter().any(|name| name == expected));
        }
        Ok(())
    }
}
