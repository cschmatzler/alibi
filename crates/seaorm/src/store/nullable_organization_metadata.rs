//! Preserve SQL NULL organization metadata in fresh and installed schemas.

use super::nullable_user_flags::sql_tokens;
use sea_orm::sqlx::{Connection, Row, SqliteConnection};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseExecutor};
use sea_orm_migration::prelude::*;
use std::collections::BTreeSet;

pub(super) struct NullableOrganizationMetadata;

impl MigrationName for NullableOrganizationMetadata {
    fn name(&self) -> &'static str {
        "m20260930_000013_nullable_organization_metadata"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for NullableOrganizationMetadata {
    // SQLite foreign_keys can only change outside a transaction. The rebuild
    // starts its own transaction after pinning and configuring one connection.
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Sqlite => rebuild_sqlite_organization(manager).await,
            DatabaseBackend::Postgres => {
                if manager.has_column("organization", "metadata").await? {
                    let _ignored_execute_unprepared = manager
                        .get_connection()
                        .execute_unprepared(
                            "ALTER TABLE \"organization\" ALTER COLUMN \"metadata\" DROP NOT NULL",
                        )
                        .await?;
                }
                Ok(())
            }
            DatabaseBackend::MySql | _ => Err(DbErr::Migration(
                "Nullable organization metadata requires SQLite or PostgreSQL".to_owned(),
            )),
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
fn sqlx_error(error: sea_orm::sqlx::Error) -> DbErr {
    DbErr::Migration(format!("Nullable organization metadata: {error}"))
}

async fn rebuild_sqlite_organization(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let DatabaseExecutor::Connection(database) = manager.get_connection() else {
        return Err(DbErr::Migration(
            "Nullable SQLite organization metadata must be migrated outside an existing transaction"
                .to_owned(),
        ));
    };
    let mut connection = database
        .get_sqlite_connection_pool()
        .acquire()
        .await
        .map_err(sqlx_error)?;
    let columns = sea_orm::sqlx::query("PRAGMA table_xinfo(\"organization\")")
        .fetch_all(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let needs_rebuild = columns.iter().any(|row| {
        let name: String = row.get("name");
        name.eq_ignore_ascii_case("metadata") && row.get::<i64, _>("notnull") != 0
    });
    if !needs_rebuild {
        return Ok(());
    }
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
    let _ignored_map_err = sea_orm::sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    // Existing views temporarily refer to the dropped name inside this
    // transaction. Legacy rename validation leaves those definitions intact
    // until the replacement restores that same name.
    let _ignored_map_err_2 = sea_orm::sqlx::query("PRAGMA legacy_alter_table = ON")
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let result = rebuild_organization_transaction(&mut connection).await;
    let _ignored_map_err_3 = sea_orm::sqlx::query(&format!("PRAGMA foreign_keys = {foreign_keys}"))
        .execute(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let _ignored_map_err_4 =
        sea_orm::sqlx::query(&format!("PRAGMA legacy_alter_table = {legacy_alter_table}"))
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

#[expect(
    clippy::string_slice,
    reason = "SQL lexer ranges end at ASCII delimiters or input boundaries and retain UTF-8 token boundaries"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep SQLite table replacement and preservation of indexes and triggers in one transaction"
)]
async fn rebuild_organization_transaction(connection: &mut SqliteConnection) -> Result<(), DbErr> {
    let mut transaction = connection.begin().await.map_err(sqlx_error)?;
    let result = async {
        let sql: String = sea_orm::sqlx::query_scalar(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'organization'",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let statements: Vec<String> = sea_orm::sqlx::query_scalar(
            "SELECT sql FROM sqlite_schema WHERE tbl_name = 'organization' AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY type, name",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let columns = sea_orm::sqlx::query("PRAGMA table_xinfo(\"organization\")")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        let sequence_exists: bool = sea_orm::sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'sqlite_sequence')",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let previous_sequence: Option<i64> = if sequence_exists {
            sea_orm::sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'organization'")
                .fetch_optional(&mut *transaction)
                .await
                .map_err(sqlx_error)?
        } else {
            None
        };
        // Generated columns are reproduced in the original DDL; inserting
        // into them is forbidden. All ordinary custom columns are copied.
        let mut copied_columns = columns
            .iter()
            .filter(|row| row.get::<i64, _>("hidden") == 0)
            .map(|row| quote_identifier(&row.get::<String, _>("name")))
            .collect::<Vec<_>>();
        let rewritten = nullable_organization_ddl(&sql)?;
        let table_body = sql_tokens(&sql)?
            .into_iter()
            .find(|span| sql[span.clone()].starts_with('('))
            .ok_or_else(|| DbErr::Migration("Unable to locate organization columns".to_owned()))?;
        let without_rowid = sql_tokens(&sql[table_body.end..])?
            .windows(2)
            .any(|tokens| {
                let suffix = &sql[table_body.end..];
                matches!(tokens, [without, rowid] if suffix[without.clone()].eq_ignore_ascii_case("WITHOUT") && suffix[rowid.clone()].eq_ignore_ascii_case("ROWID"))
            });
        // Preserve hidden row identity, including gaps left by deletions.
        // An INTEGER PRIMARY KEY alias has the same value in both copied
        // columns. WITHOUT ROWID tables have no hidden identity to copy.
        if !without_rowid
            && let Some(alias) = ["rowid", "_rowid_", "oid"].into_iter().find(|alias| {
                !columns.iter().any(|column| {
                    column.get::<String, _>("name").eq_ignore_ascii_case(alias)
                })
            }) {
                copied_columns.insert(0, quote_identifier(alias));
        }
        let copied_columns = copied_columns.join(", ");
        let _ignored_map_err_5 = sea_orm::sqlx::query(&rewritten)
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        let _ignored_map_err_6 = sea_orm::sqlx::query(&format!(
            "INSERT INTO \"organization__nullable_metadata\" ({copied_columns}) SELECT {copied_columns} FROM \"organization\""
        ))
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let _ignored_map_err_7 = sea_orm::sqlx::query("DROP TABLE \"organization\"")
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        let _ignored_map_err_8 = sea_orm::sqlx::query(
            "ALTER TABLE \"organization__nullable_metadata\" RENAME TO \"organization\"",
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        if let Some(previous_sequence) = previous_sequence {
            let updated = sea_orm::sqlx::query(
                "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = 'organization'",
            )
            .bind(previous_sequence)
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
            if updated.rows_affected() == 0 {
                let _ignored_map_err_9 = sea_orm::sqlx::query(
                    "INSERT INTO sqlite_sequence (name, seq) VALUES ('organization', ?)",
                )
                .bind(previous_sequence)
                .execute(&mut *transaction)
                .await
                .map_err(sqlx_error)?;
            }
        }
        for sql_2 in statements {
            let _ignored_map_err_10 = sea_orm::sqlx::query(&sql_2)
                .execute(&mut *transaction)
                .await
                .map_err(sqlx_error)?;
        }
        let violations = sea_orm::sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        if !violations.is_empty() {
            return Err(DbErr::Migration(
                "Nullable organization metadata migration would leave invalid foreign-key relationships"
                    .to_owned(),
            ));
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => transaction.commit().await.map_err(sqlx_error),
        Err(error) => {
            transaction.rollback().await.map_err(sqlx_error)?;
            Err(error)
        }
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[expect(
    clippy::string_slice,
    reason = "SQL lexer ranges end at ASCII delimiters or input boundaries and retain UTF-8 token boundaries"
)]
fn nullable_organization_ddl(sql: &str) -> Result<String, DbErr> {
    let tokens = sql_tokens(sql)?;
    let body = tokens
        .iter()
        .find(|span| sql[(**span).clone()].starts_with('('))
        .ok_or_else(|| {
            DbErr::Migration("Unable to locate organization table columns".to_owned())
        })?;
    let columns = &sql[body.start + 1..body.end - 1];
    let mut definitions = Vec::new();
    let mut start = 0;
    for span in sql_tokens(columns)? {
        if &columns[span.clone()] == "," {
            definitions.push(nullable_column(&columns[start..span.start])?);
            start = span.end;
        }
    }
    definitions.push(nullable_column(&columns[start..])?);
    Ok(format!(
        "CREATE TABLE \"organization__nullable_metadata\" ({}){}",
        definitions.join(","),
        &sql[body.end..]
    ))
}

#[expect(
    clippy::string_slice,
    reason = "SQL lexer ranges end at ASCII delimiters or input boundaries and retain UTF-8 token boundaries"
)]
fn nullable_column(definition: &str) -> Result<String, DbErr> {
    let tokens = sql_tokens(definition)?;
    let Some(name) = tokens.first() else {
        return Ok(definition.to_owned());
    };
    let name = definition[name.clone()].trim_matches(['"', '\'', '`', '[', ']']);
    if !name.eq_ignore_ascii_case("metadata") {
        return Ok(definition.to_owned());
    }
    let mut removed = BTreeSet::new();
    for (index, span) in tokens.iter().enumerate().skip(1) {
        if definition[span.clone()].eq_ignore_ascii_case("NOT")
            && tokens
                .get(index + 1)
                .is_some_and(|span_2| definition[span_2.clone()].eq_ignore_ascii_case("NULL"))
        {
            let _ignored_insert = removed.insert(index);
            let _ignored_insert_2 = removed.insert(index + 1);
            if tokens
                .get(index + 2)
                .is_some_and(|span_3| definition[span_3.clone()].eq_ignore_ascii_case("ON"))
                && tokens.get(index + 3).is_some_and(|span_4| {
                    definition[span_4.clone()].eq_ignore_ascii_case("CONFLICT")
                })
            {
                if tokens.get(index + 4).is_none() {
                    return Err(DbErr::Migration(
                        "Incomplete metadata NOT NULL conflict rule".to_owned(),
                    ));
                }
                let _ignored_insert_3 = removed.insert(index + 2);
                let _ignored_insert_4 = removed.insert(index + 3);
                let _ignored_insert_5 = removed.insert(index + 4);
            }
            if let Some(constraint) = index.checked_sub(2).and_then(|index| tokens.get(index))
                && definition[constraint.clone()].eq_ignore_ascii_case("CONSTRAINT")
            {
                let _ignored_insert_6 = removed.insert(index - 2);
                let _ignored_insert_7 = removed.insert(index - 1);
            }
        }
    }
    let mut output = String::new();
    let mut cursor = 0;
    for (index, span) in tokens.iter().enumerate() {
        output.push_str(&definition[cursor..span.start]);
        if !removed.contains(&index) {
            output.push_str(&definition[span.clone()]);
        }
        cursor = span.end;
    }
    output.push_str(&definition[cursor..]);
    Ok(output)
}
