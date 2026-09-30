//! Preserve unset admin/two-factor state in fresh and installed user tables.

use sea_orm::sqlx::{Connection, Row, SqliteConnection};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseExecutor};
use sea_orm_migration::prelude::*;
use std::collections::BTreeSet;
use std::ops::Range;

pub(super) struct NullableUserPluginFlags;

impl MigrationName for NullableUserPluginFlags {
    fn name(&self) -> &str {
        "m20260930_000005_nullable_user_plugin_flags"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for NullableUserPluginFlags {
    // SQLite foreign_keys can only change outside a transaction. The rebuild
    // starts its own transaction after pinning and configuring one connection.
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Sqlite => rebuild_sqlite_users(manager).await,
            DatabaseBackend::Postgres => {
                let mut clauses = Vec::new();
                for column in ["two_factor_enabled", "banned"] {
                    if manager.has_column("users", column).await? {
                        clauses.push(format!("ALTER COLUMN \"{column}\" DROP NOT NULL"));
                        clauses.push(format!("ALTER COLUMN \"{column}\" DROP DEFAULT"));
                    }
                }
                if !clauses.is_empty() {
                    let _ = manager
                        .get_connection()
                        .execute_unprepared(&format!(
                            "ALTER TABLE \"users\" {}",
                            clauses.join(", ")
                        ))
                        .await?;
                }
                Ok(())
            }
            _ => Err(DbErr::Migration(
                "Nullable user plugin fields require SQLite or PostgreSQL".to_owned(),
            )),
        }
    }
}

fn sqlx_error(error: sea_orm::sqlx::Error) -> DbErr {
    DbErr::Migration(format!("Nullable user plugin fields: {error}"))
}

async fn rebuild_sqlite_users(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let DatabaseExecutor::Connection(database) = manager.get_connection() else {
        return Err(DbErr::Migration(
            "Nullable SQLite user fields must be migrated outside an existing transaction"
                .to_owned(),
        ));
    };
    let mut connection = database
        .get_sqlite_connection_pool()
        .acquire()
        .await
        .map_err(sqlx_error)?;
    let columns = sea_orm::sqlx::query("PRAGMA table_xinfo(\"users\")")
        .fetch_all(&mut *connection)
        .await
        .map_err(sqlx_error)?;
    let needs_rebuild = columns.iter().any(|row| {
        let name: String = row.get("name");
        ["two_factor_enabled", "banned"].contains(&name.as_str())
            && (row.get::<i64, _>("notnull") != 0
                || row.get::<Option<String>, _>("dflt_value").is_some())
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
    let result = rebuild_users_transaction(&mut connection).await;
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

async fn rebuild_users_transaction(connection: &mut SqliteConnection) -> Result<(), DbErr> {
    let mut transaction = connection.begin().await.map_err(sqlx_error)?;
    let result = async {
        let sql: String = sea_orm::sqlx::query_scalar(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'users'",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let statements: Vec<String> = sea_orm::sqlx::query_scalar(
            "SELECT sql FROM sqlite_schema WHERE tbl_name = 'users' AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY type, name",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let columns = sea_orm::sqlx::query("PRAGMA table_xinfo(\"users\")")
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
            sea_orm::sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'users'")
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
        let rewritten = nullable_users_ddl(&sql)?;
        let table_body = sql_tokens(&sql)?
            .into_iter()
            .find(|span| sql[span.clone()].starts_with('('))
            .ok_or_else(|| DbErr::Migration("Unable to locate users columns".to_owned()))?;
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
        let _ = sea_orm::sqlx::query(&rewritten)
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query(&format!(
            "INSERT INTO \"users__nullable_plugin_flags\" ({copied_columns}) SELECT {copied_columns} FROM \"users\""
        ))
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query("DROP TABLE \"users\"")
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
        let _ = sea_orm::sqlx::query(
            "ALTER TABLE \"users__nullable_plugin_flags\" RENAME TO \"users\"",
        )
        .execute(&mut *transaction)
        .await
        .map_err(sqlx_error)?;
        if let Some(previous_sequence) = previous_sequence {
            let updated = sea_orm::sqlx::query(
                "UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = 'users'",
            )
            .bind(previous_sequence)
            .execute(&mut *transaction)
            .await
            .map_err(sqlx_error)?;
            if updated.rows_affected() == 0 {
                let _ = sea_orm::sqlx::query(
                    "INSERT INTO sqlite_sequence (name, seq) VALUES ('users', ?)",
                )
                .bind(previous_sequence)
                .execute(&mut *transaction)
                .await
                .map_err(sqlx_error)?;
            }
        }
        for sql in statements {
            let _ = sea_orm::sqlx::query(&sql)
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
                "Nullable user migration would leave invalid foreign-key relationships"
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

fn nullable_users_ddl(sql: &str) -> Result<String, DbErr> {
    let tokens = sql_tokens(sql)?;
    let body = tokens
        .iter()
        .find(|span| sql[(**span).clone()].starts_with('('))
        .ok_or_else(|| DbErr::Migration("Unable to locate users table columns".to_owned()))?;
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
        "CREATE TABLE \"users__nullable_plugin_flags\" ({}){}",
        definitions.join(","),
        &sql[body.end..]
    ))
}

fn nullable_column(definition: &str) -> Result<String, DbErr> {
    let tokens = sql_tokens(definition)?;
    let Some(name) = tokens.first() else {
        return Ok(definition.to_owned());
    };
    let name = definition[name.clone()].trim_matches(['"', '\'', '`', '[', ']']);
    if !["two_factor_enabled", "banned"].contains(&name.to_ascii_lowercase().as_str()) {
        return Ok(definition.to_owned());
    }
    let mut removed = BTreeSet::new();
    for (index, span) in tokens.iter().enumerate().skip(1) {
        let token = &definition[span.clone()];
        let removes_constraint = token.eq_ignore_ascii_case("DEFAULT")
            || (token.eq_ignore_ascii_case("NOT")
                && tokens
                    .get(index + 1)
                    .is_some_and(|span| definition[span.clone()].eq_ignore_ascii_case("NULL")));
        if removes_constraint {
            let Some(_) = tokens.get(index + 1) else {
                return Err(DbErr::Migration(
                    "Incomplete user column constraint".to_owned(),
                ));
            };
            let _ = removed.insert(index);
            let _ = removed.insert(index + 1);
            if token.eq_ignore_ascii_case("NOT")
                && tokens
                    .get(index + 2)
                    .is_some_and(|span| definition[span.clone()].eq_ignore_ascii_case("ON"))
                && tokens
                    .get(index + 3)
                    .is_some_and(|span| definition[span.clone()].eq_ignore_ascii_case("CONFLICT"))
            {
                if tokens.get(index + 4).is_none() {
                    return Err(DbErr::Migration(
                        "Incomplete NOT NULL conflict rule".to_owned(),
                    ));
                }
                let _ = removed.insert(index + 2);
                let _ = removed.insert(index + 3);
                let _ = removed.insert(index + 4);
            }
            if token.eq_ignore_ascii_case("DEFAULT")
                && tokens
                    .get(index + 1)
                    .is_some_and(|span| matches!(&definition[span.clone()], "+" | "-"))
            {
                if tokens.get(index + 2).is_none() {
                    return Err(DbErr::Migration(
                        "Incomplete signed user default".to_owned(),
                    ));
                }
                let _ = removed.insert(index + 2);
            }
            if let Some(constraint) = index.checked_sub(2).and_then(|index| tokens.get(index))
                && definition[constraint.clone()].eq_ignore_ascii_case("CONSTRAINT")
            {
                let _ = removed.insert(index - 2);
                let _ = removed.insert(index - 1);
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

// Return top-level SQL tokens, keeping quoted values and parenthesized
// expressions intact. This preserves custom CHECKs, generated columns,
// quoted commas and table constraints rather than reconstructing a schema
// from only the bundled entity's known fields.
fn sql_tokens(sql: &str) -> Result<Vec<Range<usize>>, DbErr> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while let Some(byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if let Some(end) = sql_comment_end(bytes, cursor)? {
            cursor = end;
            continue;
        }
        let start = cursor;
        let mut depth = 0_u32;
        let mut quote = None;
        while let Some(&byte) = bytes.get(cursor) {
            if let Some(end_quote) = quote {
                if byte == end_quote {
                    if bytes.get(cursor + 1) == Some(&end_quote) {
                        cursor += 2;
                        continue;
                    }
                    quote = None;
                }
                cursor += 1;
                if quote.is_none() && depth == 0 {
                    break;
                }
                continue;
            }
            if let Some(end) = sql_comment_end(bytes, cursor)? {
                if depth == 0 && cursor > start {
                    break;
                }
                cursor = end;
                continue;
            }
            if matches!(byte, b'\'' | b'"' | b'`' | b'[') {
                quote = Some(if byte == b'[' { b']' } else { byte });
                cursor += 1;
            } else if byte == b'(' {
                if depth == 0 && cursor > start {
                    break;
                }
                depth += 1;
                cursor += 1;
            } else if byte == b')' {
                depth = depth.checked_sub(1).ok_or_else(|| {
                    DbErr::Migration("Unbalanced user table definition".to_owned())
                })?;
                cursor += 1;
                if depth == 0 {
                    break;
                }
            } else if depth == 0
                && (byte.is_ascii_whitespace()
                    || byte == b','
                    || (matches!(byte, b'+' | b'-')
                        && (cursor == start
                            || bytes.get(start).is_some_and(u8::is_ascii_alphabetic))))
            {
                if cursor == start {
                    cursor += 1;
                }
                break;
            } else {
                cursor += 1;
            }
        }
        if quote.is_some() || depth != 0 {
            return Err(DbErr::Migration(
                "Unbalanced user table definition".to_owned(),
            ));
        }
        tokens.push(start..cursor);
    }
    Ok(tokens)
}

fn sql_comment_end(bytes: &[u8], cursor: usize) -> Result<Option<usize>, DbErr> {
    let tail = bytes
        .get(cursor..)
        .ok_or_else(|| DbErr::Migration("Invalid user SQL cursor".to_owned()))?;
    if tail.starts_with(b"--") {
        return Ok(Some(
            tail.iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| cursor + offset + 1),
        ));
    }
    if tail.starts_with(b"/*") {
        return tail
            .get(2..)
            .ok_or_else(|| DbErr::Migration("Invalid SQL comment".to_owned()))?
            .windows(2)
            .position(|window| window == b"*/")
            .map(|offset| Some(cursor + offset + 4))
            .ok_or_else(|| DbErr::Migration("Unclosed user table SQL comment".to_owned()));
    }
    Ok(None)
}
