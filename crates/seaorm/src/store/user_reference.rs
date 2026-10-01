//! Preserve installed application schemas while removing named auth references.
//!
//! Table and constraint names come exclusively from this closed enum; row values
//! use SQL bindings. The shared implementation retains cancellation and rollback
//! protection for every supported auth table.

use super::nullable_user_flags::sql_tokens;
use sea_orm::sqlx::{Connection, Row, SqliteConnection};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseExecutor, Statement};
use sea_orm_migration::prelude::*;

#[derive(Clone, Copy)]
pub(super) enum AuthReference {
    DeviceCode,
    TwoFactor,
    TeamOrganization,
    OrganizationRoleOrganization,
}
impl AuthReference {
    const fn table(self) -> &'static str {
        match self {
            Self::DeviceCode => "device_code",
            Self::TwoFactor => "two_factor",
            Self::TeamOrganization => "team",
            Self::OrganizationRoleOrganization => "organization_role",
        }
    }
    const fn column(self) -> &'static str {
        match self {
            Self::DeviceCode | Self::TwoFactor => "user_id",
            Self::TeamOrganization | Self::OrganizationRoleOrganization => "organization_id",
        }
    }
    const fn parent(self) -> &'static str {
        match self {
            Self::DeviceCode | Self::TwoFactor => "users",
            Self::TeamOrganization | Self::OrganizationRoleOrganization => "organization",
        }
    }
    const fn constraint(self) -> &'static str {
        match self {
            Self::DeviceCode => "fk_device_code_user_id",
            Self::TwoFactor => "fk_two_factor_user_id",
            Self::TeamOrganization => "fk_team_organization",
            Self::OrganizationRoleOrganization => "fk_organization_role_organization",
        }
    }
    const fn label(self) -> &'static str {
        match self {
            Self::DeviceCode => "Device",
            Self::TwoFactor => "Two-factor",
            Self::TeamOrganization => "Organization team",
            Self::OrganizationRoleOrganization => "Organization role",
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "DatabaseBackend is non-exhaustive; unsupported backends must return a migration error"
)]
pub(super) async fn remove_auth_references(
    manager: &SchemaManager<'_>,
    targets: &[AuthReference],
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    match connection.get_database_backend() {
        DatabaseBackend::Postgres => {
            use sea_orm::TransactionTrait;
            let DatabaseExecutor::Connection(database) = connection else {
                return Err(DbErr::Migration(
                    "Auth references must be migrated outside an existing transaction".into(),
                ));
            };
            let transaction = database.begin().await?;
            for target in targets {
                let _ignored_constraint = transaction
                    .execute_unprepared(&format!(
                        "ALTER TABLE {} DROP CONSTRAINT IF EXISTS {}",
                        target.table(),
                        target.constraint()
                    ))
                    .await?;
            }
            transaction.commit().await?;
            Ok(())
        }
        DatabaseBackend::Sqlite => {
            let mut found = Vec::new();
            for target in targets {
                let rows = connection
                    .query_all_raw(Statement::from_string(
                        DatabaseBackend::Sqlite,
                        format!("PRAGMA foreign_key_list('{}')", target.table()),
                    ))
                    .await?;
                for row in rows {
                    if row.try_get::<String>("", "from")? == target.column()
                        && row.try_get::<String>("", "table")? == target.parent()
                    {
                        found.push(*target);
                        break;
                    }
                }
            }
            if found.is_empty() {
                return Ok(());
            }
            rebuild_sqlite_references(manager, &found).await
        }
        backend => Err(DbErr::Custom(format!(
            "auth reference migration does not support {backend:?}"
        ))),
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
fn sqlx_error(error: sea_orm::sqlx::Error) -> DbErr {
    DbErr::Migration(format!("Auth user reference: {error}"))
}

async fn rebuild_sqlite_references(
    manager: &SchemaManager<'_>,
    targets: &[AuthReference],
) -> Result<(), DbErr> {
    let DatabaseExecutor::Connection(database) = manager.get_connection() else {
        return Err(DbErr::Migration(
            "SQLite auth user references must be migrated outside an existing transaction"
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
    let result = rebuild_reference_transaction(&mut connection, targets).await;
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
async fn rebuild_reference_transaction(
    connection: &mut SqliteConnection,
    targets: &[AuthReference],
) -> Result<(), DbErr> {
    let mut transaction = connection.begin().await.map_err(sqlx_error)?;
    let outcome = async {
      for target in targets {
        let table = target.table();
        let temporary = format!("{table}__user_reference");
        let sql: String = sea_orm::sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?").bind(table).fetch_one(&mut *transaction).await.map_err(sqlx_error)?;
        let statements: Vec<String> = sea_orm::sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE tbl_name=? AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name").bind(table).fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        let body = sql_tokens(&sql)?.into_iter().find(|span| sql[span.clone()].starts_with('(')).ok_or_else(|| DbErr::Migration("Missing auth table definition".to_owned()))?;
        let definitions = &sql[body.start+1..body.end-1];
        let mut kept = Vec::new();
        let mut start = 0;
        let mut removed = 0;
        for end in sql_tokens(definitions)?.into_iter().filter(|span| &definitions[span.clone()] == ",").map(|span| (span.start,span.end)).chain(std::iter::once((definitions.len(),definitions.len()))) {
            let definition = &definitions[start..end.0];
            let tokens = sql_tokens(definition)?;
            let target = matches!(tokens.as_slice(), [constraint,name,foreign,key,columns,references,parent,..]
                if definition[constraint.clone()].eq_ignore_ascii_case("CONSTRAINT")
                && definition[name.clone()].trim_matches(['\"','\'','`','[',']']).eq_ignore_ascii_case(target.constraint())
                && definition[foreign.clone()].eq_ignore_ascii_case("FOREIGN")
                && definition[key.clone()].eq_ignore_ascii_case("KEY")
                && definition[columns.clone()].trim().trim_matches(['(',')',' ','\"','\'','`','[',']']).eq_ignore_ascii_case(target.column())
                && definition[references.clone()].eq_ignore_ascii_case("REFERENCES")
                && definition[parent.clone()].trim_matches(['\"','\'','`','[',']']).eq_ignore_ascii_case(target.parent()));
            if target { removed += 1; } else { kept.push(definition); }
            start = end.1;
        }
        if removed != 1 { return Err(DbErr::Migration("Unable to safely remove the installed auth user constraint".to_owned())); }
        let rewritten = format!("CREATE TABLE \"{temporary}\" ({}){}", kept.join(","), &sql[body.end..]);
        let columns = sea_orm::sqlx::query(&format!("PRAGMA table_xinfo(\"{table}\")")).fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        let mut copied = columns.iter().filter(|row| row.get::<i64,_>("hidden") == 0).map(|row| format!("\"{}\"",row.get::<String,_>("name").replace('\"',"\"\""))).collect::<Vec<_>>();
        let suffix = &sql[body.end..];
        let without_rowid = sql_tokens(suffix)?.windows(2).any(|pair| matches!(pair, [without,rowid] if suffix[without.clone()].eq_ignore_ascii_case("WITHOUT") && suffix[rowid.clone()].eq_ignore_ascii_case("ROWID")));
        if !without_rowid && let Some(alias) = ["rowid","_rowid_","oid"].into_iter().find(|alias| !columns.iter().any(|row| row.get::<String,_>("name").eq_ignore_ascii_case(alias))) { copied.insert(0,format!("\"{alias}\"")); }
        let copied = copied.join(",");
        let _ignored_map_err_5 = sea_orm::sqlx::query(&rewritten).execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ignored_map_err_6 = sea_orm::sqlx::query(&format!("INSERT INTO \"{temporary}\" ({copied}) SELECT {copied} FROM \"{table}\"")).execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ignored_map_err_7 = sea_orm::sqlx::query(&format!("DROP TABLE \"{table}\"")).execute(&mut *transaction).await.map_err(sqlx_error)?;
        let _ignored_map_err_8 = sea_orm::sqlx::query(&format!("ALTER TABLE \"{temporary}\" RENAME TO \"{table}\"")).execute(&mut *transaction).await.map_err(sqlx_error)?;
        for statement in statements { let _ignored_map_err_9 = sea_orm::sqlx::query(&statement).execute(&mut *transaction).await.map_err(sqlx_error)?; }
      }
        let violations = sea_orm::sqlx::query("PRAGMA foreign_key_check").fetch_all(&mut *transaction).await.map_err(sqlx_error)?;
        if !violations.is_empty() { return Err(DbErr::Migration(format!("{} migration would invalidate foreign-key relationships",targets.first().map_or("Auth", |target| target.label())))); }
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
