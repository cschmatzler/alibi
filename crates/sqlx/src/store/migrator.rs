//! The bundled auth schema as one migration, in the ledger `SeaORM` also uses.

use crate::pool::{Engine, Exec, SqlxPool};
use crate::sql::Sql;
use better_auth_core::error::{AuthError, AuthResult, DatabaseError};
use std::time::{SystemTime, UNIX_EPOCH};

/// One named schema change, as SQL for each backend.
pub(crate) struct Migration {
    pub(crate) name: &'static str,
    pub(crate) sqlite: &'static str,
    pub(crate) postgres: &'static str,
}

const AUTH_SCHEMA: Migration = Migration {
    name: "m20261003_000001_auth_schema",
    sqlite: include_str!("../../migrations/sqlite.sql"),
    postgres: include_str!("../../migrations/postgres.sql"),
};

/// Apply the bundled auth schema.
///
/// # Errors
///
/// Returns the database error; a failed migration is rolled back and not recorded.
pub async fn run_migrations(pool: &SqlxPool) -> AuthResult<()> {
    apply(pool, "better_auth_migrations", &[AUTH_SCHEMA]).await
}

/// Apply pending migrations in order, each in its own transaction with its
/// ledger row. Ledger rows naming unknown migrations fail before any change.
pub(crate) async fn apply(
    pool: &SqlxPool,
    ledger: &'static str,
    migrations: &[Migration],
) -> AuthResult<()> {
    let exec = Exec::Pool(pool);
    let backend = pool.engine();
    let applied_at = match backend {
        Engine::Sqlite => "integer",
        Engine::Postgres => "bigint",
    };
    let mut install = Sql::with(backend, "CREATE TABLE IF NOT EXISTS ");
    install.ident(ledger);
    install.push(" ( \"version\" varchar NOT NULL PRIMARY KEY, \"applied_at\" ");
    install.push(applied_at);
    install.push(" NOT NULL )");
    _ = exec.execute(install).await?;

    let mut select = Sql::with(backend, "SELECT \"version\" FROM ");
    select.ident(ledger);
    select.push(" ORDER BY \"version\" ASC");
    let applied: Vec<String> = exec.fetch_all_scalar(select).await?;
    let missing: Vec<String> = applied
        .iter()
        .filter(|version| !migrations.iter().any(|migration| migration.name == *version))
        .map(|version| {
            format!("Migration file of version '{version}' is missing, this migration has been applied but its file is missing")
        })
        .collect();
    if !missing.is_empty() {
        return Err(AuthError::Database(DatabaseError::Query(format!(
            "Custom Error: {}",
            missing.join("\n")
        ))));
    }

    for migration in migrations
        .iter()
        .filter(|migration| !applied.iter().any(|version| version == migration.name))
    {
        let transaction = pool.begin(false).await?;
        let exec = Exec::Tx(&transaction);
        exec.execute_script(match backend {
            Engine::Sqlite => migration.sqlite,
            Engine::Postgres => migration.postgres,
        })
        .await?;
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_error| AuthError::internal("System time is before the Unix epoch"))?
            .as_secs();
        let mut record = Sql::with(backend, "INSERT INTO ");
        record.ident(ledger);
        record.push(" (\"version\", \"applied_at\") VALUES (");
        record.bind(migration.name);
        record.push(", ");
        record.bind(i64::try_from(applied_at).unwrap_or(i64::MAX));
        record.push(")");
        _ = exec.execute(record).await?;
        transaction.commit().await?;
    }
    Ok(())
}

/// Whether a base table exists in the current schema.
pub(crate) async fn has_table(exec: Exec<'_>, table: &str) -> AuthResult<bool> {
    let mut sql = Sql::new(exec.engine());
    match exec.engine() {
        Engine::Sqlite => sql.push(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name <> 'sqlite_sequence' AND name = ",
        ),
        Engine::Postgres => sql.push(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_type = 'BASE TABLE' AND table_name = ",
        ),
    };
    sql.bind(table);
    Ok(exec.fetch_scalar::<i64>(sql).await?.unwrap_or_default() > 0)
}
