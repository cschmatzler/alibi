//! Apply bundled migrations using the shared migration ledger.

use crate::pool::{Engine, Exec, SqlxPool};
use crate::sql::Sql;
use alibi_core::config::AuthConfig;
use alibi_core::error::{AuthError, AuthResult, DatabaseError};
use alibi_schema_registry::{AUTH_MIGRATION_LEDGER, AUTH_MIGRATIONS, BundledMigration};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Apply the bundled auth schema.
///
/// # Errors
///
/// Returns the database error; a failed migration is rolled back and not recorded.
pub async fn run_migrations(pool: &SqlxPool) -> AuthResult<()> {
    apply(pool, AUTH_MIGRATION_LEDGER, AUTH_MIGRATIONS).await
}

/// Apply pending migrations in order, each in its own transaction with its
/// ledger row. Ledger rows naming unknown migrations fail before any change.
pub(crate) async fn apply(
    pool: &SqlxPool,
    ledger: &'static str,
    migrations: &[BundledMigration],
) -> AuthResult<()> {
    apply_scoped(pool, ledger, migrations, None).await
}

pub(crate) async fn run_migrations_scoped(
    pool: &SqlxPool,
    config: &Arc<AuthConfig>,
) -> AuthResult<()> {
    apply_scoped(pool, AUTH_MIGRATION_LEDGER, AUTH_MIGRATIONS, Some(config)).await
}

async fn apply_scoped(
    pool: &SqlxPool,
    ledger: &'static str,
    migrations: &[BundledMigration],
    config: Option<&Arc<AuthConfig>>,
) -> AuthResult<()> {
    let mut exec = Exec::pool(pool);
    if let Some(config) = config {
        if pool.engine() == Engine::Postgres
            && let Some(schema) = &config.advanced.database.schema_name
        {
            let mut create = Sql::with(pool.engine(), "CREATE SCHEMA IF NOT EXISTS ");
            create.ident(schema);
            _ = exec.execute(create).await?;
        }
        exec = exec.with_config(config.as_ref());
    }
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
        let mut transaction = pool.begin(false).await?;
        transaction.config = config.cloned();
        let exec = Exec::tx(&transaction);
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
        Engine::Postgres => {
            sql.push("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ");
            if let Some(schema) = exec.schema_name() {
                sql.bind(schema);
            } else {
                sql.push("CURRENT_SCHEMA()");
            }
            sql.push(" AND table_type = 'BASE TABLE' AND table_name = ");
        }
    }
    sql.bind(table);
    Ok(exec.fetch_scalar::<i64>(sql).await?.unwrap_or_default() > 0)
}

pub(crate) async fn has_column(exec: Exec<'_>, table: &str, column: &str) -> AuthResult<bool> {
    let mut sql = Sql::new(exec.engine());
    match exec.engine() {
        Engine::Sqlite => {
            sql.push("SELECT COUNT(*) FROM pragma_table_info(");
            sql.bind(table);
            sql.push(") WHERE name = ");
        }
        Engine::Postgres => {
            sql.push("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = ");
            if let Some(schema) = exec.schema_name() {
                sql.bind(schema);
            } else {
                sql.push("CURRENT_SCHEMA()");
            }
            sql.push(" AND table_name = ");
            sql.bind(table);
            sql.push(" AND column_name = ");
        }
    }
    sql.bind(column);
    Ok(exec.fetch_scalar::<i64>(sql).await?.unwrap_or_default() > 0)
}
