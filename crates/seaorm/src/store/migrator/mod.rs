//! Bundled migrations compiled from the pinned Better Auth TypeScript schema.
use sea_orm::ConnectionTrait;
use sea_orm::sea_query::IntoIden;
use sea_orm_migration::prelude::*;
#[derive(Debug)]
pub struct AuthMigrator;
#[async_trait::async_trait]
impl MigratorTrait for AuthMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(AuthSchemaMigration),
            Box::new(OAuthClientsMigration),
        ]
    }
    fn migration_table_name() -> DynIden {
        "better_auth_migrations".into_iden()
    }
}
/// # Errors
/// Returns database or migration failures.
pub async fn run_migrations(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    AuthMigrator::up(db, None).await
}
struct AuthSchemaMigration;
impl MigrationName for AuthSchemaMigration {
    fn name(&self) -> &'static str {
        "m20261013_000001_typescript_auth_schema"
    }
}
struct OAuthClientsMigration;
impl MigrationName for OAuthClientsMigration {
    fn name(&self) -> &'static str {
        "m20261013_000002_typescript_oauth_schema"
    }
}
async fn apply(manager: &SchemaManager<'_>, sqlite: &str, postgres: &str) -> Result<(), DbErr> {
    let sql = match manager.get_database_backend() {
        sea_orm::DbBackend::Sqlite => sqlite,
        sea_orm::DbBackend::Postgres => postgres,
        _ => {
            return Err(DbErr::Custom(
                "Bundled migrations support SQLite and PostgreSQL".into(),
            ));
        }
    };
    for statement in sql
        .split(';')
        .filter(|statement| !statement.trim().is_empty())
    {
        _ = manager
            .get_connection()
            .execute_unprepared(statement)
            .await?;
    }
    Ok(())
}
macro_rules! migration {
    ($migration:ty, $sqlite:path, $postgres:path) => {
        #[async_trait::async_trait]
        impl MigrationTrait for $migration {
            fn use_transaction(&self) -> Option<bool> {
                Some(true)
            }
            #[expect(
                elided_lifetimes_in_paths,
                reason = "MigrationTrait requires a late-bound manager lifetime"
            )]
            async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
                apply(manager, $sqlite, $postgres).await
            }
            #[expect(
                elided_lifetimes_in_paths,
                reason = "MigrationTrait requires a late-bound manager lifetime"
            )]
            async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
                let sql = $sqlite;
                for statement in sql.split(';').rev() {
                    if let Some(create) = statement.split("create table ").nth(1) {
                        let name = create
                            .split_whitespace()
                            .next()
                            .ok_or_else(|| DbErr::Custom("Missing migration table name".into()))?;
                        _ = manager
                            .get_connection()
                            .execute_unprepared(&format!("DROP TABLE IF EXISTS {name}"))
                            .await?;
                    }
                }
                Ok(())
            }
        }
    };
}
migration!(
    AuthSchemaMigration,
    alibi_schema_registry::SQLITE_AUTH_SCHEMA,
    alibi_schema_registry::POSTGRES_AUTH_SCHEMA
);
migration!(
    OAuthClientsMigration,
    alibi_schema_registry::SQLITE_OAUTH_SCHEMA,
    alibi_schema_registry::POSTGRES_OAUTH_SCHEMA
);
