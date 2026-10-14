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
            Box::new(SsoMigration),
            Box::new(ScimManagedMigration),
            Box::new(ScimBindingMigration),
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
struct ScimManagedMigration;
impl MigrationName for ScimManagedMigration {
    fn name(&self) -> &'static str {
        "m20261014_000004_typescript_scim_managed_schema"
    }
}
struct SsoMigration;
impl MigrationName for SsoMigration {
    fn name(&self) -> &'static str {
        "m20261013_000003_typescript_sso_schema"
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

migration!(
    SsoMigration,
    alibi_schema_registry::SQLITE_SSO_SCHEMA,
    alibi_schema_registry::POSTGRES_SSO_SCHEMA
);
// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::entities::user;
    use sea_orm::{Database, EntityName};
    use sea_orm_migration::prelude::{DeriveIden, DeriveMigrationName};

    #[derive(DeriveIden)]
    enum Todo {
        Table,
        Id,
        Title,
    }

    #[derive(DeriveMigrationName)]
    struct CreateTodoTable;

    #[async_trait::async_trait]
    impl MigrationTrait for CreateTodoTable {
        #[expect(
            elided_lifetimes_in_paths,
            reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
        )]
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .create_table(
                    Table::create()
                        .table(Todo::Table)
                        .if_not_exists()
                        .col(ColumnDef::new(Todo::Id).integer().not_null().primary_key())
                        .col(ColumnDef::new(Todo::Title).string().not_null())
                        .to_owned(),
                )
                .await
        }

        #[expect(
            elided_lifetimes_in_paths,
            reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
        )]
        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(Todo::Table).if_exists().to_owned())
                .await
        }
    }

    struct AppMigrator;

    #[async_trait::async_trait]
    impl MigratorTrait for AppMigrator {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            vec![Box::new(CreateTodoTable)]
        }
    }

    // Rust-specific surface: Better Auth owns a separate SeaORM migration table so app migrators can keep the default `seaql_migrations`.
    #[tokio::test]
    async fn auth_migrator_uses_namespaced_history_table() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        run_migrations(&database).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(!manager.has_table("seaql_migrations").await.unwrap());
    }

    // Rust-specific surface: Better Auth migration composition with app-owned SeaORM migrations is a Rust integration concern with no direct TS analogue.
    #[tokio::test]
    async fn auth_and_app_migrators_can_run_against_the_same_database() {
        let database = Database::connect("sqlite::memory:").await.unwrap();

        AppMigrator::up(&database, None).await.unwrap();
        AuthMigrator::up(&database, None).await.unwrap();

        let manager = SchemaManager::new(&database);
        assert!(manager.has_table("seaql_migrations").await.unwrap());
        assert!(manager.has_table("better_auth_migrations").await.unwrap());
        assert!(manager.has_table("todo").await.unwrap());
        assert!(manager.has_table(user::Entity.table_name()).await.unwrap());
    }
}
// LCOV_EXCL_STOP

migration!(
    ScimManagedMigration,
    alibi_schema_registry::SQLITE_SCIM_MANAGED_SCHEMA,
    alibi_schema_registry::POSTGRES_SCIM_MANAGED_SCHEMA
);

struct ScimBindingMigration;
impl MigrationName for ScimBindingMigration {
    fn name(&self) -> &'static str {
        "m20261014_000005_typescript_scim_binding_schema"
    }
}
migration!(
    ScimBindingMigration,
    alibi_schema_registry::SQLITE_SCIM_BINDING_SCHEMA,
    alibi_schema_registry::POSTGRES_SCIM_BINDING_SCHEMA
);
