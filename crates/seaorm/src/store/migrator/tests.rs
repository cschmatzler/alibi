use super::*;
use sea_orm::Database;

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
