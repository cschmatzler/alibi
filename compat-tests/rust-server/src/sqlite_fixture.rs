//! Keep the fixture's in-memory database alive for the server lifetime.
use better_auth_seaorm::sea_orm::ConnectOptions;
use better_auth_seaorm::{Database, DatabaseConnection};

fn options() -> ConnectOptions {
    let mut options = ConnectOptions::new("sqlite::memory:");
    // Closing the final SQLite memory connection destroys every migrated row.
    options
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None);
    options
}

pub(super) async fn connect() -> Result<DatabaseConnection, better_auth_seaorm::sea_orm::DbErr> {
    Database::connect(options()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{AuthUser, CreateUser};
    use better_auth_seaorm::SeaOrmStore;
    use std::time::Duration;

    // Accelerate enabled/default retirement policies while preserving disabled
    // policies. This exercises the real driver without waiting its 10/30-minute
    // defaults; no mock storage or authentication fixture state is supplied.
    #[tokio::test]
    async fn retains_migrations_and_user_identity_across_connection_maintenance() {
        let mut configured = options();
        let interval = Duration::from_millis(40);
        if configured.get_idle_timeout() != Some(None) {
            configured.idle_timeout(interval);
        }
        if configured.get_max_lifetime() != Some(None) {
            configured.max_lifetime(interval);
        }
        let database = Database::connect(configured).await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let config =
            better_auth::AuthConfig::new("fixture-database-retention-test-secret-at-least-32chars");
        let store = SeaOrmStore::<crate::TestSchema>::new(config, database);
        let issued = better_auth_core::store::UserStore::create_user(
            &store,
            CreateUser::new().with_email("retained@fixture.test"),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(160)).await;
        let found =
            better_auth_core::store::UserStore::get_user_by_id(&store, issued.id().as_ref())
                .await
                .expect("connection maintenance must preserve migrated fixture tables")
                .expect("connection maintenance must retain the actual persisted user");
        assert_eq!(found.id(), issued.id());
        assert_eq!(found.email(), issued.email());
    }
}
