//! Keep the fixture's in-memory database alive for the server lifetime.
use better_auth_seaorm::sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, Statement};
use std::sync::atomic::{AtomicU64, Ordering};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
use better_auth_seaorm::{Database, DatabaseConnection};

fn options() -> ConnectOptions {
    let name = format!(
        "file:better-auth-fixture-{}-{}",
        std::process::id(),
        DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.map_sqlx_sqlite_opts(move |sqlite| {
        sqlite
            .filename(name.clone())
            .in_memory(true)
            .shared_cache(true)
    });
    // Closing the final SQLite memory connection destroys every migrated row.
    options
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None);
    options
}

pub(super) async fn connect()
-> Result<(DatabaseConnection, DatabaseConnection), better_auth_seaorm::sea_orm::DbErr> {
    let configured = options();
    let writer = Database::connect(configured.clone()).await?;
    let observer = Database::connect(configured).await?;
    // Only the application observer uses this independent connection. It can
    // inspect committed invitation status while acceptance holds the writer.
    observer
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA query_only=ON",
        ))
        .await?;
    Ok((writer, observer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{AuthUser, CreateUser};
    use better_auth_seaorm::SeaOrmStore;
    use std::time::Duration;

    #[tokio::test]
    async fn observer_reads_committed_status_during_writer_transaction_and_cannot_write() {
        use better_auth_seaorm::sea_orm::TransactionTrait;
        let (writer, observer) = connect().await.unwrap();
        writer
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "CREATE TABLE invitation(id TEXT,status TEXT);CREATE TABLE member(id TEXT)",
            ))
            .await
            .unwrap();
        writer
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "INSERT INTO invitation VALUES('issued','accepted')",
            ))
            .await
            .unwrap();
        let transaction = writer.begin().await.unwrap();
        transaction
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "INSERT INTO member VALUES('pending')",
            ))
            .await
            .unwrap();
        let row = observer
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT status FROM invitation WHERE id='issued'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<String>("", "status").unwrap(), "accepted");
        assert!(
            observer
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "UPDATE invitation SET status='pending'"
                ))
                .await
                .is_err()
        );
        transaction.rollback().await.unwrap();
        assert!(
            writer
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT id FROM member"
                ))
                .await
                .unwrap()
                .is_none()
        );
    }

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
