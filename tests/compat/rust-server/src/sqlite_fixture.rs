//! Keep the fixture's in-memory database alive for the server lifetime.
use alibi::seaorm::sea_orm::{ConnectOptions, ConnectionTrait, DbBackend, Statement};
use std::sync::atomic::{AtomicU64, Ordering};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
use alibi::seaorm::{Database, DatabaseConnection};

pub(crate) fn options() -> ConnectOptions {
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
-> Result<(DatabaseConnection, DatabaseConnection), alibi::seaorm::sea_orm::DbErr> {
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
    use alibi::{AuthUser, CreateUser};
    use std::time::Duration;

    #[tokio::test]
    async fn observer_reads_committed_status_during_writer_transaction_and_cannot_write() {
        use alibi::seaorm::sea_orm::TransactionTrait;
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

    // Exercise the real pool's retirement, not a mock store. Accelerate inherited
    // policies only; explicitly disabled fixture policies must remain disabled.
    #[tokio::test]
    async fn retains_migrations_and_user_identity_across_connection_maintenance() {
        for (label, mut configured, retain) in [
            (
                "inherited-defaults",
                ConnectOptions::new("sqlite::memory:"),
                false,
            ),
            ("persistent-fixture", options(), true),
        ] {
            configured.max_connections(1).min_connections(1);
            let interval = Duration::from_secs(1);
            if configured.get_idle_timeout() != Some(None) {
                configured.idle_timeout(interval);
            }
            if configured.get_max_lifetime() != Some(None) {
                configured.max_lifetime(interval);
            }
            let database = Database::connect(configured).await.unwrap();
            crate::backend::migrate(&database).await.unwrap();
            let config =
                alibi::AuthConfig::new("fixture-database-retention-test-secret-at-least-32chars");
            let store = crate::backend::store::<crate::TestSchema>(config, database.clone());
            let issued = alibi::store::UserStore::create_user(
                &store,
                CreateUser::new().with_email("retained@fixture.test"),
            )
            .await
            .unwrap();
            let pool = database.get_sqlite_connection_pool();
            // A TEMP table belongs to this physical connection; its random token
            // distinguishes connection retention from merely recreating schema.
            sqlx::query(sqlx::AssertSqlSafe(
                "CREATE TEMP TABLE connection_identity AS SELECT hex(randomblob(16)) AS token",
            ))
            .execute(pool)
            .await
            .unwrap();
            let before: String =
                sqlx::query_scalar(sqlx::AssertSqlSafe("SELECT token FROM connection_identity"))
                    .fetch_one(pool)
                    .await
                    .unwrap();
            let tables_before: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
            ))
            .fetch_one(pool)
            .await
            .unwrap();
            assert!(tables_before > 0);
            tokio::time::sleep(Duration::from_millis(2200)).await;
            let tables_after: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
            ))
            .fetch_one(pool)
            .await
            .unwrap();
            let connection = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
                "SELECT token FROM connection_identity",
            ))
            .fetch_one(pool)
            .await;
            let found = alibi::store::UserStore::get_user_by_id(&store, issued.id().as_ref()).await;
            eprintln!(
                "{label}: tables={tables_before}->{tables_after}; connection={before}->{connection:?}; user={found:?}"
            );
            if retain {
                assert_eq!(tables_after, tables_before);
                assert_eq!(connection.unwrap(), before);
                let found = found.unwrap().expect("persisted fixture user must survive");
                assert_eq!(found.id(), issued.id());
                assert_eq!(found.email(), issued.email());
                // A separate fixture must have independent schema and rows.
                let independent = Database::connect(options()).await.unwrap();
                crate::backend::migrate(&independent).await.unwrap();
                let independent_store = crate::backend::store::<crate::TestSchema>(
                    alibi::AuthConfig::new(
                        "fixture-database-isolation-test-secret-at-least-32chars",
                    ),
                    independent,
                );
                assert!(
                    alibi::store::UserStore::get_user_by_id(
                        &independent_store,
                        issued.id().as_ref(),
                    )
                    .await
                    .unwrap()
                    .is_none()
                );
                eprintln!("persistent-fixture: independent database has no issued user");
            } else {
                assert_eq!(
                    tables_after, 0,
                    "retirement must reproduce migrated table loss"
                );
                assert!(
                    connection
                        .unwrap_err()
                        .to_string()
                        .contains("no such table")
                );
                assert!(found.unwrap_err().to_string().contains("no such table"));
            }
        }
    }
}
