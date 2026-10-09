//! The bundled schema migration and its shared ledger.

use super::{Backend, Db, SeaOrm, Sqlx, TestResult, backend_tests, postgres_tests};
use alibi::AuthConfig;
use alibi::store::{SchemaMigrator, UserStore};
use alibi::{AuthUser, CreateUser};
use std::sync::Arc;

backend_tests!(
    reruns_are_no_ops_recorded_once_in_the_namespaced_ledger,
    unknown_recorded_versions_fail_before_any_change,
);
postgres_tests!(
    reruns_are_no_ops_recorded_once_in_the_namespaced_ledger,
    unknown_recorded_versions_fail_before_any_change,
);

const SECRET: &str = "bundled-schema-migration-secret-32-chars";

/// Every base table in the database under test, sorted and comma-separated.
async fn tables(db: &Db) -> TestResult<Option<String>> {
    db.text(
        if db.is_postgres() {
            "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_type = 'BASE TABLE'"
        } else {
            "SELECT group_concat(name, ',') FROM (SELECT name FROM sqlite_master WHERE type='table' ORDER BY name)"
        },
        &[],
    )
    .await
}

async fn reruns_are_no_ops_recorded_once_in_the_namespaced_ledger<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let user = store
        .create_user(CreateUser::new().with_email("ledger@fixture.test"))
        .await?;
    let schema = tables(&db).await?;
    store.migrate().await?;
    assert_eq!(tables(&db).await?, schema);
    assert_eq!(db.count("better_auth_migrations").await?, 1);
    assert_eq!(
        db.text("SELECT version FROM better_auth_migrations", &[])
            .await?,
        Some("m20261003_000001_auth_schema".to_owned())
    );
    let schema = schema.unwrap_or_default();
    assert!(!schema.split(',').any(|table| table == "seaql_migrations"));
    assert!(!schema.split(',').any(|table| table == "_sqlx_migrations"));
    assert!(store.get_user_by_id(user.id().as_ref()).await?.is_some());
    B::close(connection).await
}

async fn unknown_recorded_versions_fail_before_any_change<B: Backend>(db: Db) -> TestResult {
    _ = db
        .execute(
            "CREATE TABLE better_auth_migrations (version varchar NOT NULL PRIMARY KEY, applied_at bigint NOT NULL)",
            &[],
        )
        .await?;
    _ = db
        .execute(
            "INSERT INTO better_auth_migrations VALUES ('m20990101_000001_future', 0)",
            &[],
        )
        .await?;
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(AuthConfig::new(SECRET)), &connection);
    let error = store
        .migrate()
        .await
        .err()
        .ok_or("unknown version must fail")?;
    assert!(error.to_string().contains("m20990101_000001_future"));
    assert_eq!(
        tables(&db).await?,
        Some("better_auth_migrations".to_owned())
    );
    B::close(connection).await
}

async fn installed_by<From: Backend, To: Backend>(db: Db) -> TestResult {
    let (from_connection, from) = db.migrated::<From>(SECRET).await?;
    let created = from
        .create_user(CreateUser::new().with_email("switch@fixture.test"))
        .await?;
    From::close(from_connection).await?;
    let (to_connection, to) = db.migrated::<To>(SECRET).await?;
    assert_eq!(db.count("better_auth_migrations").await?, 1);
    assert_eq!(
        to.get_user_by_email("switch@fixture.test")
            .await?
            .map(|user| user.id().into_owned()),
        Some(created.id().into_owned())
    );
    drop(
        to.create_user(CreateUser::new().with_email("after-switch@fixture.test"))
            .await?,
    );
    To::close(to_connection).await
}

#[tokio::test]
async fn schema_installed_by_seaorm_is_current_for_sqlx() -> TestResult {
    installed_by::<SeaOrm, Sqlx>(Db::sqlite().await?).await
}

#[tokio::test]
async fn schema_installed_by_sqlx_is_current_for_seaorm() -> TestResult {
    installed_by::<Sqlx, SeaOrm>(Db::sqlite().await?).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_schema_installed_by_seaorm_is_current_for_sqlx() -> TestResult {
    installed_by::<SeaOrm, Sqlx>(Db::postgres().await?).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_schema_installed_by_sqlx_is_current_for_seaorm() -> TestResult {
    installed_by::<Sqlx, SeaOrm>(Db::postgres().await?).await
}
