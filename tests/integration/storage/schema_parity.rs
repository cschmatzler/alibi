//! Compare adapter migrations with databases installed by Better Auth 1.7.12.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::SchemaMigrator;

backend_tests!(all_tables_match_pinned_typescript_defaults);
postgres_tests!(all_tables_match_pinned_typescript_defaults);

async fn all_tables_match_pinned_typescript_defaults<B: Backend>(db: Db) -> TestResult {
    let (connection, _store) = db
        .migrated::<B>("schema-parity-secret-at-least-32-characters")
        .await?;
    B::rate_limit(&connection).migrate().await?;
    let (query, oracle) = if db.is_postgres() {
        (
            include_str!("../../fixtures/schema/postgres-inspect.sql"),
            include_str!("../../fixtures/schema/postgres-1.7.12.json"),
        )
    } else {
        (
            include_str!("../../fixtures/schema/sqlite-inspect.sql"),
            include_str!("../../fixtures/schema/sqlite-1.7.12.json"),
        )
    };
    let actual: serde_json::Value = serde_json::from_str(
        &db.text(query, &[])
            .await?
            .ok_or("missing schema snapshot")?,
    )?;
    let expected: serde_json::Value = serde_json::from_str(oracle)?;
    assert_eq!(actual.as_array().map(Vec::len), Some(25));
    assert_eq!(
        actual, expected,
        "table/column names, types, nullability, defaults, primary keys, indexes and foreign keys must match TypeScript"
    );
    B::close(connection).await
}
