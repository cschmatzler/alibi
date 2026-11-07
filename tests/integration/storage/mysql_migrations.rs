use super::{Backend, SeaOrm, TestResult};
use alibi::AuthConfig;
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use alibi::seaorm::{Database, SeaOrmRateLimitStorage};
use alibi::store::SchemaMigrator;
use serde_json::{Value, json};
use std::sync::Arc;

async fn schema(connection: &alibi::seaorm::DatabaseConnection) -> TestResult<Value> {
    let mut columns = Vec::new();
    for row in connection.query_all_raw(Statement::from_string(DbBackend::MySql,
        "SELECT TABLE_NAME AS tableName, COLUMN_NAME AS columnName, ORDINAL_POSITION AS position, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS defaultValue, EXTRA AS extra FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME NOT IN ('better_auth_migrations','better_auth_rate_limit_migrations') ORDER BY TABLE_NAME, ORDINAL_POSITION".to_owned(),
    )).await? {
        columns.push(json!({
            "tableName":row.try_get::<String>("", "tableName")?,
            "columnName":row.try_get::<String>("", "columnName")?,
            "position":row.try_get::<u32>("", "position")?,
            "type":row.try_get::<String>("", "type")?,
            "nullable":row.try_get::<String>("", "nullable")?,
            "defaultValue":row.try_get::<Option<String>>("", "defaultValue")?,
            "extra":row.try_get::<String>("", "extra")?,
        }));
    }
    let mut indexes = Vec::new();
    for row in connection.query_all_raw(Statement::from_string(DbBackend::MySql,
        "SELECT TABLE_NAME AS tableName, INDEX_NAME AS indexName, NON_UNIQUE AS nonUnique, SEQ_IN_INDEX AS position, COLUMN_NAME AS columnName, SUB_PART AS prefixLength FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME NOT IN ('better_auth_migrations','better_auth_rate_limit_migrations') ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX".to_owned(),
    )).await? {
        indexes.push(json!({
            "tableName":row.try_get::<String>("", "tableName")?,
            "indexName":row.try_get::<String>("", "indexName")?,
            "nonUnique":row.try_get::<i32>("", "nonUnique")?,
            "position":row.try_get::<u32>("", "position")?,
            "columnName":row.try_get::<String>("", "columnName")?,
            "prefixLength":row.try_get::<Option<u32>>("", "prefixLength")?,
        }));
    }
    Ok(json!({"columns":columns,"indexes":indexes}))
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_bundled_migrations_match_actual_source_schema() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = Database::connect(base.clone()).await?;
    let database = format!("alibi_migrations_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = Database::connect(url.as_str()).await?;
    let store = <SeaOrm as Backend>::store(
        Arc::new(AuthConfig::new(
            "mysql-migration-secret-at-least-32-characters",
        )),
        &connection,
    );
    let rates = SeaOrmRateLimitStorage::new(connection.clone());
    store.migrate().await?;
    rates.migrate().await?;
    let expected: Value =
        serde_json::from_str(include_str!("../../fixtures/schema/mysql-1.7.18.json"))?;
    assert_eq!(schema(&connection).await?, expected);
    store.migrate().await?;
    rates.migrate().await?;
    assert_eq!(schema(&connection).await?, expected);
    drop(store);
    drop(rates);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
