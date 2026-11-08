use super::super::SeaOrm;
use super::*;
use alibi::seaorm::sea_orm::ConnectionTrait;

async fn check(asynchronous: bool, transactions: bool, failures: bool) -> TestResult {
    let fixture: Value = serde_json::from_str(if failures {
        include_str!("../../../fixtures/account-update-missing-mysql-failures.json")
    } else if transactions {
        include_str!("../../../fixtures/account-update-missing-mysql-transactions.json")
    } else {
        include_str!("../../../fixtures/account-update-missing-mysql-phases.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    assert_eq!(profile["backend"], "mysql");
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), if transactions { 2 } else { 5 });
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_missing_accounts_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in profile["schema_sql"]
        .as_str()
        .unwrap()
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    _ = connection
        .execute_unprepared(
            "CREATE TABLE matched_rows_probe (id INTEGER PRIMARY KEY, value INTEGER)",
        )
        .await?;
    _ = connection
        .execute_unprepared("INSERT INTO matched_rows_probe VALUES (1, 1)")
        .await?;
    let unchanged = connection
        .execute_unprepared("UPDATE matched_rows_probe SET value = 1 WHERE id = 1")
        .await?;
    let missing = connection
        .execute_unprepared("UPDATE matched_rows_probe SET value = 1 WHERE id = 2")
        .await?;
    assert_eq!(
        json!({"unchanged":unchanged.rows_affected(),"missing":missing.rows_affected()}),
        profile["driver_found_rows"]
    );
    let trace = SharedTrace::default();
    let mut config = AuthConfig::new("user-update-missing-phases-secret-at-least-32");
    _ = config.account.additional_fields.insert(
        "accessTokenExpiresAt".into(),
        date_field(&trace, asynchronous),
    );
    let store = SeaOrm::hook(
        SeaOrm::store(Arc::new(config.clone()), &connection),
        MissingAccountHooks(trace.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    check_cases(
        auth.store().clone(),
        trace,
        cases,
        transactions,
        false,
        || async {
            let row = connection
                .query_one_raw(alibi::seaorm::sea_orm::Statement::from_string(
                    alibi::seaorm::sea_orm::DbBackend::MySql,
                    "SELECT COUNT(*) AS count FROM account",
                ))
                .await?
                .ok_or("missing account count row")?;
            Ok(row.try_get("", "count")?)
        },
    )
    .await?;
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_updates_match_sync_source_phases() -> TestResult {
    check(false, false, false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_updates_match_async_source_phases() -> TestResult {
    check(true, false, false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_transactions_match_sync_source_phases() -> TestResult {
    check(false, true, false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_transactions_match_async_source_phases() -> TestResult {
    check(true, true, false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_failures_match_sync_source_phases() -> TestResult {
    check(false, false, true).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_missing_account_failures_match_async_source_phases() -> TestResult {
    check(true, false, true).await
}
