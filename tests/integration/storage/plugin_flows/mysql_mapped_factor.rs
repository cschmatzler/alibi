use super::mysql_workflow::exchange;
use super::*;
use alibi::plugins::{TwoFactorConfig, TwoFactorPlugin};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_mapped_factor_storage_matches_actual_http() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_mapped_factor_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in include_str!("../../../fixtures/mysql-mapped-factor-schema.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mysql-mapped-factor.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let mut config = AuthConfig::new("mysql-mapped-factor-secret-at-least-32-characters")
        .base_url("http://localhost");
    config.advanced.database.two_factor = Some(alibi::config::TwoFactorDatabaseConfig {
        table_name: "factor_records".into(),
        columns: fixture["fields"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
            .collect(),
    });
    let auth = AuthBuilder::new(config.clone())
        .store(<super::super::SeaOrm as Backend>::store(
            Arc::new(config),
            &connection,
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut jar = BTreeMap::new();
    let mut code = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let (path, input) = match action {
            "signup" => (
                "/sign-up/email",
                json!({"name":"Owner","email":"mysql-mapped@example.com","password":"Password123!"}),
            ),
            "enable" => ("/two-factor/enable", json!({"password":"Password123!"})),
            "backup" | "replay" => ("/two-factor/verify-backup-code", json!({"code":code})),
            "disable" => ("/two-factor/disable", json!({"password":"Password123!"})),
            _ => panic!("unexpected mapped source action: {action}"),
        };
        let response = exchange(&auth, &mut jar, path, Some(input)).await;
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{action}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let value = body(&response);
        let output = match action {
            "signup" | "backup" => {
                json!({"email":value["user"]["email"],"token":value["token"].as_str().is_some_and(|token| !token.is_empty())})
            }
            "enable" => {
                code = value["backupCodes"][0].as_str().unwrap().to_owned();
                json!({"backupCodes":value["backupCodes"].as_array().unwrap().len(),"totp":value["totpURI"].as_str().unwrap().starts_with("otpauth://totp/")})
            }
            _ => value,
        };
        assert_eq!(output, case["output"], "{action}");
    }
    let remaining = connection
        .query_one_raw(Statement::from_string(
            DbBackend::MySql,
            "SELECT COUNT(*) AS total FROM factor_records".to_owned(),
        ))
        .await?
        .unwrap();
    assert_eq!(remaining.try_get::<i64>("", "total")?, 0);
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
