use super::mysql_workflow::exchange;
use super::*;
use alibi::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, OtpResendStrategy, SendEmailOtp,
};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::collections::BTreeMap;

#[derive(Default)]
struct Mailbox(Mutex<Vec<String>>);

#[async_trait::async_trait]
impl SendEmailOtp for Mailbox {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _: &alibi::CallbackContext,
    ) -> alibi::AuthResult<()> {
        assert_eq!(delivery.email, "mysql-otp-reuse@example.com");
        self.0.lock().unwrap().push(delivery.otp.clone());
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_email_otp_reuse_matches_actual_id_strategies() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mysql-email-otp-reuse.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    for profile in profiles {
        let database = format!("alibi_otp_reuse_{}", uuid::Uuid::new_v4().simple());
        _ = admin
            .execute_unprepared(&format!(
                "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
            ))
            .await?;
        let mut url = url::Url::parse(&base)?;
        url.set_path(&format!("/{database}"));
        let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
        for statement in include_str!("../../../fixtures/mysql-source-schema.sql")
            .split(';')
            .filter(|sql| !sql.trim().is_empty())
        {
            _ = connection.execute_unprepared(statement).await?;
        }
        let mut config = AuthConfig::new("mysql-email-otp-secret-at-least-32-characters")
            .base_url("http://localhost");
        if profile["strategy"] == "uuid" {
            config.advanced.database.generate_id = Some(alibi::config::DatabaseIdStrategy::Uuid);
        }
        let mailbox = Arc::new(Mailbox::default());
        let auth = AuthBuilder::new(config.clone())
            .store(<super::super::SeaOrm as Backend>::store(
                Arc::new(config),
                &connection,
            ))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                resend_strategy: OtpResendStrategy::Reuse,
                send_verification_otp: Some(mailbox.clone()),
                ..Default::default()
            }))
            .build()
            .await?;
        let mut jar = BTreeMap::new();
        let mut code = String::new();
        let mut expiry = None;
        let mut identifier = String::new();
        let cases = profile["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let action = case["action"].as_str().unwrap();
            let email = "mysql-otp-reuse@example.com";
            let (path, input) = match action {
                "signup" => (
                    "/sign-up/email",
                    json!({"name":"Owner","email":email,"password":"Password123!"}),
                ),
                "send" | "reuse" => (
                    "/email-otp/send-verification-otp",
                    json!({"email":email,"type":"sign-in"}),
                ),
                "wrong" => (
                    "/sign-in/email-otp",
                    json!({"email":email,"otp":if code == "000000" { "111111" } else { "000000" }}),
                ),
                "correct" | "replay" => ("/sign-in/email-otp", json!({"email":email,"otp":code})),
                _ => panic!("unexpected source OTP action: {action}"),
            };
            let response = exchange(&auth, &mut jar, path, Some(input)).await;
            assert_eq!(
                u64::from(response.status),
                case["status"].as_u64().unwrap(),
                "{}/{action}: {}",
                profile["strategy"],
                String::from_utf8_lossy(&response.body)
            );
            let value = if response.body.is_empty() {
                Value::Null
            } else {
                body(&response)
            };
            let output = if action == "signup" || action == "correct" && response.status == 200 {
                json!({"email":value["user"]["email"],"name":value["user"]["name"],"emailVerified":value["user"]["emailVerified"],"token":value["token"].as_str().is_some_and(|token| !token.is_empty())})
            } else {
                value
            };
            assert_eq!(output, case["output"], "{}/{action}", profile["strategy"]);
            let deliveries = mailbox.0.lock().unwrap().clone();
            assert_eq!(
                deliveries.len() as u64,
                case["deliveries"].as_u64().unwrap()
            );
            if action == "send" {
                code = deliveries[0].clone();
                assert_eq!(code.len(), 6);
                assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
            }
            if matches!(action, "send" | "reuse" | "wrong") {
                let stored = connection
                    .query_all_raw(Statement::from_string(
                        DbBackend::MySql,
                        "SELECT identifier, value, expiresAt FROM verification".to_owned(),
                    ))
                    .await?;
                assert_eq!(stored.len(), 1);
                let row = &stored[0];
                let current_identifier = row.try_get::<String>("", "identifier")?;
                if action == "send" {
                    identifier = current_identifier.clone();
                }
                assert_eq!(current_identifier, identifier);
                assert_eq!(json!(identifier), case["identifier"]);
                assert_eq!(
                    json!(row.try_get::<String>("", "value")?.replace(&code, "<otp>")),
                    case["value"]
                );
                let current: chrono::DateTime<chrono::Utc> = row.try_get("", "expiresAt")?;
                if action == "reuse" {
                    assert_eq!(deliveries[1], code);
                    assert!(current >= expiry.unwrap());
                    assert_eq!(case["expiry_extended"], true);
                }
                if action == "wrong" {
                    assert_eq!(Some(current), expiry);
                    assert_eq!(case["expiry_preserved"], true);
                }
                expiry = Some(current);
            }
            if matches!(action, "correct" | "replay") {
                let count = connection
                    .query_one_raw(Statement::from_sql_and_values(
                        DbBackend::MySql,
                        "SELECT COUNT(*) AS total FROM verification WHERE identifier = ?",
                        [identifier.clone().into()],
                    ))
                    .await?
                    .unwrap()
                    .try_get::<i64>("", "total")?;
                assert_eq!(json!(count), case["otp_records"]);
            }
        }
        drop(auth);
        connection.close().await?;
        _ = admin
            .execute_unprepared(&format!("DROP DATABASE `{database}`"))
            .await?;
    }
    admin.close().await?;
    Ok(())
}
