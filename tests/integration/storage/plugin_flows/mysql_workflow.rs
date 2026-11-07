use super::passkey_matrix::{Authenticator, USER_PRESENT, USER_VERIFIED};
use super::*;
use alibi::plugins::{PasskeyPlugin, TwoFactorConfig, TwoFactorPlugin};
use alibi::seaorm::sea_orm::ConnectionTrait;
use std::collections::BTreeMap;

fn passkey_output(mut row: Value, owner: &str, identity: &mut Option<Value>) -> Value {
    assert_eq!(row["userId"], owner);
    assert!(row["publicKey"].as_str().is_some());
    assert!(chrono::DateTime::parse_from_rfc3339(row["createdAt"].as_str().unwrap()).is_ok());
    let current = json!({"id":row["id"],"publicKey":row["publicKey"],"createdAt":row["createdAt"]});
    assert_eq!(*identity.get_or_insert_with(|| current.clone()), current);
    for (field, value) in [
        ("id", "<passkey>"),
        ("userId", "<owner>"),
        ("publicKey", "<public-key>"),
        ("createdAt", "<date>"),
    ] {
        row[field] = json!(value);
    }
    row
}

pub(super) async fn exchange<S: AuthSchema>(
    auth: &Alibi<S>,
    jar: &mut BTreeMap<String, String>,
    path: &str,
    input: Option<Value>,
) -> AuthResponse {
    let cookie = jar
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let mut req = request(path, input, &cookie);
    _ = req
        .headers
        .insert("origin".into(), "http://localhost".into());
    let response = Box::pin(auth.handle_request(req)).await.unwrap();
    for header in response.headers.get_all("set-cookie") {
        let (name, value) = header.split(';').next().unwrap().split_once('=').unwrap();
        if value.is_empty() {
            _ = jar.remove(name);
        } else {
            _ = jar.insert(name.to_owned(), value.to_owned());
        }
    }
    response
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_http_workflow_matches_actual_source_schema() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_workflow_{}", uuid::Uuid::new_v4().simple());
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
    let config =
        AuthConfig::new("mysql-parity-secret-at-least-32-characters").base_url("http://localhost");
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::seaorm::SeaOrmStore::<
            <super::super::SeaOrm as Backend>::Schema,
        >::new(Arc::new(config), connection.clone()))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .origin("http://localhost"),
        )
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            skip_verification_on_enable: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../../fixtures/mysql-auth-workflow.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    let mut jar = BTreeMap::new();
    let mut owner = String::new();
    let mut key_id = String::new();
    let mut challenge = String::new();
    let mut backup = String::new();
    let mut token = String::new();
    let mut credential_identity = None;
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let (path, input) = match action {
            "signup" => (
                "/sign-up/email",
                Some(
                    json!({"name":"Owner","email":"mysql-parity@example.com","password":"Password123!"}),
                ),
            ),
            "session" => ("/get-session", None),
            "register-options" => ("/passkey/generate-register-options", None),
            "register" => {
                let key = Authenticator::new(17, "mysql-workflow-credential");
                let mut proof = key.registration(&json!({"type":"webauthn.create","challenge":challenge,"origin":"http://localhost"}), &key.attestation("localhost", USER_PRESENT | USER_VERIFIED, 6), false);
                proof["response"]["transports"] = json!(["usb", "nfc"]);
                (
                    "/passkey/verify-registration",
                    Some(json!({"response":proof,"name":"Security key"})),
                )
            }
            "list" | "empty-list" => ("/passkey/list-user-passkeys", None),
            "rename" => (
                "/passkey/update-passkey",
                Some(json!({"id":key_id,"name":"Renamed"})),
            ),
            "authenticate-options" => ("/passkey/generate-authenticate-options", None),
            "enable-factor" => (
                "/two-factor/enable",
                Some(json!({"password":"Password123!"})),
            ),
            "backup" | "backup-replay" => (
                "/two-factor/verify-backup-code",
                Some(json!({"code":backup})),
            ),
            "disable-factor" => (
                "/two-factor/disable",
                Some(json!({"password":"Password123!"})),
            ),
            "delete" => ("/passkey/delete-passkey", Some(json!({"id":key_id}))),
            _ => panic!("unexpected source action: {action}"),
        };
        let response = exchange(&auth, &mut jar, path, input).await;
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{action}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let value = body(&response);
        let output = match action {
            "signup" => {
                owner = value["user"]["id"].as_str().unwrap().to_owned();
                token = value["token"].as_str().unwrap().to_owned();
                json!({"email":value["user"]["email"],"name":value["user"]["name"],"emailVerified":value["user"]["emailVerified"],"token":value["token"].as_str().is_some_and(|token| !token.is_empty())})
            }
            "session" => {
                assert_eq!(value["user"]["id"], owner);
                assert_eq!(value["session"]["userId"], owner);
                assert_eq!(value["session"]["token"], token);
                json!({"email":value["user"]["email"],"name":value["user"]["name"],"token":value["session"]["token"].as_str().is_some_and(|token| !token.is_empty())})
            }
            "register-options" => {
                challenge = value["challenge"].as_str().unwrap().to_owned();
                json!({"name":value["user"]["name"],"rp":value["rp"],"excludeCredentials":value["excludeCredentials"],"extensions":value["extensions"]})
            }
            "register" => {
                key_id = value["id"].as_str().unwrap().to_owned();
                passkey_output(value, &owner, &mut credential_identity)
            }
            "list" => Value::Array(
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned()
                    .map(|row| passkey_output(row, &owner, &mut credential_identity))
                    .collect(),
            ),
            "rename" => {
                json!({"passkey":passkey_output(value["passkey"].clone(), &owner, &mut credential_identity)})
            }
            "authenticate-options" => {
                json!({"rpId":value["rpId"],"allowCredentials":value["allowCredentials"],"userVerification":value["userVerification"]})
            }
            "enable-factor" => {
                backup = value["backupCodes"][0].as_str().unwrap().to_owned();
                json!({"backupCodes":value["backupCodes"].as_array().unwrap().len(),"totp":value["totpURI"].as_str().unwrap().starts_with("otpauth://totp/")})
            }
            "backup" => {
                json!({"token":value["token"].as_str().is_some_and(|token| !token.is_empty()),"email":value["user"]["email"]})
            }
            _ => value,
        };
        assert_eq!(output, case["output"], "{action}");
    }
    for table in ["passkey", "twoFactor"] {
        let row = connection
            .query_one_raw(alibi::seaorm::sea_orm::Statement::from_string(
                alibi::seaorm::sea_orm::DbBackend::MySql,
                format!("SELECT COUNT(*) AS total FROM `{table}`"),
            ))
            .await?
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "total")?, 0);
    }
    assert_eq!(
        auth.store()
            .get_user_by_id(&owner)
            .await?
            .unwrap()
            .two_factor_enabled,
        Some(false)
    );
    let factor = auth
        .store()
        .create_two_factor(alibi::CreateTwoFactor {
            user_id: owner.clone(),
            secret: "secret".into(),
            backup_codes: "original".into(),
            verified: Some(true),
            failed_verification_count: Some(0.0),
            locked_until: None,
        })
        .await?;
    let mut increments = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = auth.store().clone();
        let id = factor.id.clone();
        _ = increments.spawn(async move { store.increment_two_factor_failure(&id).await });
    }
    let mut counts = Vec::new();
    while let Some(result) = increments.join_next().await {
        counts.push(result??.unwrap().failed_verification_count.unwrap());
    }
    counts.sort_by(f64::total_cmp);
    assert_eq!(counts, [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);
    let mut rotations = tokio::task::JoinSet::new();
    for replacement in ["first", "second"] {
        let store = auth.store().clone();
        let id = factor.id.clone();
        _ = rotations.spawn(async move {
            store
                .compare_and_swap_two_factor_backup_codes(&id, "original", replacement)
                .await
        });
    }
    let mut winners = 0;
    while let Some(result) = rotations.join_next().await {
        winners += usize::from(result??);
    }
    assert_eq!(winners, 1);
    assert!(
        auth.store()
            .update_two_factor(
                &factor.id,
                alibi::UpdateTwoFactor {
                    verified: Some(true),
                    ..Default::default()
                }
            )
            .await?
            .is_some()
    );
    let until = chrono::Utc::now() + chrono::Duration::minutes(1);
    assert!(
        auth.store()
            .set_two_factor_lock_if_count_at_least(&factor.id, 9.0, until)
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .set_two_factor_lock_if_count_at_least(&factor.id, 8.0, until)
            .await?
            .is_some()
    );
    assert!(
        auth.store()
            .clear_expired_two_factor_lock(&factor.id, chrono::Utc::now())
            .await?
            .is_none()
    );
    assert_eq!(
        auth.store()
            .clear_expired_two_factor_lock(&factor.id, until + chrono::Duration::seconds(1))
            .await?
            .unwrap()
            .failed_verification_count,
        Some(0.0)
    );
    auth.store().delete_two_factor(&owner).await?;
    assert!(
        auth.store()
            .increment_two_factor_failure(&factor.id)
            .await?
            .is_none()
    );
    assert!(
        !auth
            .store()
            .compare_and_swap_two_factor_backup_codes(&factor.id, "first", "missing")
            .await?
    );
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
