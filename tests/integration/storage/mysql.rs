//! Directed MySQL probes use a disposable database and an application-owned table.
use super::{Backend, SeaOrm, TestResult};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use alibi::seaorm::{Database, SeaOrmStore};
use alibi::store::PasskeyStore;
use alibi::utils::json::{self as native, JsValue};
use alibi::{AuthConfig, CreatePasskey};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_passkey_raw_values_match_actual_adapter() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = Database::connect(base.clone()).await?;
    let database = format!("alibi_oracle_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = Database::connect(url.as_str()).await?;
    _ = connection.execute_raw(Statement::from_string(DbBackend::MySql,
        "CREATE TABLE passkey (id VARCHAR(255) PRIMARY KEY, name TEXT, publicKey TEXT, userId VARCHAR(255), credentialID VARCHAR(255), counter BIGINT, deviceType TEXT, backedUp BOOLEAN, transports TEXT, createdAt DATETIME(3), aaguid TEXT)".to_owned(),
    )).await?;
    let store = SeaOrmStore::<<SeaOrm as Backend>::Schema>::new(
        Arc::new(AuthConfig::new(
            "mysql-parity-secret-at-least-32-characters",
        )),
        connection.clone(),
    );
    let fixture = native::parse_value(include_str!(
        "../../../crates/core/src/store/passkey_mysql_raw_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 48);
    for case in cases {
        let field = case["field"].as_str().unwrap();
        let mode = case["mode"].as_str().unwrap();
        let credential_id = format!("{field}-{mode}");
        let value = if case["input_date"].as_bool().unwrap() {
            JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap())
        } else if let Some(number) = case["input_number"].as_str() {
            JsValue::Number(match number {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ => panic!("unexpected oracle number: {number}"),
            })
        } else {
            case["input"].clone()
        };
        let result = store
            .create_passkey(CreatePasskey {
                user_id: "owner".into(),
                name: if field == "name" {
                    value.clone()
                } else {
                    JsValue::Undefined
                },
                public_key: "public".into(),
                credential_id: credential_id.clone(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: if field == "transports" {
                    value.clone()
                } else {
                    JsValue::Undefined
                },
                created_at: JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                aaguid: if field == "aaguid" {
                    value
                } else {
                    JsValue::Undefined
                },
            })
            .await;
        if case.get("error").is_some() {
            assert_eq!(result.expect_err(mode).status_code(), 500);
            assert!(
                store
                    .get_passkey_by_credential_id(&credential_id)
                    .await?
                    .is_none()
            );
        } else {
            let row = result.unwrap_or_else(|error| panic!("{field}/{mode}: {error}"));
            assert_eq!(
                native::to_js_value(&row)?[field],
                case["output"],
                "{field}/{mode}"
            );
            let persisted = store.get_passkey_by_id(&row.id).await?.unwrap();
            assert_eq!(native::to_js_value(&persisted)?[field], case["output"]);
        }
    }
    drop(store);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
