use super::*;
use alibi::store::{PasskeyStore, UserStore};
use alibi::utils::json::{self as native, JsValue};

backend_tests!(passkey_raw_optional_values_match_actual_adapter);
postgres_tests!(passkey_raw_optional_values_match_actual_adapter);

async fn check_raw_values(store: &impl PasskeyStore, backend: &str) -> TestResult {
    let fixture = native::parse_value(if backend == "postgres" {
        include_str!("../../../../crates/core/src/store/passkey_postgres_raw_cases.json")
    } else {
        include_str!("../../../../crates/core/src/store/passkey_raw_optional_cases.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend)
    {
        count += 1;
        let field = case["field"].as_str().unwrap();
        let mode = case["mode"].as_str().unwrap();
        let label = format!("{field}-{mode}-{backend}");
        let value = if case["input_date"].as_bool().unwrap() {
            JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap())
        } else {
            case["input"].clone()
        };
        let result = store
            .create_passkey(alibi::CreatePasskey {
                user_id: "owner".into(),
                name: if field == "name" {
                    value.clone()
                } else {
                    JsValue::Undefined
                },
                public_key: "public".into(),
                credential_id: label.clone(),
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
            let error = result.expect_err(&format!(
                "{backend}/{field}/{mode}: source rejects the binding"
            ));
            assert_eq!(error.status_code(), 500);
            assert!(store.get_passkey_by_credential_id(&label).await?.is_none());
            continue;
        }
        let row = result.unwrap_or_else(|error| panic!("{backend}/{field}/{mode}: {error}"));
        let snapshot = native::to_js_value(&row)?;
        let expected = if case["date"].as_bool().unwrap() {
            JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap())
        } else {
            case["output"].clone()
        };
        assert_eq!(snapshot[field], expected, "{backend}/{field}/{mode}");
        let persisted = store.get_passkey_by_id(&row.id).await?.unwrap();
        assert_eq!(native::to_js_value(&persisted)?[field], expected);
    }
    assert_eq!(count, if backend == "postgres" { 30 } else { 18 });
    Ok(())
}

async fn passkey_raw_optional_values_match_actual_adapter<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let store = B::store(Arc::new(AuthConfig::new(SECRET)), &connection);
    _ = store
        .create_user(alibi::CreateUser {
            id: Some("owner".into()),
            email: Some("raw-presence@example.com".into()),
            ..Default::default()
        })
        .await?;
    check_raw_values(
        &store,
        if db.raw.is_postgres() {
            "postgres"
        } else {
            "sqlite"
        },
    )
    .await?;
    B::close(connection).await
}

#[tokio::test]
async fn memory_passkey_raw_optional_values_match_actual_adapter() -> TestResult {
    check_raw_values(
        &alibi::store::stateless::StatelessStore::default(),
        "memory",
    )
    .await
}
