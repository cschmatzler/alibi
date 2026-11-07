use super::*;
use alibi::store::{PasskeyStore, UserStore};
use alibi::utils::json::{self as native, JsValue};

backend_tests!(passkey_optional_fields_match_actual_adapter_presence);

async fn check_presence(store: &impl PasskeyStore, backend: &str) -> TestResult {
    let fixture = native::parse_value(include_str!(
        "../../../../crates/core/src/store/passkey_field_presence_cases.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == backend)
    {
        count += 1;
        let input = &case["input"];
        let created_at = if case["input_date"].as_bool() == Some(true) {
            JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap())
        } else {
            input["createdAt"].clone()
        };
        let row = store
            .create_passkey(alibi::CreatePasskey {
                user_id: "owner".into(),
                name: input["name"].clone(),
                public_key: "public".into(),
                credential_id: input["credentialID"].as_str().unwrap().into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: input["transports"].clone(),
                created_at,
                aaguid: input["aaguid"].clone(),
            })
            .await?;
        let snapshot = native::to_js_value(&row)?;
        let mut expected = case["output"].clone();
        expected["id"] = JsValue::String(row.id.clone().into());
        let wire = native::to_string(&row)?;
        assert_eq!(
            native::parse_value(&wire)?,
            expected,
            "{backend}/{}",
            case["mode"].as_str().unwrap()
        );
        let expected_wire = case["wire"].as_str().unwrap().replace(
            &format!("\"id\":\"{}\"", input["id"].as_str().unwrap()),
            &format!("\"id\":\"{}\"", row.id),
        );
        assert_eq!(wire, expected_wire);
        let keys = JsValue::Array(
            snapshot
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .map(JsValue::String)
                .collect(),
        );
        assert_eq!(keys, case["keys"]);
        let undefined = JsValue::Array(
            snapshot
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, value)| value.is_undefined())
                .map(|(name, _)| JsValue::String(name.clone()))
                .collect(),
        );
        assert_eq!(undefined, case["undefined"]);
        assert_eq!(
            snapshot["createdAt"].as_date().is_some(),
            case["date"].as_bool().unwrap()
        );
        let view: alibi::wire::PasskeyView = native::from_value(snapshot.clone())?;
        assert_eq!(native::to_js_value(&view)?, snapshot);
        assert_eq!(serde_json::to_value(&view)?, expected.to_json_value()?);
        let found = store.get_passkey_by_id(&row.id).await?.unwrap();
        assert_eq!(native::to_js_value(&found)?, snapshot);
        let found = store
            .get_passkey_by_credential_id(&row.credential_id)
            .await?
            .unwrap();
        assert_eq!(native::to_js_value(&found)?, snapshot);
        let listed = store.list_passkeys_by_user("owner").await?;
        assert_eq!(
            native::to_js_value(listed.iter().find(|row| row.id == found.id).unwrap())?,
            snapshot
        );
    }
    assert_eq!(count, 6);
    Ok(())
}

async fn passkey_optional_fields_match_actual_adapter_presence<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let store = B::store(Arc::new(AuthConfig::new(SECRET)), &connection);
    _ = store
        .create_user(alibi::CreateUser {
            id: Some("owner".into()),
            email: Some("presence@example.com".into()),
            ..Default::default()
        })
        .await?;
    check_presence(&store, "sqlite").await?;
    B::close(connection).await
}

#[tokio::test]
async fn memory_passkey_optional_fields_match_actual_adapter_presence() -> TestResult {
    check_presence(
        &alibi::store::stateless::StatelessStore::default(),
        "memory",
    )
    .await
}
