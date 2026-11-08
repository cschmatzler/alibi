use super::*;
use alibi::store::{CacheAdapter, MemoryCacheAdapter};

backend_tests!(
    session_creation_cache_wire_matches_source,
    session_refresh_cache_wire_matches_source
);
postgres_tests!(
    session_creation_cache_wire_matches_source,
    session_refresh_cache_wire_matches_source
);

async fn check<B: Backend>(db: Db, operation: &str) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/session-timestamp-hooks-secondary-wire.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let cases = profiles
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap()["cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 2);
    let case = cases
        .iter()
        .find(|case| case["operation"] == operation)
        .unwrap();
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.session.store_in_database = true;
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()))
        .transform_adapter_input(|value| async move {
            match value {
                Some(JsValue::Date(date)) => {
                    Ok(Some(JsValue::Date(date + chrono::Duration::seconds(1))))
                }
                _ => Err(alibi::AuthError::internal(
                    "wire fixture expected a Date input",
                )),
            }
        });
    _ = config
        .session
        .additional_fields
        .insert("expiresAt".into(), field);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("session-timestamp@example.com"),
        )
        .await?;
    let token = format!("timestamp-{operation}-date");
    let mut create = CreateSession {
        additional_fields: Default::default(),
        user_id: owner.id().into_owned(),
        token: Some(token.clone()),
        expires_at: "2030-01-01T00:00:00.123Z".parse()?,
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    if operation == "create" {
        create.expires_at = case["input"].as_str().unwrap().parse()?;
        let session = auth.store().create_session(create).await?;
        assert_eq!(
            native::to_value(&JsValue::Date(session.expires_at()))?,
            case["output"]
        );
    } else {
        assert_eq!(operation, "update");
        let original = auth.store().create_session(create).await?;
        let session = auth
            .store()
            .refresh_session(&token, case["input"].as_str().unwrap().parse()?)
            .await?
            .ok_or("wire refresh unexpectedly missing")?;
        assert_eq!(session.id(), original.id());
        assert_eq!(
            native::to_value(&JsValue::Date(session.expires_at()))?,
            case["output"]
        );
    }
    let raw = cache
        .get(&token)
        .await?
        .ok_or("source cache token missing")?;
    assert_payload(&raw, case["wire"].as_str().unwrap(), backend, operation)?;
    drop(auth);
    B::close(connection).await
}

pub(super) fn assert_payload(
    raw: &str,
    expected_wire: &str,
    backend: &str,
    operation: &str,
) -> TestResult {
    let mut payload = native::parse_value(raw)?;
    let expected = native::parse_value(expected_wire)?;
    for path in ["", "/session", "/user"] {
        let actual = payload
            .pointer(path)
            .and_then(JsValue::as_object)
            .ok_or("native cache object missing")?;
        let expected = expected
            .pointer(path)
            .and_then(JsValue::as_object)
            .ok_or("source cache object missing")?;
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{backend}/{operation} {path} own property order, raw: {raw}"
        );
    }
    assert_eq!(
        payload["session"]["userId"], payload["user"]["id"],
        "{backend}/{operation} cached owner identity"
    );
    for (owner, key, value) in [
        ("session", "id", "$session"),
        ("session", "userId", "$user"),
        ("user", "id", "$user"),
    ] {
        assert!(
            payload[owner][key].as_str().is_some(),
            "{backend}/{operation} source identifier must remain a string"
        );
        payload[owner][key] = JsValue::String(value.into());
    }
    for owner in ["session", "user"] {
        for key in ["createdAt", "updatedAt"] {
            let value = payload[owner][key]
                .as_str()
                .ok_or("native cache clock is not a string")?;
            let date: chrono::DateTime<chrono::Utc> = value.parse()?;
            assert_eq!(
                value,
                alibi::utils::datetime::json_date_millis(date.timestamp_millis()),
                "{backend}/{operation} cache clock representation"
            );
            payload[owner][key] = JsValue::String("$clock".into());
        }
    }
    assert_eq!(
        native::to_string(&payload)?,
        expected_wire,
        "{backend}/{operation} exact normalized cache bytes"
    );
    Ok(())
}

async fn session_creation_cache_wire_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "create").await
}
async fn session_refresh_cache_wire_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "update").await
}
