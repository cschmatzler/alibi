use super::*;
use alibi::store::{CacheAdapter, MemoryCacheAdapter};

backend_tests!(
    session_creation_sync_expiry_matches_secondary_source,
    session_creation_async_expiry_matches_secondary_source,
    session_refresh_sync_expiry_matches_secondary_source,
    session_refresh_async_expiry_matches_secondary_source,
    session_creation_sync_string_matches_secondary_source,
    session_creation_async_string_matches_secondary_source,
    session_refresh_sync_string_matches_secondary_source,
    session_refresh_async_string_matches_secondary_source
);
postgres_tests!(
    session_creation_sync_expiry_matches_secondary_source,
    session_creation_async_expiry_matches_secondary_source,
    session_refresh_sync_expiry_matches_secondary_source,
    session_refresh_async_expiry_matches_secondary_source,
    session_creation_sync_string_matches_secondary_source,
    session_creation_async_string_matches_secondary_source,
    session_refresh_sync_string_matches_secondary_source,
    session_refresh_async_string_matches_secondary_source
);

async fn check<B: Backend>(
    db: Db,
    asynchronous: bool,
    operation: &str,
    string: bool,
) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if string {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-string.json")
    } else {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary.json")
    })?;
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
    assert_eq!(case["kind"], if string { "string" } else { "date" });
    let cache = Arc::new(MemoryCacheAdapter::new());
    let events = Events::default();
    let inputs = events.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            async move { transform(&inputs, value, false) }
        })
    } else {
        field.transform(move |value| transform(&inputs, value.cloned(), false))
    };
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.session.store_in_database = true;
    _ = config
        .session
        .additional_fields
        .insert("expiresAt".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        SessionHooks(events.clone()),
    );
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("session-timestamp@example.com"),
        )
        .await?;
    let token = format!(
        "timestamp-{operation}-{}",
        if string { "string" } else { "date" }
    );
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
    let result = if operation == "create" {
        if string {
            _ = create
                .additional_fields
                .insert("expiresAt".into(), case["input"].clone().into());
        } else {
            create.expires_at = case["input"].as_str().unwrap().parse()?;
        }
        events.lock().unwrap().clear();
        auth.store().create_session(create).await
    } else {
        assert_eq!(operation, "update");
        let original = auth.store().create_session(create).await?;
        events.lock().unwrap().clear();
        let session = if string {
            let mut fields = alibi::field_policy::FieldValues::new();
            _ = fields.insert("expiresAt".into(), case["input"].clone().into());
            auth.store().update_session_fields(&token, fields).await?
        } else {
            auth.store()
                .refresh_session(&token, case["input"].as_str().unwrap().parse()?)
                .await?
        }
        .ok_or("secondary refresh unexpectedly missing")?;
        assert_eq!(session.id(), original.id());
        Ok(session)
    };
    let returned_id = if let Some(expected) = case["outcome"].get("error") {
        let error = result
            .err()
            .ok_or("source post-SQL mirror failure became a successful creation")?;
        assert_eq!(expected["name"], "TypeError");
        assert!(
            error
                .to_string()
                .contains(expected["message"].as_str().unwrap()),
            "{backend}/{operation}: {error}"
        );
        None
    } else {
        let session = result?;
        let expected = if string {
            &case["outcome"]["output"]
        } else {
            &case["output"]
        };
        assert_eq!(
            native::to_value(&JsValue::Date(session.expires_at()))?,
            *expected,
            "{backend}/{operation} returned SQL expiry"
        );
        Some(session.id().into_owned())
    };
    assert_eq!(
        json!(*events.lock().unwrap()),
        case["events"],
        "{backend}/{operation} phases"
    );
    let cached: Value = cache
        .get(&token)
        .await?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?
        .unwrap_or(Value::Null);
    assert_eq!(
        cached["session"]["expiresAt"], case["cached"],
        "{backend}/{operation} cached expiry, payload: {cached}"
    );
    if let Some(session) = cached["session"].as_object() {
        for name in [
            "expires_at",
            "created_at",
            "updated_at",
            "user_id",
            "ip_address",
            "user_agent",
        ] {
            assert!(
                !session.contains_key(name),
                "{backend}/{operation} leaked native property {name}"
            );
        }
    }
    let readback = auth
        .store()
        .get_session(&token)
        .await?
        .ok_or("secondary callback readback missing")?;
    if let Some(id) = returned_id {
        assert_eq!(readback.id().as_ref(), id);
    }
    assert_eq!(
        native::to_value(&JsValue::Date(readback.expires_at()))?,
        case["readback"],
        "{backend}/{operation} public cache readback"
    );
    let stored = if db.is_postgres() {
        db.text("SELECT to_char(\"expiresAt\" AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') FROM session WHERE token = $1", &[&token]).await?
    } else {
        db.text(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', \"expiresAt\") FROM session WHERE token = $1",
            &[&token],
        )
        .await?
    };
    assert_eq!(
        json!(stored),
        case["stored"],
        "{backend}/{operation} physical SQL expiry"
    );
    let references: Option<Value> = cache
        .get(&format!("active-sessions-{}", owner.id()))
        .await?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?;
    let reference = references
        .as_ref()
        .and_then(Value::as_array)
        .and_then(|references| {
            references
                .iter()
                .find(|reference| reference["token"] == token)
        });
    assert_eq!(
        reference
            .map(|reference| reference["expiresAt"].clone())
            .unwrap_or(Value::Null),
        case["referenced"],
        "{backend}/{operation} original expiry reference"
    );
    drop(auth);
    B::close(connection).await
}

async fn session_creation_sync_expiry_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create", false).await
}
async fn session_creation_async_expiry_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create", false).await
}
async fn session_refresh_sync_expiry_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update", false).await
}
async fn session_refresh_async_expiry_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "update", false).await
}

async fn session_creation_sync_string_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create", true).await
}
async fn session_creation_async_string_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create", true).await
}
async fn session_refresh_sync_string_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update", true).await
}
async fn session_refresh_async_string_matches_secondary_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "update", true).await
}
