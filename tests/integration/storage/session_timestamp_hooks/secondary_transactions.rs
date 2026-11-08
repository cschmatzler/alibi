use super::*;
use alibi::session::SessionCreationPolicy;
use alibi::store::{CacheAdapter, MemoryCacheAdapter};

backend_tests!(
    inline_sync_date_publication_matches_source,
    inline_async_date_publication_matches_source,
    inline_sync_string_publication_matches_source,
    inline_async_string_publication_matches_source,
    deferred_sync_date_publication_matches_source,
    deferred_async_date_publication_matches_source,
    deferred_sync_string_publication_matches_source,
    deferred_async_string_publication_matches_source
);
postgres_tests!(
    inline_sync_date_publication_matches_source,
    inline_async_date_publication_matches_source,
    inline_sync_string_publication_matches_source,
    inline_async_string_publication_matches_source,
    deferred_sync_date_publication_matches_source,
    deferred_async_date_publication_matches_source,
    deferred_sync_string_publication_matches_source,
    deferred_async_string_publication_matches_source
);

async fn check<B: Backend>(db: Db, asynchronous: bool, deferred: bool, string: bool) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if deferred {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-deferred.json")
    } else {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-transactions.json")
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
    assert_eq!(cases.len(), 4);
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
    let kind = if string { "string" } else { "date" };
    let mut checked = 0;
    for case in cases.iter().filter(|case| case["kind"] == kind) {
        checked += 1;
        let action = case["action"].as_str().unwrap();
        let token = format!("timestamp-{kind}-{action}");
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
        if string {
            _ = create
                .additional_fields
                .insert("expiresAt".into(), case["input"].clone().into());
        } else {
            create.expires_at = case["input"].as_str().unwrap().parse()?;
        }
        let inside = Arc::new(Mutex::new(None));
        let inside_result = inside.clone();
        let inside_events = events.clone();
        let inside_cache = cache.clone();
        let inside_token = token.clone();
        let owner_id = owner.id().into_owned();
        let rollback = action == "rollback";
        events.lock().unwrap().clear();
        let result = alibi_core::store::transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let policy = if deferred {
                    SessionCreationPolicy::DeferSecondaryStorageWrites
                } else {
                    SessionCreationPolicy::Inline
                };
                let result = tx
                    .create_session_record_with_policy(create, policy)
                    .await
                    .map(|session| session.stored().expires_at());
                inside_events
                    .lock()
                    .unwrap()
                    .push(json!({"phase":"inside"}));
                let rows = tx
                    .get_user_sessions(&owner_id)
                    .await?
                    .into_iter()
                    .filter(|session| session.token() == inside_token)
                    .count();
                let cached: Value = inside_cache
                    .get(&inside_token)
                    .await?
                    .map(|raw| serde_json::from_str(&raw))
                    .transpose()
                    .map_err(|error| alibi::AuthError::internal(error.to_string()))?
                    .unwrap_or(Value::Null);
                *inside_result.lock().unwrap() =
                    Some(json!({"rows":rows,"cached":cached["session"]["expiresAt"]}));
                if rollback {
                    return Err(alibi::AuthError::internal("session expiry rollback"));
                }
                Ok(result)
            })
        })
        .await;
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{deferred}/{kind}/{action} phases"
        );
        assert_eq!(
            json!(*inside.lock().unwrap()),
            case["inside"],
            "{backend}/{deferred}/{kind}/{action} inside transaction"
        );
        if rollback {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(case["outcome"]["error"]["message"].as_str().unwrap())
            );
        } else if let Some(expected) = case["outcome"].get("error") {
            assert_eq!(expected["name"], "TypeError");
            assert!(
                result?
                    .unwrap_err()
                    .to_string()
                    .contains(expected["message"].as_str().unwrap())
            );
        } else {
            assert_eq!(
                native::to_value(&JsValue::Date(result??))?,
                case["outcome"]["output"]
            );
        }
        let cached: Value = cache
            .get(&token)
            .await?
            .map(|raw| serde_json::from_str(&raw))
            .transpose()?
            .unwrap_or(Value::Null);
        assert_eq!(
            cached["session"]["expiresAt"], case["cached"],
            "{backend}/{deferred}/{kind}/{action} final cache"
        );
        let stored = if db.is_postgres() {
            db.text("SELECT to_char(\"expiresAt\" AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') FROM session WHERE token = $1", &[&token]).await?
        } else {
            db.text("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', \"expiresAt\") FROM session WHERE token = $1", &[&token]).await?
        };
        assert_eq!(
            json!(stored),
            case["stored"],
            "{backend}/{deferred}/{kind}/{action} final SQL"
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
            "{backend}/{deferred}/{kind}/{action} reference"
        );
    }
    assert_eq!(checked, 2);
    drop(auth);
    B::close(connection).await
}

async fn inline_sync_date_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, false).await
}
async fn inline_async_date_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, false).await
}
async fn inline_sync_string_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, true).await
}
async fn inline_async_string_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, true).await
}
async fn deferred_sync_date_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true, false).await
}
async fn deferred_async_date_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, true, false).await
}
async fn deferred_sync_string_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true, true).await
}
async fn deferred_async_string_publication_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, true, true).await
}
