use super::*;
use alibi::session::SessionCreationPolicy;
use alibi::store::{CacheAdapter, MemoryCacheAdapter};

backend_tests!(
    inline_sync_creation_clocks_keep_original_cache_authority,
    inline_async_creation_clocks_keep_original_cache_authority,
    deferred_sync_creation_clocks_keep_original_cache_authority,
    deferred_async_creation_clocks_keep_original_cache_authority
);
postgres_tests!(
    inline_sync_creation_clocks_keep_original_cache_authority,
    inline_async_creation_clocks_keep_original_cache_authority,
    deferred_sync_creation_clocks_keep_original_cache_authority,
    deferred_async_creation_clocks_keep_original_cache_authority
);

struct Hooks {
    events: Events,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        self.events.lock().unwrap().push(json!({
            "phase":"create.before", "createdAt":input.additional_fields.get("createdAt"),
            "updatedAt":if matches!(input.additional_fields.get("updatedAt"),Some(JsValue::Date(_))) { json!("$clock") } else { Value::Null },
        }));
        _ = input
            .additional_fields
            .insert("createdAt".into(), JsValue::Date(self.created_at));
        _ = input
            .additional_fields
            .insert("updatedAt".into(), JsValue::Date(self.updated_at));
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        self.events.lock().unwrap().push(json!({
            "phase":"create.after", "createdAt":JsValue::Date(session.created_at()), "updatedAt":JsValue::Date(session.updated_at()),
        }));
        Ok(())
    }
}

fn clocks<S: AuthSession>(session: &S) -> Value {
    json!({"createdAt":JsValue::Date(session.created_at()),"updatedAt":JsValue::Date(session.updated_at())})
}

async fn cached_clocks(cache: &MemoryCacheAdapter, token: &str) -> alibi::AuthResult<Value> {
    let Some(raw) = cache.get(token).await? else {
        return Ok(Value::Null);
    };
    let payload = native::parse_value(&raw)?;
    let session = &payload["session"];
    Ok(json!({"createdAt":session["createdAt"],"updatedAt":session["updatedAt"]}))
}

fn input(
    events: &Events,
    name: &str,
    value: Option<JsValue>,
) -> alibi::AuthResult<Option<JsValue>> {
    let Some(JsValue::Date(date)) = value else {
        return Err(alibi::AuthError::internal(
            "transaction clock policy expected a Date",
        ));
    };
    events
        .lock()
        .unwrap()
        .push(json!({"phase":"input","field":name,"value":JsValue::Date(date)}));
    Ok(Some(JsValue::Date(date + chrono::Duration::seconds(1))))
}

async fn check<B: Backend>(db: Db, asynchronous: bool, deferred: bool) -> TestResult {
    let secret = "session-transaction-clocks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/session-transaction-creation-clocks.json"
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
    assert_eq!(cases.len(), 4);
    let events = Events::default();
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.session.store_in_database = true;
    for name in ["createdAt", "updatedAt"] {
        let observed = events.clone();
        let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
        field.required = true;
        if name == "createdAt" {
            field = field.default_value(JsValue::Date(
                cases[0]["default_created_at"].as_str().unwrap().parse()?,
            ));
        }
        let field = if asynchronous {
            field.transform_adapter_input(move |value| {
                let observed = observed.clone();
                async move { input(&observed, name, value) }
            })
        } else {
            field.transform(move |value| input(&observed, name, value.cloned()))
        };
        _ = config.session.additional_fields.insert(name.into(), field);
    }
    let hooks = Hooks {
        events: events.clone(),
        created_at: cases[0]["hook_clocks"]["createdAt"]
            .as_str()
            .unwrap()
            .parse()?,
        updated_at: cases[0]["hook_clocks"]["updatedAt"]
            .as_str()
            .unwrap()
            .parse()?,
    };
    let store = B::hook(B::store(Arc::new(config.clone()), &connection), hooks);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Transaction Clocks")
                .with_email("transaction-clocks@example.com"),
        )
        .await?;
    let mut checked = 0;
    for case in cases.iter().filter(|case| case["deferred"] == deferred) {
        checked += 1;
        let action = case["action"].as_str().unwrap();
        let rollback = action == "rollback";
        let token = format!("transaction-clocks-{deferred}-{action}");
        let create = CreateSession {
            additional_fields: Default::default(),
            user_id: owner.id().into_owned(),
            token: Some(token.clone()),
            expires_at: "2039-01-01T00:00:00.123Z".parse()?,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        events.lock().unwrap().clear();
        let inside = Arc::new(Mutex::new(None));
        let inside_result = inside.clone();
        let inside_events = events.clone();
        let inside_cache = cache.clone();
        let inside_token = token.clone();
        let owner_id = owner.id().into_owned();
        let result = alibi_core::store::transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let policy = if deferred {
                    SessionCreationPolicy::DeferSecondaryStorageWrites
                } else {
                    SessionCreationPolicy::Inline
                };
                let session = tx.create_session_record_with_policy(create, policy).await?;
                inside_events
                    .lock()
                    .unwrap()
                    .push(json!({"phase":"inside"}));
                let stored = tx
                    .get_user_sessions(&owner_id)
                    .await?
                    .into_iter()
                    .find(|session| session.token() == inside_token)
                    .ok_or_else(|| alibi::AuthError::internal("transaction clock row missing"))?;
                assert_eq!(stored.id(), session.stored().id());
                let cached = cached_clocks(&inside_cache, &inside_token).await?;
                *inside_result.lock().unwrap() =
                    Some(json!({"cached":cached,"stored":clocks(&stored)}));
                if rollback {
                    return Err(alibi::AuthError::internal("transaction clocks rollback"));
                }
                Ok(clocks(session.stored()))
            })
        })
        .await;
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{deferred}/{action} phases"
        );
        assert_eq!(
            json!(*inside.lock().unwrap()),
            case["inside"],
            "{backend}/{deferred}/{action} inside clocks"
        );
        if rollback {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(case["outcome"]["error"]["message"].as_str().unwrap())
            );
        } else {
            assert_eq!(result?, case["outcome"]["output"]);
        }
        assert_eq!(
            cached_clocks(&cache, &token).await?,
            case["cached"],
            "{backend}/{deferred}/{action} final cache"
        );
        let stored = auth
            .store()
            .get_user_sessions(owner.id().as_ref())
            .await?
            .into_iter()
            .find(|session| session.token() == token);
        assert_eq!(
            stored.as_ref().map(clocks).unwrap_or(Value::Null),
            case["stored"]
        );
        let references: Option<Value> = cache
            .get(&format!("active-sessions-{}", owner.id()))
            .await?
            .map(|raw| serde_json::from_str(&raw))
            .transpose()?;
        let referenced = references
            .as_ref()
            .and_then(Value::as_array)
            .is_some_and(|references| {
                references
                    .iter()
                    .any(|reference| reference["token"] == token)
            });
        assert_eq!(json!(referenced), case["referenced"]);
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM session WHERE token = $1", &[&token])
                .await?,
            if rollback { 0 } else { 1 }
        );
        for name in ["createdAt", "updatedAt"] {
            let query = if db.is_postgres() {
                format!(
                    "SELECT to_char(\"{name}\" AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') FROM session WHERE token = $1"
                )
            } else {
                format!(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ',\"{name}\") FROM session WHERE token = $1"
                )
            };
            assert_eq!(
                json!(db.text(&query, &[&token]).await?),
                case["stored"][name]
            );
        }
    }
    assert_eq!(checked, 2);
    drop(auth);
    B::close(connection).await
}

async fn inline_sync_creation_clocks_keep_original_cache_authority<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, false).await
}
async fn inline_async_creation_clocks_keep_original_cache_authority<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, false).await
}
async fn deferred_sync_creation_clocks_keep_original_cache_authority<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, true).await
}
async fn deferred_async_creation_clocks_keep_original_cache_authority<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, true).await
}
