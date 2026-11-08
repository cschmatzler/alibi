use super::*;

backend_tests!(builtin_creation_default_keeps_adapter_field_order);
postgres_tests!(builtin_creation_default_keeps_adapter_field_order);

#[derive(Default)]
struct Window {
    hook_end: Option<i64>,
    expiry_end: Option<i64>,
    updated_start: Option<i64>,
}

struct Hooks {
    events: Events,
    window: Arc<Mutex<Window>>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        self.events.lock().unwrap().push(json!({
            "phase":"create.before",
            "createdAt":before_clock(input.additional_fields.get("createdAt"),false)?,
            "updatedAt":before_clock(input.additional_fields.get("updatedAt"),false)?,
        }));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.window.lock().unwrap().hook_end = Some(chrono::Utc::now().timestamp_millis());
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        self.events.lock().unwrap().push(json!({
            "phase":"create.after", "createdAt":JsValue::Date(session.created_at()), "updatedAt":JsValue::Date(session.updated_at()), "expiresAt":JsValue::Date(session.expires_at()),
        }));
        Ok(())
    }
}

async fn input(
    events: Events,
    window: Arc<Mutex<Window>>,
    name: &'static str,
    value: Option<JsValue>,
) -> alibi::AuthResult<Option<JsValue>> {
    let Some(JsValue::Date(date)) = value else {
        return Err(alibi::AuthError::internal(
            "ordered clock policy expected a Date",
        ));
    };
    if name == "updatedAt" {
        window.lock().unwrap().updated_start = Some(chrono::Utc::now().timestamp_millis());
    }
    events
        .lock()
        .unwrap()
        .push(json!({"phase":"input","field":name,"kind":"date","value":JsValue::Date(date)}));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    if name == "expiresAt" {
        window.lock().unwrap().expiry_end = Some(chrono::Utc::now().timestamp_millis());
    }
    Ok(Some(JsValue::Date(date)))
}

async fn builtin_creation_default_keeps_adapter_field_order<B: Backend>(db: Db) -> TestResult {
    let secret = "session-creation-clock-order-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/session-creation-clock-order.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let case = profiles
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap();
    let events = Events::default();
    let window = Arc::new(Mutex::new(Window::default()));
    let mut config = AuthConfig::new(secret);
    for name in ["updatedAt", "expiresAt"] {
        let observed = events.clone();
        let observed_window = window.clone();
        let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
        field.required = true;
        let field = field.transform_adapter_input(move |value| {
            input(observed.clone(), observed_window.clone(), name, value)
        });
        _ = config.session.additional_fields.insert(name.into(), field);
    }
    let hooks = Hooks {
        events: events.clone(),
        window: window.clone(),
    };
    let store = B::hook(B::store(Arc::new(config.clone()), &connection), hooks);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Clock Order")
                .with_email("clock-order@example.com"),
        )
        .await?;
    let mut fields = alibi::field_policy::FieldValues::new();
    _ = fields.insert("createdAt".into(), JsValue::Undefined);
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: fields,
            user_id: owner.id().into_owned(),
            token: Some("creation-clock-order".into()),
            expires_at: case["input"]["expiresAt"].as_str().unwrap().parse()?,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let mut observed = events.lock().unwrap().clone();
    for event in &mut observed {
        let names: &[&str] = if event["phase"] == "create.after" {
            &["createdAt", "updatedAt"]
        } else if event["phase"] == "input" && event["field"] == "updatedAt" {
            &["value"]
        } else {
            &[]
        };
        for name in names {
            let value = event[*name]
                .as_str()
                .ok_or("ordered clock must remain a date string")?;
            let date: chrono::DateTime<chrono::Utc> = value.parse()?;
            assert_eq!(
                value,
                alibi::utils::datetime::json_date_millis(date.timestamp_millis())
            );
            event[*name] = json!("$clock");
        }
    }
    assert_eq!(
        json!(observed),
        case["events"],
        "{backend} builtin default and policy callback order"
    );
    let (hook_end, expiry_end, updated_start) = {
        let window = window.lock().unwrap();
        (
            window.hook_end.ok_or("before-hook end missing")?,
            window.expiry_end.ok_or("expiry input end missing")?,
            window
                .updated_start
                .ok_or("updatedAt input start missing")?,
        )
    };
    assert!(expiry_end >= hook_end);
    assert!(updated_start >= expiry_end);
    assert_eq!(
        json!(session.created_at().timestamp_millis() >= expiry_end),
        case["created_after_expiry"]
    );
    assert_eq!(
        json!(session.created_at().timestamp_millis() <= updated_start),
        case["created_before_updated_callback"]
    );
    assert_eq!(
        json!(session.updated_at().timestamp_millis() < hook_end),
        case["updated_before_hook"]
    );
    let readback = auth
        .store()
        .get_session("creation-clock-order")
        .await?
        .ok_or("ordered clock readback missing")?;
    assert_eq!(readback.id(), session.id());
    for (name, returned, stored) in [
        ("createdAt", session.created_at(), readback.created_at()),
        ("updatedAt", session.updated_at(), readback.updated_at()),
        ("expiresAt", session.expires_at(), readback.expires_at()),
    ] {
        assert_eq!(stored.timestamp_millis(), returned.timestamp_millis());
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
            db.text(&query, &["creation-clock-order"]).await?,
            Some(alibi::utils::datetime::json_date_millis(
                stored.timestamp_millis()
            ))
        );
    }
    assert_eq!(
        native::to_value(&JsValue::Date(session.expires_at()))?,
        case["output"]["expiresAt"]
    );
    drop(auth);
    B::close(connection).await
}
