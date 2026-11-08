use super::*;

backend_tests!(
    sync_omitted_input_evaluates_default,
    async_omitted_input_evaluates_default,
    sync_date_override_still_evaluates_default,
    async_date_override_still_evaluates_default,
    sync_undefined_override_evaluates_default_twice,
    async_undefined_override_evaluates_default_twice,
    sync_null_override_evaluates_default_twice,
    async_null_override_evaluates_default_twice
);
postgres_tests!(
    sync_omitted_input_evaluates_default,
    async_omitted_input_evaluates_default,
    sync_date_override_still_evaluates_default,
    async_date_override_still_evaluates_default,
    sync_undefined_override_evaluates_default_twice,
    async_undefined_override_evaluates_default_twice,
    sync_null_override_evaluates_default_twice,
    async_null_override_evaluates_default_twice
);

#[derive(Default)]
struct Window {
    factory_ends: Vec<i64>,
    hook_start: Option<i64>,
    hook_end: Option<i64>,
    created_at: Option<i64>,
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
        let created = input.additional_fields.get("createdAt");
        {
            let mut window = self.window.lock().unwrap();
            window.hook_start = Some(chrono::Utc::now().timestamp_millis());
            window.created_at = match created {
                Some(JsValue::Date(date)) => Some(date.timestamp_millis()),
                _ => None,
            };
        }
        self.events.lock().unwrap().push(json!({
            "phase":"create.before",
            "createdAt":if matches!(created,Some(JsValue::Date(_))) { json!("$clock") } else { Value::Null },
            "updatedAt":before_clock(input.additional_fields.get("updatedAt"),true)?,
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
            "phase":"create.after", "createdAt":JsValue::Date(session.created_at()), "updatedAt":JsValue::Date(session.updated_at()),
        }));
        Ok(())
    }
}

fn input(events: &Events, value: Option<JsValue>) -> alibi::AuthResult<Option<JsValue>> {
    let Some(JsValue::Date(date)) = value else {
        return Err(alibi::AuthError::internal(
            "default evaluation policy expected a Date",
        ));
    };
    events
        .lock()
        .unwrap()
        .push(json!({"phase":"input","kind":"date","value":JsValue::Date(date)}));
    Ok(Some(JsValue::Date(date + chrono::Duration::seconds(1))))
}

async fn check<B: Backend>(db: Db, asynchronous: bool, input_kind: &str) -> TestResult {
    let secret = "session-default-evaluation-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/session-creation-default-evaluation.json"
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
    let window = Arc::new(Mutex::new(Window::default()));
    let default_events = events.clone();
    let default_window = window.clone();
    let default_value: chrono::DateTime<chrono::Utc> =
        cases[0]["default_value"].as_str().unwrap().parse()?;
    let mut field =
        alibi::field_policy::FieldConfig::new(json!({"type":"date"})).default_callback(move || {
            default_events
                .lock()
                .unwrap()
                .push(json!({"phase":"default"}));
            // Configured default factories are synchronous in the source API.
            std::thread::sleep(std::time::Duration::from_millis(20));
            default_window
                .lock()
                .unwrap()
                .factory_ends
                .push(chrono::Utc::now().timestamp_millis());
            JsValue::Date(default_value)
        });
    field.required = true;
    let observed = events.clone();
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let observed = observed.clone();
            async move { input(&observed, value) }
        })
    } else {
        field.transform(move |value| input(&observed, value.cloned()))
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .session
        .additional_fields
        .insert("updatedAt".into(), field);
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
                .with_name("Default Evaluation")
                .with_email("default-evaluation@example.com"),
        )
        .await?;
    let mut checked = 0;
    for case in cases.iter().filter(|case| case["kind"] == input_kind) {
        checked += 1;
        let kind = case["kind"].as_str().unwrap();
        let mut fields = alibi::field_policy::FieldValues::new();
        match kind {
            "omitted" => {}
            "date" => {
                _ = fields.insert(
                    "updatedAt".into(),
                    JsValue::Date(case["input"].as_str().unwrap().parse()?),
                );
            }
            "undefined" => {
                _ = fields.insert("updatedAt".into(), JsValue::Undefined);
            }
            "null" => {
                assert_eq!(case["input"], Value::Null);
                _ = fields.insert("updatedAt".into(), JsValue::Null);
            }
            _ => return Err("unexpected source default-evaluation input".into()),
        }
        events.lock().unwrap().clear();
        *window.lock().unwrap() = Window::default();
        let token = format!("default-evaluation-{kind}");
        let session = auth
            .store()
            .create_session(CreateSession {
                additional_fields: fields,
                user_id: owner.id().into_owned(),
                token: Some(token.clone()),
                expires_at: "2039-01-01T00:00:00.123Z".parse()?,
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await?;
        let mut observed = events.lock().unwrap().clone();
        for event in &mut observed {
            if event["phase"] == "create.after" {
                let value = event["createdAt"]
                    .as_str()
                    .ok_or("default evaluation after-hook must retain a Date")?;
                let date: chrono::DateTime<chrono::Utc> = value.parse()?;
                assert_eq!(
                    value,
                    alibi::utils::datetime::json_date_millis(date.timestamp_millis())
                );
                event["createdAt"] = json!("$clock");
            }
        }
        assert_eq!(
            json!(observed),
            case["events"],
            "{backend}/{kind} default-evaluation phases"
        );
        {
            let window = window.lock().unwrap();
            assert_eq!(json!(window.factory_ends.len()), case["factory_calls"]);
            let created = window
                .created_at
                .ok_or("default-evaluation before-hook clock missing")?;
            assert_eq!(
                json!(created >= window.factory_ends[0]),
                case["created_after_first_factory"]
            );
            assert_eq!(
                json!(created <= window.hook_start.ok_or("before-hook start missing")?),
                case["created_before_hook"]
            );
            assert!(created < window.hook_end.ok_or("before-hook end missing")?);
            if let Some(expected) = case.get("second_factory_after_hook") {
                assert_eq!(
                    json!(window.factory_ends[1] >= window.hook_end.unwrap()),
                    *expected
                );
            }
            assert_eq!(session.created_at().timestamp_millis(), created);
        }
        assert_eq!(
            native::to_value(&JsValue::Date(session.updated_at()))?,
            case["output"]["updatedAt"]
        );
        let readback = auth
            .store()
            .get_session(&token)
            .await?
            .ok_or("default evaluation readback missing")?;
        assert_eq!(readback.id(), session.id());
        assert_eq!(
            readback.created_at().timestamp_millis(),
            session.created_at().timestamp_millis()
        );
        assert_eq!(
            readback.updated_at().timestamp_millis(),
            session.updated_at().timestamp_millis()
        );
        for (name, date) in [
            ("createdAt", session.created_at()),
            ("updatedAt", session.updated_at()),
        ] {
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
                db.text(&query, &[&token]).await?,
                Some(alibi::utils::datetime::json_date_millis(
                    date.timestamp_millis()
                ))
            );
        }
    }
    assert_eq!(checked, 1);
    drop(auth);
    B::close(connection).await
}

async fn sync_omitted_input_evaluates_default<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "omitted").await
}
async fn async_omitted_input_evaluates_default<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "omitted").await
}
async fn sync_date_override_still_evaluates_default<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "date").await
}
async fn async_date_override_still_evaluates_default<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "date").await
}
async fn sync_undefined_override_evaluates_default_twice<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "undefined").await
}
async fn async_undefined_override_evaluates_default_twice<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "undefined").await
}
async fn sync_null_override_evaluates_default_twice<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "null").await
}
async fn async_null_override_evaluates_default_twice<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "null").await
}
