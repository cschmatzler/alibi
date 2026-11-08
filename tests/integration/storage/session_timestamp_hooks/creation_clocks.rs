use super::*;

mod builtin_defaults;
mod default_evaluation;
mod omission;
mod order;

backend_tests!(
    builtin_creation_clocks_precede_database_hooks,
    sync_creation_clock_policies_follow_database_hooks,
    async_creation_clock_policies_follow_database_hooks,
    sync_creation_clock_defaults_precede_database_hooks,
    async_creation_clock_defaults_precede_database_hooks
);
postgres_tests!(
    builtin_creation_clocks_precede_database_hooks,
    sync_creation_clock_policies_follow_database_hooks,
    async_creation_clock_policies_follow_database_hooks,
    sync_creation_clock_defaults_precede_database_hooks,
    async_creation_clock_defaults_precede_database_hooks
);

struct Hooks {
    events: Events,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    custom_defaults: bool,
}

fn before_clock(value: Option<&JsValue>, custom_defaults: bool) -> alibi::AuthResult<Value> {
    Ok(match value {
        Some(JsValue::Date(date)) => json!({"kind":"date","value":if custom_defaults {
            native::to_value(&JsValue::Date(*date))?
        } else { json!("$clock") }}),
        None | Some(JsValue::Undefined) => json!({"kind":"undefined","value":null}),
        Some(JsValue::Null) => json!({"kind":"null","value":null}),
        Some(value) => json!({"kind":"unexpected","value":native::to_value(value)?}),
    })
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
            "createdAt":before_clock(input.additional_fields.get("createdAt"),self.custom_defaults)?,
            "updatedAt":before_clock(input.additional_fields.get("updatedAt"),self.custom_defaults)?,
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

fn transform(
    events: &Events,
    name: &str,
    value: Option<JsValue>,
) -> alibi::AuthResult<Option<JsValue>> {
    let Some(JsValue::Date(date)) = value else {
        return Err(alibi::AuthError::internal(
            "creation clock policy expected a Date",
        ));
    };
    events
        .lock()
        .unwrap()
        .push(json!({"phase":"input","field":name,"kind":"date","value":JsValue::Date(date)}));
    Ok(Some(JsValue::Date(date + chrono::Duration::seconds(1))))
}

async fn check<B: Backend>(db: Db, policy: &str, asynchronous: bool) -> TestResult {
    let secret = "session-creation-clocks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/session-creation-clocks.json"
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
    assert_eq!(cases.len(), 3);
    let case = cases.iter().find(|case| case["policy"] == policy).unwrap();
    let events = Events::default();
    let mut config = AuthConfig::new(secret);
    if policy != "builtin" {
        for name in ["createdAt", "updatedAt"] {
            let observed = events.clone();
            let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
            field.required = true;
            if let Some(defaults) = case.get("defaults") {
                field =
                    field.default_value(JsValue::Date(defaults[name].as_str().unwrap().parse()?));
            }
            let field = if asynchronous {
                field.transform_adapter_input(move |value| {
                    let observed = observed.clone();
                    async move { transform(&observed, name, value) }
                })
            } else {
                field.transform(move |value| transform(&observed, name, value.cloned()))
            };
            _ = config.session.additional_fields.insert(name.into(), field);
        }
    }
    let hooks = Hooks {
        events: events.clone(),
        created_at: case["hook_clocks"]["createdAt"].as_str().unwrap().parse()?,
        updated_at: case["hook_clocks"]["updatedAt"].as_str().unwrap().parse()?,
        custom_defaults: case.get("defaults").is_some(),
    };
    let store = B::hook(B::store(Arc::new(config.clone()), &connection), hooks);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Creation Clocks")
                .with_email(format!("{policy}@creation-clocks.example.com")),
        )
        .await?;
    let token = format!("creation-clocks-{policy}");
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: Default::default(),
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
    assert_eq!(
        json!(*events.lock().unwrap()),
        case["events"],
        "{backend}/{policy} creation clock phases"
    );
    assert_eq!(
        json!({"createdAt":JsValue::Date(session.created_at()),"updatedAt":JsValue::Date(session.updated_at())}),
        case["output"]
    );
    let readback = auth
        .store()
        .get_session(&token)
        .await?
        .ok_or("creation clock readback missing")?;
    assert_eq!(readback.id(), session.id());
    assert_eq!(
        json!({"createdAt":JsValue::Date(readback.created_at()),"updatedAt":JsValue::Date(readback.updated_at())}),
        case["readback"]
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
            case["readback"][name],
            "{backend}/{policy} physical {name}"
        );
    }
    drop(auth);
    B::close(connection).await
}

async fn builtin_creation_clocks_precede_database_hooks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "builtin", false).await
}
async fn sync_creation_clock_policies_follow_database_hooks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "declared", false).await
}
async fn async_creation_clock_policies_follow_database_hooks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "declared", true).await
}
async fn sync_creation_clock_defaults_precede_database_hooks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "custom-defaults", false).await
}
async fn async_creation_clock_defaults_precede_database_hooks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "custom-defaults", true).await
}
