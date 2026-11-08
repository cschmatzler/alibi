use super::*;

backend_tests!(
    sync_omitted_creation_clock_reaches_required_constraint,
    async_omitted_creation_clock_reaches_required_constraint
);
postgres_tests!(
    sync_omitted_creation_clock_reaches_required_constraint,
    async_omitted_creation_clock_reaches_required_constraint
);

struct Hooks(Events);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Hooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(
            &self.0,
            "create.before",
            input.additional_fields.get("createdAt"),
        )?;
        Ok(HookControl::Continue)
    }

    async fn after_create_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(
            &self.0,
            "create.after",
            Some(&JsValue::Date(session.created_at())),
        )
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/session-created-at-hooks-omit-required.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["field"], "createdAt");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let profile = profiles
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap();
    if db.is_postgres() {
        assert!(profile["schema_sql"].as_str().unwrap().contains(
            "\"token\" text not null unique, \"createdAt\" timestamptz not null, \"updatedAt\" timestamptz not null"
        ));
        assert_eq!(
            db.text("SELECT column_default FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'session' AND column_name = 'createdAt'", &[]).await?,
            Some("CURRENT_TIMESTAMP".to_owned())
        );
        // The replacement descriptor also removes the builtin SQL default.
        _ = db
            .execute(
                "ALTER TABLE session ALTER COLUMN \"createdAt\" DROP DEFAULT",
                &[],
            )
            .await?;
        assert_eq!(
            db.text("SELECT column_default FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'session' AND column_name = 'createdAt'", &[]).await?,
            None
        );
    }
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let events = Events::default();
    let inputs = events.clone();
    let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    field.required = true;
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            async move {
                event(&inputs, "input", value.as_ref())?;
                Ok(None)
            }
        })
    } else {
        field.transform(move |value| {
            event(&inputs, "input", value)?;
            Ok(None)
        })
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .session
        .additional_fields
        .insert("createdAt".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        Hooks(events.clone()),
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
    let mut checked = 0;
    for case in cases.iter().filter(|case| case["operation"] == "create") {
        checked += 1;
        let kind = case["kind"].as_str().unwrap();
        let token = format!("timestamp-create-{kind}");
        let mut fields = alibi::field_policy::FieldValues::new();
        let input = if kind == "date" {
            JsValue::Date(case["input"].as_str().unwrap().parse()?)
        } else {
            assert_eq!(kind, "string");
            case["input"].clone().into()
        };
        _ = fields.insert("createdAt".into(), input);
        events.lock().unwrap().clear();
        let result = auth
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
            .await;
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{kind} omitted creation clock phases"
        );
        let error = result
            .err()
            .ok_or("omitted createdAt incorrectly inherited a native creation clock")?;
        assert!(
            matches!(&error, alibi::AuthError::Database(_)),
            "{backend}/{kind}: {error}"
        );
        let expected = &case["outcome"]["error"];
        assert_eq!(
            expected["code"],
            if db.is_postgres() {
                "23502"
            } else {
                "ERR_SQLITE_ERROR"
            }
        );
        assert!(
            error
                .to_string()
                .contains(expected["message"].as_str().unwrap()),
            "{backend}/{kind}: {error}"
        );
        assert_eq!(case["exists"], false);
        assert_eq!(case["readback"], Value::Null);
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM session WHERE token = $1", &[&token])
                .await?,
            0
        );
        assert!(auth.store().get_session(&token).await?.is_none());
    }
    assert_eq!(checked, 2);
    drop(auth);
    B::close(connection).await
}

async fn sync_omitted_creation_clock_reaches_required_constraint<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false).await
}
async fn async_omitted_creation_clock_reaches_required_constraint<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true).await
}
