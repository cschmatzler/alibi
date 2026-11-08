use super::*;

backend_tests!(
    creation_sync_updated_at_matches_source,
    creation_async_updated_at_matches_source,
    refresh_sync_updated_at_matches_source,
    refresh_async_updated_at_matches_source
);
postgres_tests!(
    creation_sync_updated_at_matches_source,
    creation_async_updated_at_matches_source,
    refresh_sync_updated_at_matches_source,
    refresh_async_updated_at_matches_source
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
            input.additional_fields.get("updatedAt"),
        )?;
        Ok(HookControl::Continue)
    }
    async fn before_update_session(
        &self,
        _: &str,
        fields: &mut alibi::field_policy::FieldValues,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(&self.0, "update.before", fields.get("updatedAt"))?;
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
            Some(&JsValue::Date(session.updated_at())),
        )
    }
    async fn after_update_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(
            &self.0,
            "update.after",
            Some(&JsValue::Date(session.updated_at())),
        )
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool, operation: &str) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/session-updated-at-hooks.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["field"], "updatedAt");
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
    assert_eq!(cases.len(), 5);
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
    _ = config
        .session
        .additional_fields
        .insert("updatedAt".into(), field);
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
    for case in cases.iter().filter(|case| case["operation"] == operation) {
        checked += 1;
        let kind = case["kind"].as_str().unwrap();
        let token = format!("timestamp-{operation}-{kind}");
        let mut create = CreateSession {
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
        let mut fields = alibi::field_policy::FieldValues::new();
        if kind == "date" {
            _ = fields.insert(
                "updatedAt".into(),
                JsValue::Date(case["input"].as_str().unwrap().parse()?),
            );
        } else if kind == "string" {
            _ = fields.insert("updatedAt".into(), case["input"].clone().into());
        } else {
            assert_eq!(kind, "omitted");
        }
        let session = if operation == "create" {
            create.additional_fields = fields;
            events.lock().unwrap().clear();
            auth.store().create_session(create).await?
        } else {
            assert_eq!(operation, "update");
            _ = create.additional_fields.insert(
                "updatedAt".into(),
                JsValue::Date("2030-01-01T00:00:00.123Z".parse()?),
            );
            let original = auth.store().create_session(create).await?;
            events.lock().unwrap().clear();
            let updated = auth
                .store()
                .update_session_fields(&token, fields)
                .await?
                .ok_or("updated-at policy row missing")?;
            assert_eq!(updated.id(), original.id());
            updated
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{operation}/{kind} updated-at callback phases"
        );
        assert_eq!(
            native::to_value(&JsValue::Date(session.updated_at()))?,
            case["output"]
        );
        let readback = auth
            .store()
            .get_session(&token)
            .await?
            .ok_or("updated-at policy readback missing")?;
        assert_eq!(readback.id(), session.id());
        assert_eq!(
            native::to_value(&JsValue::Date(readback.updated_at()))?,
            case["readback"]
        );
        let stored = if db.is_postgres() {
            db.text("SELECT to_char(\"updatedAt\" AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') FROM session WHERE token = $1", &[&token]).await?
        } else {
            db.text(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ',\"updatedAt\") FROM session WHERE token = $1",
                &[&token],
            )
            .await?
        };
        assert_eq!(
            json!(stored),
            case["readback"],
            "{backend}/{operation}/{kind} actual SQL updated-at"
        );
    }
    assert_eq!(checked, if operation == "create" { 2 } else { 3 });
    drop(auth);
    B::close(connection).await
}

async fn creation_sync_updated_at_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create").await
}
async fn creation_async_updated_at_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create").await
}
async fn refresh_sync_updated_at_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update").await
}
async fn refresh_async_updated_at_matches_source<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "update").await
}
