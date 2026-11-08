use super::*;

backend_tests!(
    missing_session_sync_policy_matches_driver_phases,
    missing_session_async_policy_matches_driver_phases
);
postgres_tests!(
    missing_session_sync_policy_matches_driver_phases,
    missing_session_async_policy_matches_driver_phases
);

struct Hooks(Events);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Hooks {
    async fn before_update_session(
        &self,
        _: &str,
        fields: &mut alibi::field_policy::FieldValues,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(&self.0, "update.before", fields.get("expiresAt"))?;
        Ok(HookControl::Continue)
    }

    async fn after_update_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(
            &self.0,
            "update.after",
            Some(&JsValue::Date(session.expires_at())),
        )
    }

    async fn after_update_session_missing(
        &self,
        _: &str,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(&self.0, "update.after", Some(&JsValue::Null))
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool) -> TestResult {
    let secret = "session-timestamp-missing-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/session-timestamp-missing.json"
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
    assert_eq!(cases.len(), 10);
    let events = Events::default();
    let observed = events.clone();
    let callback_result = Arc::new(Mutex::new(JsValue::Undefined));
    let output = callback_result.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let observed = observed.clone();
            let output = output.clone();
            async move {
                event(&observed, "input", value.as_ref())?;
                Ok(Some(output.lock().unwrap().clone()))
            }
        })
    } else {
        field.transform(move |value| {
            event(&observed, "input", value)?;
            Ok(Some(output.lock().unwrap().clone()))
        })
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .session
        .additional_fields
        .insert("expiresAt".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        Hooks(events.clone()),
    );
    let auth = AuthBuilder::new(config).store(store).build().await?;
    for case in cases {
        let kind = case["result_kind"].as_str().unwrap();
        *callback_result.lock().unwrap() = match kind {
            "date" => JsValue::Date(case["callback_result"].as_str().unwrap().parse()?),
            "string" | "invalid-string" => case["callback_result"].clone().into(),
            "null" => {
                assert_eq!(case["callback_result"], Value::Null);
                JsValue::Null
            }
            "undefined" => {
                assert!(case.get("callback_result").is_none());
                JsValue::Undefined
            }
            _ => return Err("unexpected source missing-session result kind".into()),
        };
        events.lock().unwrap().clear();
        let result = if case["input_kind"] == "date" {
            auth.store()
                .refresh_session("missing-token", case["input"].as_str().unwrap().parse()?)
                .await
        } else {
            assert_eq!(case["input_kind"], "string");
            let mut fields = alibi::field_policy::FieldValues::new();
            _ = fields.insert("expiresAt".into(), case["input"].clone().into());
            auth.store()
                .update_session_fields("missing-token", fields)
                .await
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{kind}/{} callback phases",
            case["input_kind"]
        );
        if let Some(expected) = case["outcome"].get("error") {
            let error = result
                .err()
                .ok_or("source missing-session driver error became nullable success")?;
            assert!(
                matches!(&error, alibi::AuthError::Database(_)),
                "{backend}/{kind}: {error}"
            );
            assert_eq!(expected["code"], "22007");
            assert!(
                error
                    .to_string()
                    .contains(expected["message"].as_str().unwrap()),
                "{backend}/{kind}: {error}"
            );
        } else {
            assert!(
                result?.is_none(),
                "missing session must not produce a fabricated model"
            );
            assert_eq!(case["outcome"]["output"], Value::Null);
        }
        assert_eq!(db.count("session").await?, case["rows"].as_i64().unwrap());
        assert!(auth.store().get_session("missing-token").await?.is_none());
    }
    drop(auth);
    B::close(connection).await
}

async fn missing_session_sync_policy_matches_driver_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false).await
}
async fn missing_session_async_policy_matches_driver_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true).await
}
