use super::*;

#[cfg(feature = "seaorm-mysql")]
mod mysql;

backend_tests!(
    creation_sync_string_preserves_driver_precision,
    creation_async_string_preserves_driver_precision,
    refresh_sync_string_preserves_driver_precision,
    refresh_async_string_preserves_driver_precision,
    creation_sync_compatible_string_preserves_driver_precision,
    creation_async_compatible_string_preserves_driver_precision,
    refresh_sync_compatible_string_preserves_driver_precision,
    refresh_async_compatible_string_preserves_driver_precision
);
postgres_tests!(
    creation_sync_string_preserves_driver_precision,
    creation_async_string_preserves_driver_precision,
    refresh_sync_string_preserves_driver_precision,
    refresh_async_string_preserves_driver_precision,
    creation_sync_compatible_string_preserves_driver_precision,
    creation_async_compatible_string_preserves_driver_precision,
    refresh_sync_compatible_string_preserves_driver_precision,
    refresh_async_compatible_string_preserves_driver_precision
);

fn input(
    events: &Events,
    value: Option<JsValue>,
    applying: bool,
    compatible: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    if !applying {
        return transform(events, value, false);
    }
    event(events, "input", value.as_ref())?;
    Ok(Some(JsValue::String(
        if compatible {
            "2035-02-03 04:05:06.123987"
        } else {
            "2035-02-03T04:05:06.123987Z"
        }
        .into(),
    )))
}

async fn check<B: Backend>(
    db: Db,
    asynchronous: bool,
    operation: &str,
    compatible: bool,
) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if compatible {
        include_str!("../../../fixtures/session-timestamp-hooks-string-compatible.json")
    } else {
        include_str!("../../../fixtures/session-timestamp-hooks-string.json")
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
    assert_eq!(cases.len(), 5);
    let events = Events::default();
    let inputs = events.clone();
    let applying_input = Arc::new(AtomicBool::new(false));
    let applying = applying_input.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            let applying = applying.clone();
            async move { input(&inputs, value, applying.load(Ordering::SeqCst), compatible) }
        })
    } else {
        field.transform(move |value| {
            input(
                &inputs,
                value.cloned(),
                applying.load(Ordering::SeqCst),
                compatible,
            )
        })
    };
    let mut config = AuthConfig::new(secret);
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
    let mut checked = 0;
    for case in cases.iter().filter(|case| case["operation"] == operation) {
        checked += 1;
        let kind = case["kind"].as_str().unwrap();
        let token = format!("timestamp-{operation}-{kind}");
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
        let session = if operation == "create" {
            if kind == "date" {
                create.expires_at = case["input"].as_str().unwrap().parse()?;
            } else {
                assert_eq!(kind, "string");
                _ = create
                    .additional_fields
                    .insert("expiresAt".into(), case["input"].clone().into());
            }
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            auth.store().create_session(create).await?
        } else {
            assert_eq!(operation, "update");
            applying_input.store(false, Ordering::SeqCst);
            let original = auth.store().create_session(create).await?;
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            let updated = if kind == "date" {
                auth.store()
                    .refresh_session(&token, case["input"].as_str().unwrap().parse()?)
                    .await?
            } else {
                let mut fields = alibi::field_policy::FieldValues::new();
                if kind == "string" {
                    _ = fields.insert("expiresAt".into(), case["input"].clone().into());
                } else {
                    assert_eq!(kind, "omitted");
                }
                auth.store().update_session_fields(&token, fields).await?
            }
            .ok_or("string-result session update missing")?;
            assert_eq!(updated.id(), original.id());
            updated
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{operation}/{kind} callback phases"
        );
        assert_eq!(
            native::to_value(&JsValue::Date(session.expires_at()))?,
            case["output"],
            "{backend}/{operation}/{kind} returned JS expiry"
        );
        let readback = auth
            .store()
            .get_session(&token)
            .await?
            .ok_or("string-result readback missing")?;
        assert_eq!(readback.id(), session.id());
        assert_eq!(
            native::to_value(&JsValue::Date(readback.expires_at()))?,
            case["readback"],
            "{backend}/{operation}/{kind} readback JS expiry"
        );
        let physical = if db.is_postgres() {
            db.text("SELECT to_char(\"expiresAt\" AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM session WHERE token = $1", &[&token]).await?
        } else {
            db.text(
                "SELECT CAST(\"expiresAt\" AS TEXT) FROM session WHERE token = $1",
                &[&token],
            )
            .await?
        };
        assert_eq!(
            json!(physical),
            case["physical"],
            "{backend}/{operation}/{kind} exact stored callback text or driver microseconds"
        );
    }
    assert_eq!(checked, if operation == "create" { 2 } else { 3 });
    drop(auth);
    B::close(connection).await
}

async fn creation_sync_string_preserves_driver_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create", false).await
}
async fn creation_async_string_preserves_driver_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create", false).await
}
async fn refresh_sync_string_preserves_driver_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update", false).await
}
async fn refresh_async_string_preserves_driver_precision<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "update", false).await
}
async fn creation_sync_compatible_string_preserves_driver_precision<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "create", true).await
}
async fn creation_async_compatible_string_preserves_driver_precision<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "create", true).await
}
async fn refresh_sync_compatible_string_preserves_driver_precision<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "update", true).await
}
async fn refresh_async_compatible_string_preserves_driver_precision<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "update", true).await
}
