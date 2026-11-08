use super::*;

backend_tests!(
    builtin_created_at_undefined_runs_factory_after_hook,
    builtin_updated_at_undefined_reaches_required_constraint,
    builtin_created_at_null_runs_factory_after_hook,
    builtin_updated_at_null_reaches_required_constraint
);
postgres_tests!(
    builtin_created_at_undefined_runs_factory_after_hook,
    builtin_updated_at_undefined_reaches_required_constraint,
    builtin_created_at_null_runs_factory_after_hook,
    builtin_updated_at_null_reaches_required_constraint
);

struct Hooks {
    events: Events,
    end: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
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
        // Distinguish the data-construction clocks from post-hook adapter defaults.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        *self.end.lock().unwrap() = Some(chrono::Utc::now());
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

async fn check<B: Backend>(db: Db, field: &str, null_input: bool) -> TestResult {
    let secret = "session-builtin-undefined-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if null_input {
        include_str!("../../../../fixtures/session-builtin-null-clocks.json")
    } else {
        include_str!("../../../../fixtures/session-builtin-undefined-clocks.json")
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
    let case = cases.iter().find(|case| case["field"] == field).unwrap();
    let events = Events::default();
    let end = Arc::new(Mutex::new(None));
    let config = AuthConfig::new(secret);
    let hooks = Hooks {
        events: events.clone(),
        end: end.clone(),
    };
    let store = B::hook(B::store(Arc::new(config.clone()), &connection), hooks);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Builtin Undefined")
                .with_email("builtin-undefined@example.com"),
        )
        .await?;
    let token = format!(
        "builtin-{field}-{}",
        if null_input { "null" } else { "undefined" }
    );
    let mut fields = alibi::field_policy::FieldValues::new();
    _ = fields.insert(
        field.into(),
        if null_input {
            JsValue::Null
        } else {
            JsValue::Undefined
        },
    );
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
    let returned_at = chrono::Utc::now().timestamp_millis();
    let mut observed = events.lock().unwrap().clone();
    for event in &mut observed {
        if event["phase"] == "create.after" {
            for name in ["createdAt", "updatedAt"] {
                let value = event[name]
                    .as_str()
                    .ok_or("native after-hook clock must be a date string")?;
                let date: chrono::DateTime<chrono::Utc> = value.parse()?;
                assert_eq!(
                    value,
                    alibi::utils::datetime::json_date_millis(date.timestamp_millis())
                );
                event[name] = json!("$clock");
            }
        }
    }
    assert_eq!(
        json!(observed),
        case["events"],
        "{backend}/{field}/{null_input} builtin clock phases"
    );
    let readback = if let Some(expected) = case["outcome"].get("error") {
        let error = result
            .err()
            .ok_or("builtin updatedAt incorrectly inherited a creation default")?;
        assert!(
            matches!(&error, alibi::AuthError::Database(_)),
            "{backend}/{field}: {error}"
        );
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
            "{backend}/{field}: {error}"
        );
        let readback = auth.store().get_session(&token).await?;
        assert!(readback.is_none());
        None
    } else {
        let session = result?;
        let hook_end = end
            .lock()
            .unwrap()
            .ok_or("delayed before-hook did not finish")?
            .timestamp_millis();
        assert_eq!(
            json!(session.created_at().timestamp_millis() >= hook_end),
            case["outcome"]["created_after_hook"],
            "{backend}/{field} builtin factory timing"
        );
        assert_eq!(
            json!(session.created_at().timestamp_millis() <= returned_at),
            case["outcome"]["created_before_return"],
            "{backend}/{field} factory clock upper bound"
        );
        assert_eq!(
            json!(session.updated_at().timestamp_millis() < hook_end),
            case["outcome"]["updated_before_hook"],
            "{backend}/{field} original update clock timing"
        );
        let readback = auth
            .store()
            .get_session(&token)
            .await?
            .ok_or("builtin undefined clock readback missing")?;
        assert_eq!(readback.id(), session.id());
        assert_eq!(
            readback.created_at().timestamp_millis(),
            session.created_at().timestamp_millis()
        );
        assert_eq!(
            readback.updated_at().timestamp_millis(),
            session.updated_at().timestamp_millis()
        );
        Some(readback)
    };
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM session WHERE token = $1", &[&token])
            .await?,
        case["rows"].as_i64().unwrap()
    );
    if let Some(readback) = readback {
        for (name, date) in [
            ("createdAt", readback.created_at()),
            ("updatedAt", readback.updated_at()),
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
    drop(auth);
    B::close(connection).await
}

async fn builtin_created_at_undefined_runs_factory_after_hook<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "createdAt", false).await
}
async fn builtin_updated_at_undefined_reaches_required_constraint<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, "updatedAt", false).await
}

async fn builtin_created_at_null_runs_factory_after_hook<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "createdAt", true).await
}
async fn builtin_updated_at_null_reaches_required_constraint<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, "updatedAt", true).await
}
