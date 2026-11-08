use super::*;

struct Hooks(Events);

fn input(
    events: &Events,
    value: Option<JsValue>,
    applying: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    events
        .lock()
        .unwrap()
        .push(json!({"phase":"input","value":value}));
    Ok(if applying {
        Some(JsValue::String("2035-02-03 04:05:06.123987".into()))
    } else {
        value
    })
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Hooks {
    async fn before_update_session(
        &self,
        _: &str,
        fields: &mut alibi::field_policy::FieldValues,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        self.0.lock().unwrap().push(json!({
            "phase":"update.before", "token":fields.get("token"), "expiresAt":fields.get("expiresAt"),
        }));
        Ok(HookControl::Continue)
    }

    async fn after_update_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        self.0.lock().unwrap().push(json!({
            "phase":"update.after", "token":session.token(), "expiresAt":JsValue::Date(session.expires_at()),
        }));
        Ok(())
    }

    async fn after_update_session_missing(
        &self,
        _: &str,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(json!({"phase":"update.after","token":null,"expiresAt":null}));
        Ok(())
    }
}

async fn check(asynchronous: bool) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/session-token-timestamp-mysql.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backend"], "mysql");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    let admin =
        alibi::seaorm::Database::connect(std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?).await?;
    let database = format!("alibi_session_token_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in fixture["schema_sql"]
        .as_str()
        .unwrap()
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    _ = connection.execute_unprepared("INSERT INTO `user` (`id`,`name`,`email`,`emailVerified`,`createdAt`,`updatedAt`) VALUES ('token-owner','Token Timestamp','session-token-timestamp@example.com',false,'2020-01-01 00:00:00.123','2020-01-01 00:00:00.123')").await?;
    let events = Events::default();
    let inputs = events.clone();
    let applying_input = Arc::new(AtomicBool::new(false));
    let applying = applying_input.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            let applying = applying.clone();
            async move { input(&inputs, value, applying.load(Ordering::SeqCst)) }
        })
    } else {
        field
            .transform(move |value| input(&inputs, value.cloned(), applying.load(Ordering::SeqCst)))
    };
    let mut config = AuthConfig::new("session-token-timestamp-secret-at-least-32");
    _ = config
        .session
        .additional_fields
        .insert("expiresAt".into(), field);
    let store =
        alibi::seaorm::SeaOrmStore::<Schema>::new(Arc::new(config.clone()), connection.clone())
            .hook(Hooks(events.clone()));
    let auth = AuthBuilder::new(config).store(store).build().await?;
    for case in cases {
        let token = case["token"].as_str().unwrap();
        let next_token = case["input"]["token"].as_str().unwrap();
        applying_input.store(false, Ordering::SeqCst);
        let original = auth
            .store()
            .create_session(CreateSession {
                additional_fields: Default::default(),
                user_id: "token-owner".into(),
                token: Some(token.into()),
                expires_at: "2031-01-01T00:00:00.123Z".parse()?,
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await?;
        applying_input.store(true, Ordering::SeqCst);
        events.lock().unwrap().clear();
        let mut fields = alibi::field_policy::FieldValues::new();
        _ = fields.insert("token".into(), JsValue::String(next_token.into()));
        _ = fields.insert(
            "expiresAt".into(),
            JsValue::Date(case["input"]["expiresAt"].as_str().unwrap().parse()?),
        );
        let updated = auth.store().update_session_fields(token, fields).await?;
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "changed token {} callbacks",
            case["change_token"]
        );
        let updated = updated.ok_or("changed token update lost its returned row")?;
        assert_eq!(updated.id(), original.id());
        assert_eq!(json!(updated.token()), case["returned_token"]);
        assert_eq!(
            native::to_value(&JsValue::Date(updated.expires_at()))?,
            case["expiresAt"]
        );
        let old = auth.store().get_session(token).await?;
        let new = auth.store().get_session(next_token).await?;
        assert_eq!(json!(old.is_some()), case["old_exists"]);
        assert_eq!(json!(new.is_some()), case["new_exists"]);
        assert_eq!(new.ok_or("new token missing")?.id(), original.id());
        let row = connection.query_one_raw(Statement::from_sql_and_values(DbBackend::MySql,"SELECT token,DATE_FORMAT(expiresAt,'%Y-%m-%dT%H:%i:%s.%fZ') AS expiresAt FROM session WHERE token = ?",[next_token.into()])).await?.ok_or("physical new token missing")?;
        let stored_token: String = row.try_get("", "token")?;
        let expiry: String = row.try_get("", "expiresAt")?;
        assert_eq!(
            json!([{ "token":stored_token,"expiresAt":expiry }]),
            case["rows"]
        );
    }
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn sync_timestamp_text_reselects_updated_token() -> TestResult {
    check(false).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn async_timestamp_text_reselects_updated_token() -> TestResult {
    check(true).await
}
