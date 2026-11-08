use super::super::SeaOrm;
use super::*;
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

fn input(
    events: &Events,
    value: Option<JsValue>,
    compatible: bool,
    applying: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    if compatible
        && applying
        && value
            .as_ref()
            .is_some_and(|value| !value.is_null() && !value.is_undefined())
    {
        event(events, "input", value.as_ref())?;
        return Ok(Some(JsValue::String("2035-02-03 04:05:06.123987".into())));
    }
    transform(events, value, ResultMode::String, applying)
}

async fn check(asynchronous: bool, compatible: bool) -> TestResult {
    let fixture: Value = serde_json::from_str(if compatible {
        include_str!("../../../fixtures/account-timestamp-mysql-compatible-hooks.json")
    } else {
        include_str!("../../../fixtures/account-timestamp-mysql-hooks.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backend"], "mysql");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_account_dates_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
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
    _ = connection.execute_unprepared("INSERT INTO `user` (`id`, `name`, `email`, `emailVerified`, `createdAt`, `updatedAt`) VALUES ('account-owner', 'Timestamp', 'account-timestamp@example.com', false, '2020-01-01 00:00:00.123', '2020-01-01 00:00:00.123')").await?;
    let events = Events::default();
    let observed = events.clone();
    let applying_input = Arc::new(AtomicBool::new(false));
    let applying = applying_input.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let observed = observed.clone();
            let applying = applying.clone();
            async move {
                input(
                    &observed,
                    value,
                    compatible,
                    applying.load(Ordering::SeqCst),
                )
            }
        })
    } else {
        field.transform(move |value| {
            input(
                &observed,
                value.cloned(),
                compatible,
                applying.load(Ordering::SeqCst),
            )
        })
    };
    let mut config = AuthConfig::new("account-timestamp-parameters-secret-at-least-32");
    _ = config
        .account
        .additional_fields
        .insert("accessTokenExpiresAt".into(), field);
    let store = SeaOrm::hook(
        SeaOrm::store(Arc::new(config.clone()), &connection),
        AccountHooks(events.clone()),
    );
    let auth = AuthBuilder::new(config).store(store).build().await?;
    for case in cases {
        let operation = case["operation"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let key = format!("{operation}-{kind}");
        let mut create = CreateAccount {
            additional_fields: Default::default(),
            user_id: "account-owner".into(),
            account_id: key.as_str().into(),
            provider_id: "timestamp-provider".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        };
        let mut original_id = None;
        let result = if operation == "create" {
            if kind == "date" {
                create.access_token_expires_at = Some(case["input"].as_str().unwrap().parse()?);
            } else if kind != "omitted" {
                _ = create
                    .additional_fields
                    .insert("accessTokenExpiresAt".into(), case["input"].clone().into());
            }
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            auth.store().create_account(create).await
        } else {
            assert_eq!(operation, "update");
            applying_input.store(false, Ordering::SeqCst);
            create.access_token_expires_at = Some("2030-01-01T00:00:00.123Z".parse()?);
            let original = auth.store().create_account(create).await?;
            original_id = Some(original.id().into_owned());
            let mut update = UpdateAccount::default();
            if kind == "date" {
                update.access_token_expires_at = Some(case["input"].as_str().unwrap().parse()?);
            } else if kind != "omitted" {
                _ = update
                    .additional_fields
                    .insert("accessTokenExpiresAt".into(), case["input"].clone().into());
            }
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            auth.store()
                .update_account(original.id().as_ref(), update)
                .await
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "mysql/{operation}/{kind}"
        );
        let returned_id = if let Some(error) = case["outcome"].get("error") {
            let actual = result
                .err()
                .ok_or("source MySQL error became a successful account write")?;
            assert!(matches!(&actual, alibi::AuthError::Database(_)));
            assert_eq!(error["code"], "ER_TRUNCATED_WRONG_VALUE");
            assert_eq!(error["sql_state"], "22007");
            assert!(
                actual
                    .to_string()
                    .contains(error["message"].as_str().unwrap()),
                "mysql/{operation}/{kind}: {actual}"
            );
            None
        } else {
            let account = result?;
            assert_eq!(
                native::to_value(
                    &account
                        .access_token_expires_at()
                        .map_or(JsValue::Null, JsValue::Date)
                )?,
                case["outcome"]["output"],
                "mysql/{operation}/{kind}"
            );
            Some(account.id().into_owned())
        };
        let readback = auth
            .store()
            .get_account("timestamp-provider", &key.as_str().into())
            .await?;
        assert_eq!(
            json!(readback.is_some()),
            case["exists"],
            "mysql/{operation}/{kind} row existence"
        );
        if let Some(account) = readback {
            assert_eq!(
                native::to_value(
                    &account
                        .access_token_expires_at()
                        .map_or(JsValue::Null, JsValue::Date)
                )?,
                case["readback"],
                "mysql/{operation}/{kind} readback"
            );
            if let Some(id) = original_id.or(returned_id) {
                assert_eq!(account.id().as_ref(), id);
            }
        }
        let row = connection.query_one_raw(Statement::from_sql_and_values(DbBackend::MySql, "SELECT DATE_FORMAT(`accessTokenExpiresAt`, '%Y-%m-%dT%H:%i:%s.%fZ') AS `value` FROM account WHERE `accountId` = ?", [key.into()])).await?;
        let stored: Option<String> = row
            .map(|row| row.try_get("", "value"))
            .transpose()?
            .flatten();
        let stored = stored
            .as_deref()
            .map(alibi::utils::datetime::parse_date_millis);
        let stored = match stored {
            Some(Some(millis)) => Value::String(alibi::utils::datetime::json_date_millis(millis)),
            None => Value::Null,
            Some(None) => panic!("unparseable physical MySQL date"),
        };
        assert_eq!(
            stored, case["stored"],
            "mysql/{operation}/{kind} physical date"
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
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_account_date_strings_preserve_sync_source_failures() -> TestResult {
    check(false, false).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_account_date_strings_preserve_async_source_failures() -> TestResult {
    check(true, false).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_account_date_strings_preserve_sync_source_rounding() -> TestResult {
    check(false, true).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_account_date_strings_preserve_async_source_rounding() -> TestResult {
    check(true, true).await
}
