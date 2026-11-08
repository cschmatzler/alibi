use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::AdminPlugin;
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::utils::json::{self as native, JsValue};
use alibi::{AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

backend_tests!(
    user_date_strings_precede_sync_adapter_input,
    user_date_strings_precede_async_adapter_input,
    user_date_transform_strings_preserve_sync_driver_values,
    user_date_transform_strings_preserve_async_driver_values
);
postgres_tests!(
    user_date_strings_precede_sync_adapter_input,
    user_date_strings_precede_async_adapter_input,
    user_date_transform_strings_preserve_sync_driver_values,
    user_date_transform_strings_preserve_async_driver_values
);

type Events = Arc<Mutex<Vec<Value>>>;

fn event(events: &Events, phase: &str, value: Option<&JsValue>) -> alibi::AuthResult<()> {
    let kind = match value {
        None | Some(JsValue::Undefined) => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Date(_)) => "date",
        Some(JsValue::String(_)) => "string",
        _ => return Err(alibi::AuthError::internal("unexpected date callback value")),
    };
    let value = value
        .filter(|value| !value.is_undefined())
        .map(native::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
    events
        .lock()
        .unwrap()
        .push(json!({"phase":phase,"kind":kind,"value":value}));
    Ok(())
}

fn transform(
    events: &Events,
    value: Option<JsValue>,
    string_result: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    event(events, "input", value.as_ref())?;
    if string_result
        && value
            .as_ref()
            .is_some_and(|value| !value.is_null() && !value.is_undefined())
    {
        return Ok(Some(JsValue::String("2035-02-03T04:05:06.123987Z".into())));
    }
    Ok(match value {
        None | Some(JsValue::Undefined) => None,
        Some(JsValue::Null) => Some(JsValue::Null),
        Some(JsValue::Date(date)) => Some(JsValue::Date(date + chrono::Duration::seconds(1))),
        Some(JsValue::String(value)) => {
            let date = value
                .as_str()
                .and_then(alibi::utils::datetime::parse_date_millis)
                .and_then(chrono::DateTime::from_timestamp_millis)
                .ok_or_else(|| alibi::AuthError::internal("invalid callback date string"))?;
            Some(JsValue::Date(date + chrono::Duration::seconds(1)))
        }
        _ => return Err(alibi::AuthError::internal("unexpected date callback input")),
    })
}

struct DateHooks(Events);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for DateHooks {
    async fn before_update_user(
        &self,
        _: &str,
        data: &mut native::JsObject,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(&self.0, "before", data.get("banExpires"))?;
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        user: &S::User,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        let value = user.ban_expires().map_or(JsValue::Null, JsValue::Date);
        event(&self.0, "after", Some(&value))
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool, string_result: bool) -> TestResult {
    let secret = "user-timestamp-parameters-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if string_result {
        include_str!("../../fixtures/user-timestamp-hooks-string.json")
    } else {
        include_str!("../../fixtures/user-timestamp-hooks.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let profile = fixture["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap();
    let cases = profile["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let events = Events::default();
    let observed = events.clone();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let observed = observed.clone();
            async move { transform(&observed, value, string_result) }
        })
    } else {
        field.transform(move |value| transform(&observed, value.cloned(), string_result))
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .user
        .additional_fields
        .insert("banExpires".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        DateHooks(events.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("timestamp@example.com"),
        )
        .await?;
    for case in cases {
        events.lock().unwrap().clear();
        let action = case["action"].as_str().unwrap();
        let mut update = UpdateUser {
            banned: Some(action != "unban"),
            ..Default::default()
        };
        match action {
            "date" => update.ban_expires = Some(Some(case["input"].as_str().unwrap().parse()?)),
            "string" => {
                _ = update
                    .adapter_native_fields
                    .insert("banExpires".into(), case["input"].clone().into());
            }
            "unban" => {}
            "clear" => update.ban_expires = Some(None),
            _ => panic!("unknown source date hook action: {action}"),
        }
        let updated = auth.store().update_user(user.id().as_ref(), update).await?;
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{action}"
        );
        let expected: Option<chrono::DateTime<chrono::Utc>> =
            case["output"].as_str().map(str::parse).transpose()?;
        if string_result {
            assert_eq!(
                native::to_value(&updated.ban_expires().map_or(JsValue::Null, JsValue::Date))?,
                case["output"],
                "{backend}/{action}"
            );
            assert_eq!(
                json!(
                    db.text(
                        "SELECT CAST(\"banExpires\" AS TEXT) FROM \"user\" WHERE id = $1",
                        &[user.id().as_ref()]
                    )
                    .await?
                ),
                case["stored"],
                "{backend}/{action} physical parameter"
            );
        } else {
            assert_eq!(updated.ban_expires(), expected, "{backend}/{action}");
        }
        assert_eq!(
            json!(updated.banned()),
            case["banned"],
            "{backend}/{action}"
        );
        let readback = auth
            .store()
            .get_user_by_id(user.id().as_ref())
            .await?
            .ok_or("date hook user missing")?;
        if string_result {
            assert_eq!(
                readback.ban_expires(),
                updated.ban_expires(),
                "{backend}/{action} exact native readback"
            );
            assert_eq!(
                native::to_value(&readback.ban_expires().map_or(JsValue::Null, JsValue::Date))?,
                case["output"],
                "{backend}/{action} public date readback"
            );
        } else {
            assert_eq!(
                readback.ban_expires(),
                expected,
                "{backend}/{action} readback"
            );
        }
    }
    drop(auth);
    B::close(connection).await
}

async fn user_date_strings_precede_sync_adapter_input<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false).await
}

async fn user_date_strings_precede_async_adapter_input<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false).await
}

async fn user_date_transform_strings_preserve_sync_driver_values<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true).await
}

async fn user_date_transform_strings_preserve_async_driver_values<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, true).await
}
