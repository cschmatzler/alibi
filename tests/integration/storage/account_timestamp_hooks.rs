use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::utils::json::{self as native, JsValue};
use alibi::{
    AuthAccount, AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateAccount, CreateUser,
    UpdateAccount,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

backend_tests!(
    account_date_inputs_precede_sync_adapter_callbacks,
    account_date_inputs_precede_async_adapter_callbacks,
    account_date_omission_overrides_sync_native_input,
    account_date_omission_overrides_async_native_input
);
postgres_tests!(
    account_date_inputs_precede_sync_adapter_callbacks,
    account_date_inputs_precede_async_adapter_callbacks,
    account_date_omission_overrides_sync_native_input,
    account_date_omission_overrides_async_native_input
);

type Events = Arc<Mutex<Vec<Value>>>;

fn event(events: &Events, phase: &str, value: Option<&JsValue>) -> alibi::AuthResult<()> {
    let kind = match value {
        None | Some(JsValue::Undefined) => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Date(_)) => "date",
        Some(JsValue::String(_)) => "string",
        _ => {
            return Err(alibi::AuthError::internal(
                "unexpected account date callback value",
            ));
        }
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
    omit_result: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    event(events, "input", value.as_ref())?;
    if omit_result
        && value
            .as_ref()
            .is_some_and(|value| !value.is_null() && !value.is_undefined())
    {
        return Ok(None);
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
                .ok_or_else(|| alibi::AuthError::internal("invalid account callback date"))?;
            Some(JsValue::Date(date + chrono::Duration::seconds(1)))
        }
        _ => {
            return Err(alibi::AuthError::internal(
                "unexpected account callback input",
            ));
        }
    })
}

struct AccountHooks(Events);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for AccountHooks {
    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let value = account
            .additional_fields
            .get("accessTokenExpiresAt")
            .cloned()
            .or_else(|| account.access_token_expires_at.map(JsValue::Date));
        event(&self.0, "create.before", value.as_ref())?;
        Ok(HookControl::Continue)
    }
    async fn before_update_account(
        &self,
        _: &str,
        account: &mut UpdateAccount,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let value = account
            .additional_fields
            .get("accessTokenExpiresAt")
            .cloned()
            .or_else(|| account.access_token_expires_at.map(JsValue::Date));
        event(&self.0, "update.before", value.as_ref())?;
        Ok(HookControl::Continue)
    }
    async fn after_create_account(
        &self,
        account: &S::Account,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(
            &self.0,
            "create.after",
            Some(
                &account
                    .access_token_expires_at()
                    .map_or(JsValue::Null, JsValue::Date),
            ),
        )
    }
    async fn after_update_account(
        &self,
        account: &S::Account,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        event(
            &self.0,
            "update.after",
            Some(
                &account
                    .access_token_expires_at()
                    .map_or(JsValue::Null, JsValue::Date),
            ),
        )
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool, omit_result: bool) -> TestResult {
    let secret = "account-timestamp-parameters-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if omit_result {
        include_str!("../../fixtures/account-timestamp-hooks-omit.json")
    } else {
        include_str!("../../fixtures/account-timestamp-hooks.json")
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
    assert_eq!(cases.len(), 8);
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
                transform(
                    &observed,
                    value,
                    omit_result && applying.load(Ordering::SeqCst),
                )
            }
        })
    } else {
        field.transform(move |value| {
            transform(
                &observed,
                value.cloned(),
                omit_result && applying.load(Ordering::SeqCst),
            )
        })
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .account
        .additional_fields
        .insert("accessTokenExpiresAt".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        AccountHooks(events.clone()),
    );
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("account-timestamp@example.com"),
        )
        .await?;
    for case in cases {
        let operation = case["operation"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let key = format!("{operation}-{kind}");
        let mut create = CreateAccount {
            additional_fields: Default::default(),
            user_id: owner.id().into_owned(),
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
        let account = if operation == "create" {
            if kind == "date" {
                create.access_token_expires_at = Some(case["input"].as_str().unwrap().parse()?);
            } else if kind != "omitted" {
                _ = create
                    .additional_fields
                    .insert("accessTokenExpiresAt".into(), case["input"].clone().into());
            }
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            auth.store().create_account(create).await?
        } else {
            assert_eq!(operation, "update");
            create.access_token_expires_at = Some("2030-01-01T00:00:00.123Z".parse()?);
            applying_input.store(false, Ordering::SeqCst);
            let original = auth.store().create_account(create).await?;
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
            let account = auth
                .store()
                .update_account(original.id().as_ref(), update)
                .await?;
            assert_eq!(account.id(), original.id());
            account
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{operation}/{kind}"
        );
        let expected: Option<chrono::DateTime<chrono::Utc>> =
            case["output"].as_str().map(str::parse).transpose()?;
        assert_eq!(
            account.access_token_expires_at(),
            expected,
            "{backend}/{operation}/{kind}"
        );
        let readback = auth
            .store()
            .get_account("timestamp-provider", &key.as_str().into())
            .await?
            .ok_or("account callback readback missing")?;
        assert_eq!(readback.id(), account.id());
        assert_eq!(
            readback.access_token_expires_at(),
            expected,
            "{backend}/{operation}/{kind} readback"
        );
    }
    drop(auth);
    B::close(connection).await
}

async fn account_date_inputs_precede_sync_adapter_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false).await
}
async fn account_date_inputs_precede_async_adapter_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false).await
}

async fn account_date_omission_overrides_sync_native_input<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true).await
}
async fn account_date_omission_overrides_async_native_input<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, true).await
}
