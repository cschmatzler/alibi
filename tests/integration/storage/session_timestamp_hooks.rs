use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::utils::json::{self as native, JsValue};
use alibi::{
    AuthBuilder, AuthConfig, AuthSchema, AuthSession, AuthUser, CreateSession, CreateUser,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

mod secondary;
mod secondary_transactions;
mod wire;
mod wire_fields;

backend_tests!(
    session_creation_dates_precede_sync_input_callbacks,
    session_creation_dates_precede_async_input_callbacks,
    session_refresh_dates_precede_sync_input_callbacks,
    session_refresh_dates_precede_async_input_callbacks,
    session_creation_omission_preserves_sync_required_expiry_failure,
    session_creation_omission_preserves_async_required_expiry_failure,
    session_refresh_omission_preserves_sync_existing_expiry,
    session_refresh_omission_preserves_async_existing_expiry
);
postgres_tests!(
    session_creation_dates_precede_sync_input_callbacks,
    session_creation_dates_precede_async_input_callbacks,
    session_refresh_dates_precede_sync_input_callbacks,
    session_refresh_dates_precede_async_input_callbacks,
    session_creation_omission_preserves_sync_required_expiry_failure,
    session_creation_omission_preserves_async_required_expiry_failure,
    session_refresh_omission_preserves_sync_existing_expiry,
    session_refresh_omission_preserves_async_existing_expiry
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
                "unexpected session callback value",
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
    omit: bool,
) -> alibi::AuthResult<Option<JsValue>> {
    event(events, "input", value.as_ref())?;
    if omit
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
                .ok_or_else(|| alibi::AuthError::internal("invalid session callback date"))?;
            Some(JsValue::Date(date + chrono::Duration::seconds(1)))
        }
        _ => {
            return Err(alibi::AuthError::internal(
                "unexpected session callback input",
            ));
        }
    })
}

struct SessionHooks(Events);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for SessionHooks {
    async fn before_create_session(
        &self,
        input: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let value = input
            .additional_fields
            .get("expiresAt")
            .cloned()
            .unwrap_or(JsValue::Date(input.expires_at));
        event(&self.0, "create.before", Some(&value))?;
        Ok(HookControl::Continue)
    }
    async fn before_update_session(
        &self,
        _: &str,
        fields: &mut alibi::field_policy::FieldValues,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(&self.0, "update.before", fields.get("expiresAt"))?;
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
            Some(&JsValue::Date(session.expires_at())),
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
            Some(&JsValue::Date(session.expires_at())),
        )
    }
}

async fn check<B: Backend>(db: Db, asynchronous: bool, operation: &str, omit: bool) -> TestResult {
    let secret = "session-timestamp-hooks-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if omit {
        include_str!("../../fixtures/session-timestamp-hooks-omit-required.json")
    } else {
        include_str!("../../fixtures/session-timestamp-hooks.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let profiles = fixture["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
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
    let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}))
        .on_update(|| JsValue::String("2031-02-03T04:05:06.123987Z".into()));
    field.required = omit;
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            let applying = applying.clone();
            async move { transform(&inputs, value, omit && applying.load(Ordering::SeqCst)) }
        })
    } else {
        field.transform(move |value| {
            transform(
                &inputs,
                value.cloned(),
                omit && applying.load(Ordering::SeqCst),
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
            user_id: owner.id().into_owned(),
            token: Some(token.clone()),
            expires_at: "2030-01-01T00:00:00.123Z".parse()?,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: Default::default(),
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
            let result = auth.store().create_session(create).await;
            if let Some(expected) = case["outcome"].get("error") {
                let error = result
                    .err()
                    .ok_or("omitted required expiry unexpectedly created a session")?;
                assert!(matches!(&error, alibi::AuthError::Database(_)));
                assert!(
                    error
                        .to_string()
                        .contains(expected["message"].as_str().unwrap()),
                    "{backend}/{operation}/{kind}: {error}"
                );
                assert_eq!(
                    json!(*events.lock().unwrap()),
                    case["events"],
                    "{backend}/{operation}/{kind}"
                );
                assert!(auth.store().get_session(&token).await?.is_none());
                assert_eq!(
                    db.count_where("SELECT COUNT(*) FROM session WHERE token = $1", &[&token])
                        .await?,
                    0
                );
                continue;
            }
            result?
        } else {
            assert_eq!(operation, "update");
            applying_input.store(false, Ordering::SeqCst);
            let original = auth.store().create_session(create).await?;
            events.lock().unwrap().clear();
            applying_input.store(true, Ordering::SeqCst);
            let session = if kind == "date" {
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
            .ok_or("session callback update unexpectedly missing")?;
            assert_eq!(session.id(), original.id());
            session
        };
        assert_eq!(
            json!(*events.lock().unwrap()),
            case["events"],
            "{backend}/{operation}/{kind}"
        );
        let expected = if omit {
            &case["outcome"]["output"]
        } else {
            &case["output"]
        };
        assert_eq!(
            session.expires_at(),
            expected
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<chrono::Utc>>()?,
            "{backend}/{operation}/{kind}"
        );
        let readback = auth
            .store()
            .get_session(&token)
            .await?
            .ok_or("session callback readback missing")?;
        assert_eq!(readback.id(), session.id());
        assert_eq!(
            readback.expires_at(),
            case["readback"]
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<chrono::Utc>>()?,
            "{backend}/{operation}/{kind} readback"
        );
    }
    assert_eq!(checked, if operation == "create" { 2 } else { 3 });
    drop(auth);
    B::close(connection).await
}

async fn session_creation_dates_precede_sync_input_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "create", false).await
}
async fn session_creation_dates_precede_async_input_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "create", false).await
}
async fn session_refresh_dates_precede_sync_input_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update", false).await
}
async fn session_refresh_dates_precede_async_input_callbacks<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, "update", false).await
}

async fn session_creation_omission_preserves_sync_required_expiry_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, false, "create", true).await
}
async fn session_creation_omission_preserves_async_required_expiry_failure<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "create", true).await
}
async fn session_refresh_omission_preserves_sync_existing_expiry<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, "update", true).await
}
async fn session_refresh_omission_preserves_async_existing_expiry<B: Backend>(
    db: Db,
) -> TestResult {
    check::<B>(db, true, "update", true).await
}
