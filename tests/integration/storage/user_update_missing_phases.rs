use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::AdminPlugin;
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::utils::json::{self as native, JsValue};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthSchema, UpdateUser};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

backend_tests!(
    missing_user_updates_match_sync_source_phases,
    missing_user_updates_match_async_source_phases,
    missing_user_transactions_match_sync_source_phases,
    missing_user_transactions_match_async_source_phases,
    missing_user_failures_match_sync_source_phases,
    missing_user_failures_match_async_source_phases
);
postgres_tests!(
    missing_user_updates_match_sync_source_phases,
    missing_user_updates_match_async_source_phases,
    missing_user_transactions_match_sync_source_phases,
    missing_user_transactions_match_async_source_phases,
    missing_user_failures_match_sync_source_phases,
    missing_user_failures_match_async_source_phases
);

#[derive(Default)]
struct Trace {
    action: String,
    events: Vec<Value>,
}

type SharedTrace = Arc<Mutex<Trace>>;

fn event(trace: &SharedTrace, phase: &str, value: Option<&JsValue>) -> alibi::AuthResult<()> {
    let kind = match value {
        None | Some(JsValue::Undefined) => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Date(_)) => "date",
        Some(JsValue::String(_)) => "string",
        _ => {
            return Err(AuthError::internal(
                "unexpected missing-user callback value",
            ));
        }
    };
    let value = value
        .filter(|value| !value.is_undefined())
        .map(native::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
    trace
        .lock()
        .unwrap()
        .events
        .push(json!({"phase":phase,"kind":kind,"value":value}));
    Ok(())
}

fn transform(trace: &SharedTrace, value: Option<JsValue>) -> alibi::AuthResult<Option<JsValue>> {
    event(trace, "input", value.as_ref())?;
    if trace.lock().unwrap().action == "input-error" {
        return Err(AuthError::internal("date input veto"));
    }
    if trace.lock().unwrap().action == "driver-error" {
        return Ok(Some(JsValue::String("not-a-timestamp".into())));
    }
    if trace.lock().unwrap().action == "driver-quote" {
        return Ok(Some(JsValue::String(
            "2031-02-03T04:05:06.123Z'); DROP TABLE user; --\\path".into(),
        )));
    }
    Ok(value)
}

struct MissingHooks(SharedTrace);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for MissingHooks {
    async fn before_update_user(
        &self,
        _: &str,
        input: &mut native::JsObject,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        event(&self.0, "before", input.get("banExpires"))?;
        Ok(if self.0.lock().unwrap().action == "before-cancel" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_update_user_missing(
        &self,
        id: &str,
        context: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        assert_eq!(id, "missing-timestamp-user");
        assert!(
            context.tx.is_none(),
            "missing-row after hooks run after commit"
        );
        event(&self.0, "after", Some(&JsValue::Null))?;
        if self.0.lock().unwrap().action.ends_with("after-error") {
            return Err(AuthError::internal("missing after veto"));
        }
        Ok(())
    }
}

async fn check<B: Backend>(
    db: Db,
    asynchronous: bool,
    transactions: bool,
    failures: bool,
) -> TestResult {
    let secret = "user-update-missing-phases-secret-at-least-32";
    let (connection, _) = db.migrated::<B>(secret).await?;
    let fixture: Value = serde_json::from_str(if failures {
        include_str!("../../fixtures/user-update-missing-failures.json")
    } else if transactions {
        include_str!("../../fixtures/user-update-missing-transactions.json")
    } else {
        include_str!("../../fixtures/user-update-missing-phases.json")
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
    assert_eq!(
        cases.len(),
        if failures {
            5
        } else if transactions {
            2
        } else {
            5
        }
    );
    let trace = SharedTrace::default();
    let defaults = trace.clone();
    let field =
        alibi::field_policy::FieldConfig::new(json!({"type":"date"})).on_update(move || {
            defaults
                .lock()
                .unwrap()
                .events
                .push(json!({"phase":"onUpdate"}));
            JsValue::String("2031-02-03T04:05:06.123987Z".into())
        });
    let inputs = trace.clone();
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            async move { transform(&inputs, value) }
        })
    } else {
        field.transform(move |value| transform(&inputs, value.cloned()))
    };
    let mut config = AuthConfig::new(secret);
    _ = config
        .user
        .additional_fields
        .insert("banExpires".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        MissingHooks(trace.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    let mut observations = Vec::new();
    let mut outcomes = Vec::new();
    for case in cases {
        let action = case["action"].as_str().unwrap().to_owned();
        {
            let mut trace = trace.lock().unwrap();
            trace.action.clone_from(&action);
            trace.events.clear();
        }
        let mut update = UpdateUser::default();
        if action == "omitted" {
            update.banned = Some(false);
        } else {
            _ = update.adapter_native_fields.insert(
                "banExpires".into(),
                case["input"]["banExpires"].clone().into(),
            );
        }
        let result = if transactions
            || action.starts_with("commit")
            || action.starts_with("rollback")
        {
            let inside = trace.clone();
            let rollback = action.starts_with("rollback");
            alibi_core::store::transaction(auth.store().as_ref(), move |tx| {
                Box::pin(async move {
                    // The typed API keeps its missing-row error; only the source
                    // callback phases, not a fabricated successful user, are compared.
                    let error = tx
                        .update_user("missing-timestamp-user", update)
                        .await
                        .err()
                        .ok_or_else(|| {
                            AuthError::internal("missing user update unexpectedly succeeded")
                        })?;
                    inside
                        .lock()
                        .unwrap()
                        .events
                        .push(json!({"phase":"inside"}));
                    if rollback {
                        return Err(AuthError::internal("missing update rollback"));
                    }
                    Ok(error)
                })
            })
            .await
        } else {
            auth.store()
                .update_user("missing-timestamp-user", update)
                .await
                .err()
                .ok_or_else(|| AuthError::internal("missing user update unexpectedly succeeded"))
        };
        let rows = db.count("user").await?;
        observations
            .push(json!({"action":action,"events":trace.lock().unwrap().events,"rows":rows}));
        outcomes.push((action, result, case["outcome"].clone()));
    }
    let expected: Vec<Value> = cases
        .iter()
        .map(|case| json!({"action":case["action"],"events":case["events"],"rows":case["rows"]}))
        .collect();
    assert_eq!(observations, expected, "{backend} missing-user phases");
    for (action, result, expected_outcome) in outcomes {
        if action.starts_with("rollback") || action == "commit-after-error" {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(expected_outcome["error"].as_str().unwrap())
            );
            continue;
        }
        let error = result?;
        match action.as_str() {
            "before-cancel" => assert_eq!(error.status_code(), 403),
            "input-error" | "after-error" => {
                assert_eq!(error.status_code(), 500);
                assert!(
                    error
                        .to_string()
                        .contains(expected_outcome["error"].as_str().unwrap())
                );
            }
            "driver-error" | "driver-quote" if db.is_postgres() => {
                assert!(matches!(&error, AuthError::Database(_)));
                assert_eq!(expected_outcome["code"], "22007");
                assert!(
                    error
                        .to_string()
                        .contains(expected_outcome["error"].as_str().unwrap())
                );
            }
            _ => match error {
                AuthError::UserNotFound => {}
                AuthError::Database(alibi::DatabaseError::Query(message)) => {
                    assert_eq!(message, "the update matched no row")
                }
                error => panic!("unexpected missing-row error: {error}"),
            },
        }
    }
    drop(auth);
    B::close(connection).await
}

async fn missing_user_updates_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, false).await
}
async fn missing_user_updates_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, false).await
}
async fn missing_user_transactions_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true, false).await
}
async fn missing_user_transactions_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, true, false).await
}

async fn missing_user_failures_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, true).await
}
async fn missing_user_failures_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, true).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_quoted_literals_match_bound_text_values() -> TestResult {
    let db = Db::postgres().await?;
    for value in [
        "",
        "2035-02-03T04:05:06.123987Z",
        "O'Reilly",
        "'; DROP TABLE users; --\\path",
        "雪\n\t'\\",
    ] {
        let literal = alibi_core::store::postgres_parameter::quoted_literal(value);
        assert_eq!(
            db.text("SELECT $1::text", &[value]).await?,
            Some(value.to_owned())
        );
        assert_eq!(
            db.text(&format!("SELECT {literal}::text"), &[]).await?,
            Some(value.to_owned())
        );
    }
    let value = "before\0after";
    let bound = db.text("SELECT $1::text", &[value]).await.unwrap_err();
    let literal = alibi_core::store::postgres_parameter::quoted_literal(value);
    let quoted = db
        .text(&format!("SELECT {literal}::text"), &[])
        .await
        .unwrap_err();
    for error in [bound, quoted] {
        assert!(
            error
                .to_string()
                .contains("invalid byte sequence for encoding \"UTF8\": 0x00")
        );
    }
    Ok(())
}
