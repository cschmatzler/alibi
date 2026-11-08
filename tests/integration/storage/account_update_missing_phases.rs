use super::user_update_missing_phases::{SharedTrace, event, transform};
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::AdminPlugin;
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::utils::json::JsValue;
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthSchema, UpdateAccount};
use serde_json::{Value, json};
use std::sync::Arc;

#[cfg(feature = "seaorm-mysql")]
mod mysql;

backend_tests!(
    missing_account_updates_match_sync_source_phases,
    missing_account_updates_match_async_source_phases,
    missing_account_transactions_match_sync_source_phases,
    missing_account_transactions_match_async_source_phases,
    missing_account_failures_match_sync_source_phases,
    missing_account_failures_match_async_source_phases
);
postgres_tests!(
    missing_account_updates_match_sync_source_phases,
    missing_account_updates_match_async_source_phases,
    missing_account_transactions_match_sync_source_phases,
    missing_account_transactions_match_async_source_phases,
    missing_account_failures_match_sync_source_phases,
    missing_account_failures_match_async_source_phases
);

struct MissingAccountHooks(SharedTrace);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for MissingAccountHooks {
    async fn before_update_account(
        &self,
        _: &str,
        input: &mut UpdateAccount,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let value = input
            .additional_fields
            .get("accessTokenExpiresAt")
            .cloned()
            .or_else(|| input.access_token_expires_at.map(JsValue::Date));
        event(&self.0, "before", value.as_ref())?;
        Ok(if self.0.lock().unwrap().action == "before-cancel" {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }

    async fn after_update_account_missing(
        &self,
        id: &str,
        context: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        assert_eq!(id, "missing-timestamp-account");
        assert!(
            context.tx.is_none(),
            "missing account after hooks run after commit"
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
        include_str!("../../fixtures/account-update-missing-failures.json")
    } else if transactions {
        include_str!("../../fixtures/account-update-missing-transactions.json")
    } else {
        include_str!("../../fixtures/account-update-missing-phases.json")
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
    assert_eq!(cases.len(), if transactions { 2 } else { 5 });
    let trace = SharedTrace::default();
    let field = date_field(&trace, asynchronous);
    let mut config = AuthConfig::new(secret);
    _ = config
        .account
        .additional_fields
        .insert("accessTokenExpiresAt".into(), field);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        MissingAccountHooks(trace.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(AdminPlugin::new())
        .build()
        .await?;
    check_cases(
        auth.store().clone(),
        trace,
        cases,
        transactions,
        db.is_postgres(),
        || db.count("account"),
    )
    .await?;
    drop(auth);
    B::close(connection).await
}

fn date_field(trace: &SharedTrace, asynchronous: bool) -> alibi::field_policy::FieldConfig {
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
    if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            async move { transform(&inputs, value) }
        })
    } else {
        field.transform(move |value| transform(&inputs, value.cloned()))
    }
}

async fn check_cases<S: AuthSchema, F, Fut>(
    store: Arc<dyn alibi::AuthStore<S>>,
    trace: SharedTrace,
    cases: &[Value],
    transactions: bool,
    postgres: bool,
    count: F,
) -> TestResult
where
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<i64>>,
{
    let mut observations = Vec::new();
    let mut outcomes = Vec::new();
    for case in cases {
        let action = case["action"].as_str().unwrap().to_owned();
        {
            let mut trace = trace.lock().unwrap();
            trace.action.clone_from(&action);
            trace.events.clear();
        }
        let mut update = UpdateAccount::default();
        if action != "omitted" {
            _ = update.additional_fields.insert(
                "accessTokenExpiresAt".into(),
                case["input"]["accessTokenExpiresAt"].clone().into(),
            );
        }
        let result = if transactions
            || action.starts_with("commit")
            || action.starts_with("rollback")
        {
            let inside = trace.clone();
            let rollback = action.starts_with("rollback");
            alibi_core::store::transaction(store.as_ref(), move |tx| {
                Box::pin(async move {
                    let error = tx
                        .update_account("missing-timestamp-account", update)
                        .await
                        .err()
                        .ok_or_else(|| {
                            AuthError::internal("missing account update unexpectedly succeeded")
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
            store
                .update_account("missing-timestamp-account", update)
                .await
                .err()
                .ok_or_else(|| AuthError::internal("missing account update unexpectedly succeeded"))
        };
        let rows = count().await?;
        observations
            .push(json!({"action":action,"events":trace.lock().unwrap().events,"rows":rows}));
        outcomes.push((action, result, case["outcome"].clone()));
    }
    let expected: Vec<Value> = cases
        .iter()
        .map(|case| json!({"action":case["action"],"events":case["events"],"rows":case["rows"]}))
        .collect();
    assert_eq!(observations, expected, "missing-account phases");
    for (action, result, outcome) in outcomes {
        if action.starts_with("rollback") || action == "commit-after-error" {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(outcome["error"].as_str().unwrap())
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
                        .contains(outcome["error"].as_str().unwrap())
                );
            }
            "driver-error" | "driver-quote" if postgres => {
                assert!(matches!(&error, AuthError::Database(_)));
                assert_eq!(outcome["code"], "22007");
                assert!(
                    error
                        .to_string()
                        .contains(outcome["error"].as_str().unwrap())
                );
            }
            _ => match error {
                AuthError::NotFound(message) => assert_eq!(message, "Account not found"),
                error => panic!("unexpected missing-account error: {error}"),
            },
        }
    }
    Ok(())
}

async fn missing_account_updates_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, false).await
}
async fn missing_account_updates_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, false).await
}
async fn missing_account_transactions_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, true, false).await
}
async fn missing_account_transactions_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, true, false).await
}
async fn missing_account_failures_match_sync_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, false, false, true).await
}
async fn missing_account_failures_match_async_source_phases<B: Backend>(db: Db) -> TestResult {
    check::<B>(db, true, false, true).await
}
