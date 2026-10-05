//! Record observers receive transformed snapshots only after successful persistence.
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use async_trait::async_trait;
use better_auth::AuthConfig;
use better_auth_core::field_policy::{FieldConfig, FieldValues};
use better_auth_core::store::{
    AccountStore, AdapterAfterHook, AdapterEvent, AuthStore, SessionStore, UserStore, transaction,
};
use better_auth_core::utils::json::JsValue;
use better_auth_core::{
    AuthAccount, AuthError, AuthInitContext, AuthResult, AuthSession, AuthUser, CreateAccount,
    CreateSession, CreateUser, UpdateAccount, UpdateUser,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
backend_tests!(adapter_observers_see_all_committed_record_kinds_and_respect_output_failure);
postgres_tests!(adapter_observers_see_all_committed_record_kinds_and_respect_output_failure);
struct Observer<B: Backend> {
    raw: Arc<B::Store>,
    seen: Arc<Mutex<Vec<Value>>>,
    fail: Arc<AtomicBool>,
}
#[async_trait]
impl<B: Backend> AdapterAfterHook<B::Schema> for Observer<B> {
    async fn after_write(
        &self,
        event: &AdapterEvent<B::Schema>,
        _: &dyn AuthStore<B::Schema>,
    ) -> AuthResult<()> {
        let value = match event {
            AdapterEvent::UserCreated(value) | AdapterEvent::UserUpdated(value) => {
                let actual = self.raw.get_user_by_id(&value.id()).await?.unwrap();
                assert_eq!(actual.role(), value.role());
                json!([
                    if matches!(event, AdapterEvent::UserCreated(_)) {
                        "user-created"
                    } else {
                        "user-updated"
                    },
                    value.raw_snapshot().values().get("role")
                ])
            }
            AdapterEvent::AccountCreated(value) | AdapterEvent::AccountUpdated(value) => {
                let rows = self.raw.get_user_accounts(&value.user_id()).await?;
                assert!(
                    rows.iter()
                        .any(|row| row.id() == value.id() && row.scope() == value.scope())
                );
                json!([
                    if matches!(event, AdapterEvent::AccountCreated(_)) {
                        "account-created"
                    } else {
                        "account-updated"
                    },
                    value.raw_snapshot().values().get("scope")
                ])
            }
            AdapterEvent::SessionCreated(value) | AdapterEvent::SessionUpdated(value) => {
                let actual = self.raw.get_session(value.token()).await?.unwrap();
                assert_eq!(actual.ip_address(), value.ip_address());
                json!([
                    if matches!(event, AdapterEvent::SessionCreated(_)) {
                        "session-created"
                    } else {
                        "session-updated"
                    },
                    value.raw_snapshot().values().get("ipAddress")
                ])
            }
        };
        self.seen.lock().unwrap().push(value);
        if self.fail.load(Ordering::SeqCst) {
            Err(AuthError::forbidden("observer rejected committed result"))
        } else {
            Ok(())
        }
    }
}
fn account(owner: &str) -> CreateAccount {
    CreateAccount {
        user_id: owner.into(),
        provider_id: "application".into(),
        account_id: "observer-subject".into(),
        scope: Some("original".into()),
        additional_fields: Default::default(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        password: None,
    }
}
fn session(owner: &str, token: &str) -> CreateSession {
    CreateSession {
        user_id: owner.into(),
        token: Some(token.into()),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: Some("original".into()),
        user_agent: None,
        additional_fields: Default::default(),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    }
}
async fn adapter_observers_see_all_committed_record_kinds_and_respect_output_failure<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("adapter-observer-secret-32-characters")
        .await?;
    let raw = Arc::new(store);
    let output_failure = Arc::new(AtomicBool::new(false));
    let observer_failure = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut config = AuthConfig::new("adapter-observer-secret-32-characters");
    for (fields, name) in [
        (&mut config.user.additional_fields, "role"),
        (&mut config.account.additional_fields, "scope"),
        (&mut config.session.additional_fields, "ipAddress"),
    ] {
        let fail = output_failure.clone();
        drop(fields.insert(
            name.into(),
            FieldConfig::new(json!({"type":"string"})).transform_output(move |value| {
                let fail = fail.clone();
                async move {
                    if fail.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("output callback failed"));
                    }
                    Ok(value
                        .map(|value| JsValue::String(format!("shown:{}", value.as_str().unwrap()))))
                }
            }),
        ));
    }
    let mut init = AuthInitContext::<B::Schema>::new(Arc::new(config), raw.clone());
    init.register_adapter_after_hook(Arc::new(Observer::<B> {
        raw: raw.clone(),
        seen: seen.clone(),
        fail: observer_failure.clone(),
    }));
    let store = init.database_with_registered_transforms();
    let user = store
        .create_user_record(
            CreateUser::new()
                .with_email("observer@example.test")
                .with_role("original"),
        )
        .await?;
    let id = user.id().into_owned();
    let account = store.create_account_record(account(&id)).await?;
    drop(
        store
            .create_session_record(session(&id, "observer-session"))
            .await?,
    );
    drop(
        store
            .update_user_record(
                &id,
                UpdateUser {
                    role: Some("updated".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    drop(
        store
            .update_account_record(
                &account.id(),
                UpdateAccount {
                    scope: Some("updated".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let mut fields = FieldValues::new();
    drop(fields.insert("ipAddress".into(), JsValue::String("updated".into())));
    drop(
        store
            .update_session_fields_record("observer-session", fields)
            .await?,
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            json!(["user-created", "shown:original"]),
            json!(["account-created", "shown:original"]),
            json!(["session-created", "shown:original"]),
            json!(["user-updated", "shown:updated"]),
            json!(["account-updated", "shown:updated"]),
            json!(["session-updated", "shown:updated"])
        ]
    );
    for in_transaction in [false, true] {
        for failure in ["none", "rollback", "output", "observer"] {
            if !in_transaction && failure == "rollback" {
                continue;
            }
            output_failure.store(failure == "output", Ordering::SeqCst);
            observer_failure.store(failure == "observer", Ordering::SeqCst);
            seen.lock().unwrap().clear();
            let email = format!("{in_transaction}-{failure}@example.test");
            let input = CreateUser::new().with_email(&email).with_role("created");
            let result: AuthResult<()> = if in_transaction {
                transaction(store.as_ref(), move |tx| {
                    Box::pin(async move {
                        drop(tx.create_user_record(input).await?);
                        if failure == "rollback" {
                            Err(AuthError::forbidden("application aborts transaction"))
                        } else {
                            Ok(())
                        }
                    })
                })
                .await
            } else {
                store.create_user_record(input).await.map(drop)
            };
            assert_eq!(result.is_ok(), failure == "none");
            let persisted = !(in_transaction && matches!(failure, "rollback" | "output"));
            assert_eq!(
                db.count_where("SELECT COUNT(*) FROM users WHERE email=$1", &[&email])
                    .await?,
                i64::from(persisted)
            );
            assert_eq!(
                *seen.lock().unwrap(),
                if matches!(failure, "none" | "observer") {
                    vec![json!(["user-created", "shown:created"])]
                } else {
                    vec![]
                }
            );
        }
    }
    B::close(connection).await
}
