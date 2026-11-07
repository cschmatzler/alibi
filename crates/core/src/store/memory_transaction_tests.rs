use crate::store::{
    AccountStore, AuthStore, PasskeyStore, UserStore, VerificationStore, transaction,
};
use crate::utils::json::{self, JsValue};
use crate::{AuthError, AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};
use std::sync::Arc;

async fn stateless_record_counts(store: &crate::store::stateless::StatelessStore) -> JsValue {
    let (_, users) = store.list_users(ListUsersParams::default()).await.unwrap();
    let accounts = store.get_user_accounts("owner").await.unwrap().len();
    let verifications = usize::from(
        store
            .get_verification("tx-code", "secret")
            .await
            .unwrap()
            .is_some(),
    );
    let passkeys = store.list_passkeys_by_user("owner").await.unwrap().len();
    json::to_js_value(&[users, accounts, verifications, passkeys]).unwrap()
}

#[tokio::test]
async fn stateless_transactions_keep_related_identity_records_atomic() {
    use crate::store::stateless::{StatelessSchema, StatelessStore};
    let fixture =
        json::parse_value(include_str!("memory_transaction_isolation_cases.json")).unwrap();
    let cases = fixture["records"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let store = Arc::new(StatelessStore::default());
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let rollback = case["rollback"].as_bool().unwrap();
        let task_store = store.clone();
        let task = tokio::spawn(async move {
            transaction::<StatelessSchema, (), _>(&*task_store, move |tx| {
                Box::pin(async move {
                    tx.create_user(user("owner", "Owner")).await?;
                    assert_eq!(
                        tx.get_user_by_email(&"owner@test".into())
                            .await?
                            .unwrap()
                            .id,
                        "owner"
                    );
                    tx.create_account(crate::CreateAccount {
                        user_id: "owner".into(),
                        provider_id: "provider".into(),
                        account_id: "remote".into(),
                        additional_fields: Default::default(),
                        access_token: None,
                        refresh_token: None,
                        id_token: None,
                        access_token_expires_at: None,
                        refresh_token_expires_at: None,
                        scope: None,
                        password: None,
                    })
                    .await?;
                    assert_eq!(
                        tx.get_account("provider", &"remote".into())
                            .await?
                            .unwrap()
                            .user_id,
                        "owner"
                    );
                    tx.create_verification(crate::CreateVerification {
                        identifier: "tx-code".into(),
                        value: "secret".into(),
                        expires_at: chrono::DateTime::parse_from_rfc3339("2090-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                    })
                    .await?;
                    tx.create_passkey(crate::CreatePasskey {
                        user_id: "owner".into(),
                        name: JsValue::Undefined,
                        credential_id: "credential".into(),
                        public_key: "public".into(),
                        counter: 0,
                        device_type: "singleDevice".into(),
                        backed_up: false,
                        transports: JsValue::Undefined,
                        created_at: JsValue::Undefined,
                        aaguid: JsValue::Undefined,
                    })
                    .await?;
                    entered.send(()).unwrap();
                    blocked.await.unwrap();
                    if rollback {
                        Err(AuthError::internal("intentional rollback"))
                    } else {
                        Ok(())
                    }
                })
            })
            .await
        });
        ready
            .await
            .expect("transaction failed while staging related records");
        assert_eq!(stateless_record_counts(&store).await, case["during"]);
        release.send(()).unwrap();
        let result = task.await.unwrap();
        if rollback {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .ends_with(case["outcome"].as_str().unwrap())
            );
        } else {
            result.unwrap();
        }
        assert_eq!(stateless_record_counts(&store).await, case["after"]);
    }
}

#[test]
fn memory_transaction_row_changes_use_actual_json_stringify_comparison() {
    let fixture = json::parse_value(include_str!("memory_transaction_json_cases.json")).unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let kind = case["kind"].as_str().unwrap();
        let undefined = || JsValue::Object([("x".into(), JsValue::Undefined)].into());
        let (before, after) = match kind {
            "nonfinite" => (JsValue::Number(f64::NAN), JsValue::Number(f64::INFINITY)),
            "undefined-omission" => (undefined(), JsValue::Object(Default::default())),
            "undefined-null" => (
                undefined(),
                JsValue::Object([("x".into(), JsValue::Null)].into()),
            ),
            "date-string" => (
                JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                JsValue::String("1970-01-01T00:00:00.000Z".into()),
            ),
            "key-order" => (
                json::parse_value(r#"{"x":1,"y":2}"#).unwrap(),
                json::parse_value(r#"{"y":2,"x":1}"#).unwrap(),
            ),
            "negative-zero" => (JsValue::Number(-0.0), JsValue::Number(0.0)),
            _ => panic!("unknown fixture kind: {kind}"),
        };
        let row = |name: &str, marker| {
            JsValue::Object(
                [
                    ("id".into(), JsValue::String("row".into())),
                    ("name".into(), JsValue::String(name.into())),
                    ("marker".into(), marker),
                    (
                        "updatedAt".into(),
                        JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                    ),
                ]
                .into(),
            )
        };
        let base = [("row", row("base", before.clone()))];
        let changed = [("row", row("base", after))];
        let live = [("row", row("concurrent", before))];
        let merged = super::memory_transaction::merge_rows(
            live.iter().map(|(id, row)| (id, row)),
            base.iter().map(|(id, row)| (id, row)),
            changed.iter().map(|(id, row)| (id, row)),
        )
        .unwrap();
        let rows = JsValue::Array(merged.into_iter().map(|(_, row)| row).collect());
        assert_eq!(
            json::to_string(&rows).unwrap(),
            case["wire"].as_str().unwrap(),
            "{kind}"
        );
    }
}

fn cases() -> Vec<JsValue> {
    let fixture =
        json::parse_value(include_str!("memory_transaction_isolation_cases.json")).unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    cases.to_vec()
}

fn user(id: &str, name: &str) -> CreateUser {
    CreateUser {
        id: Some(id.into()),
        name: Some(name.into()),
        email: Some(format!("{id}@test")),
        ..Default::default()
    }
}

fn names(users: [Option<UserView>; 2]) -> JsValue {
    JsValue::Array(
        users
            .into_iter()
            .map(|user| {
                user.and_then(|user| user.name)
                    .map_or(JsValue::Null, |name| JsValue::String(name.into()))
            })
            .collect(),
    )
}

async fn exercise<S: AuthSchema<User = UserView>>(store: Arc<dyn AuthStore<S>>, case: &JsValue) {
    let kind = case["kind"].as_str().unwrap();
    store.create_user(user("existing", "base")).await.unwrap();
    store
        .create_user(user("other", "base-other"))
        .await
        .unwrap();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, blocked) = tokio::sync::oneshot::channel();
    let rollback = case["rollback"].as_bool().unwrap();
    let task_store = store.clone();
    let task = tokio::spawn(async move {
        transaction::<S, (), _>(&*task_store, move |tx| {
            Box::pin(async move {
                tx.update_user(
                    "existing",
                    UpdateUser {
                        name: Some("transaction".into()),
                        ..Default::default()
                    },
                )
                .await?;
                tx.create_user(user("tx-created", "tx-created")).await?;
                let inside = names([
                    tx.get_user_by_id("existing").await?,
                    tx.get_user_by_id("tx-created").await?,
                ]);
                entered.send(inside).unwrap();
                blocked.await.unwrap();
                if rollback {
                    Err(AuthError::internal("intentional rollback"))
                } else {
                    Ok(())
                }
            })
        })
        .await
    });
    let inside = ready
        .await
        .expect("transaction failed before its staged reads");
    assert_eq!(inside, case["inside"], "{kind}");
    let during = names([
        store.get_user_by_id("existing").await.unwrap(),
        store.get_user_by_id("tx-created").await.unwrap(),
    ]);
    assert_eq!(during, case["during"], "{kind}");
    let concurrent = case["concurrent"].as_str().unwrap();
    if concurrent == "delete" {
        store.delete_user("existing").await.unwrap();
    } else {
        store
            .update_user(
                concurrent,
                UpdateUser {
                    name: Some("concurrent".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    store
        .create_user(user("live-created", "live-created"))
        .await
        .unwrap();
    release.send(()).unwrap();
    let result = task.await.unwrap();
    if rollback {
        assert!(
            result
                .unwrap_err()
                .to_string()
                .ends_with(case["outcome"].as_str().unwrap()),
            "{kind}"
        );
    } else {
        result.unwrap();
        assert_eq!(case["outcome"], "committed");
    }
    let (rows, count) = store.list_users(ListUsersParams::default()).await.unwrap();
    assert_eq!(count, case["rows"].as_array().unwrap().len(), "{kind}");
    let rows = JsValue::Array(
        rows.into_iter()
            .map(|row| {
                JsValue::Object(
                    [
                        ("id".into(), JsValue::String(row.id.into())),
                        ("name".into(), JsValue::String(row.name.unwrap().into())),
                    ]
                    .into(),
                )
            })
            .collect(),
    );
    assert_eq!(rows, case["rows"], "{kind}");
}

#[tokio::test]
async fn memory_user_transactions_isolate_and_merge_like_actual_adapter() {
    for case in cases() {
        exercise::<crate::test_store::BundledSchema>(
            Arc::new(crate::test_store::MemoryStore::default()),
            &case,
        )
        .await;
    }
}

#[tokio::test]
async fn stateless_user_transactions_isolate_and_merge_like_actual_adapter() {
    for case in cases() {
        exercise::<crate::store::stateless::StatelessSchema>(
            Arc::new(crate::store::stateless::StatelessStore::default()),
            &case,
        )
        .await;
    }
}
