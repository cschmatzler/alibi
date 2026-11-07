pub mod adapter;
mod contracts;
mod database_hooks;
mod decorated;
mod jwks;
pub(crate) mod memory_transaction;
#[cfg(test)]
mod memory_transaction_tests {
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
                            expires_at: chrono::DateTime::parse_from_rfc3339(
                                "2090-01-01T00:00:00Z",
                            )
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
        let fixture =
            json::parse_value(include_str!("memory_transaction_json_cases.json")).unwrap();
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

    async fn exercise<S: AuthSchema<User = UserView>>(
        store: Arc<dyn AuthStore<S>>,
        case: &JsValue,
    ) {
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
}

pub(crate) mod memory_user_id;
#[cfg(test)]
mod memory_user_id_tests {
    use super::memory_user_id::MemoryUserId;
    use crate::store::{
        UserStore,
        stateless::{StatelessSchema, StatelessStore},
    };
    use crate::test_store::{BundledSchema, MemoryStore};
    use crate::{AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};
    use serde_json::json;

    mod duplicate_rows {
        use crate::store::{PreparedUserUpdate, UserStore};
        use crate::utils::json::{self, JsValue};
        use crate::{AuthSchema, CreateUser, ListUsersParams, UserView};

        async fn rows<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) -> JsValue {
            let (rows, count) = store.list_users(ListUsersParams::default()).await.unwrap();
            assert_eq!(rows.len(), count);
            JsValue::Array(
                rows.iter()
                    .map(|row| {
                        JsValue::Object(
                            [
                                ("id".into(), JsValue::String(row.id.clone().into())),
                                (
                                    "name".into(),
                                    JsValue::String(row.name.clone().unwrap().into()),
                                ),
                                (
                                    "email".into(),
                                    JsValue::String(row.email.clone().unwrap().into()),
                                ),
                            ]
                            .into(),
                        )
                    })
                    .collect(),
            )
        }

        async fn duplicate_rows<S: AuthSchema<User = UserView>>(
            store: &impl UserStore<S>,
            paged: bool,
        ) {
            let fixture =
                json::parse_value(include_str!("memory_user_duplicate_cases.json")).unwrap();
            assert_eq!(fixture["better_auth"], "1.7.18");
            for input in fixture["inputs"].as_array().unwrap() {
                store
                    .create_user(CreateUser {
                        adapter_native_fields: [("id".into(), input["id"].clone())].into(),
                        name: Some(input["name"].as_str().unwrap().into()),
                        email: Some(input["email"].as_str().unwrap().into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }
            assert_eq!(rows(store).await, fixture["created"]);
            let first = store.get_user_by_id("duplicate").await.unwrap().unwrap();
            assert_eq!(first.name.as_deref(), fixture["first"].as_str());
            let ids = ["last".into(), "duplicate".into(), "duplicate".into()];
            let selected = store.list_users_by_ids(&ids).await.unwrap();
            let names = |users: &[UserView]| {
                JsValue::Array(
                    users
                        .iter()
                        .map(|row| JsValue::String(row.name.clone().unwrap().into()))
                        .collect(),
                )
            };
            assert_eq!(names(&selected), fixture["selected"]);
            let (numeric, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_value: Some(JsValue::Number(7.0).into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(count, 2);
            assert_eq!(names(&numeric), fixture["numeric"]);
            if paged {
                let selected = store.list_users_by_ids_page(&ids, 2.0).await.unwrap();
                assert_eq!(
                    names(&selected),
                    JsValue::Array(fixture["selected"].as_array().unwrap()[..2].to_vec())
                );
            }
            let changed = store
                .update_user_prepared(
                    "duplicate",
                    PreparedUserUpdate {
                        data: [
                            ("id".into(), JsValue::String("other".into())),
                            ("name".into(), JsValue::String("updated".into())),
                        ]
                        .into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(changed.id, "other");
            assert_eq!(changed.name.as_deref(), Some("updated"));
            assert_eq!(rows(store).await, fixture["after_collision"]);
            assert!(store.get_user_by_id("duplicate").await.unwrap().is_none());
            store
                .update_user(
                    "other",
                    crate::UpdateUser {
                        email: Some("updated@test".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(rows(store).await, fixture["after_update"]);
            store.delete_user("other").await.unwrap();
            assert_eq!(rows(store).await, fixture["after_delete"]);
            assert!(store.get_user_by_id("other").await.unwrap().is_none());
            assert_eq!(
                store
                    .get_user_by_id("7")
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("row-6")
            );
        }

        #[tokio::test]
        async fn duplicate_user_rows_memory_follow_actual_adapter_mutations() {
            duplicate_rows::<crate::test_store::BundledSchema>(
                &crate::test_store::MemoryStore::default(),
                false,
            )
            .await;
        }

        #[tokio::test]
        async fn duplicate_user_rows_stateless_follow_actual_adapter_mutations() {
            duplicate_rows::<crate::store::stateless::StatelessSchema>(
                &crate::store::stateless::StatelessStore::default(),
                true,
            )
            .await;
        }
    }

    mod primitive_updates {
        use crate::store::UserStore;
        use crate::utils::json::{self, JsValue};
        use crate::{AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};

        fn cases() -> Vec<JsValue> {
            let fixture =
                json::parse_value(include_str!("memory_user_update_primitive_id_cases.json"))
                    .unwrap();
            assert_eq!(fixture["better_auth"], "1.7.18");
            let cases = fixture["cases"].as_array().unwrap();
            assert_eq!(cases.len(), 5);
            cases.to_vec()
        }

        async fn check<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>, case: &JsValue) {
            let kind = case["kind"].as_str().unwrap();
            let value = match kind {
                "integer" => JsValue::Number(7.0),
                "fractional" => JsValue::Number(7.25),
                "true" => JsValue::Bool(true),
                "infinity" => JsValue::Number(f64::INFINITY),
                "negative-infinity" => JsValue::Number(f64::NEG_INFINITY),
                _ => panic!("unknown fixture kind: {kind}"),
            };
            let text = case["id"].as_str().unwrap();
            for (id, name) in [
                (JsValue::String("target".into()), "target"),
                (value.clone(), "native"),
                (JsValue::String(text.into()), "text"),
            ] {
                store
                    .create_user(CreateUser {
                        name: Some(name.into()),
                        email: Some(format!("{name}@test")),
                        adapter_native_fields: [("id".into(), id)].into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }
            let updated = store
                .update_user(
                    "target",
                    UpdateUser {
                        name: Some("updated".into()),
                        adapter_native_fields: [("id".into(), value.clone())].into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{kind}: {error}"));
            assert_eq!(updated.id, text, "{kind}");
            assert_eq!(updated.name.as_deref(), case["name"].as_str(), "{kind}");
            assert!(store.get_user_by_id("target").await.unwrap().is_none());
            let (native, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_value: Some(value.into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(count, 2, "{kind}");
            let names = JsValue::Array(
                native
                    .iter()
                    .map(|row| JsValue::String(row.name.clone().unwrap().into()))
                    .collect(),
            );
            assert_eq!(names, case["native"], "{kind}");
            assert_eq!(
                store
                    .get_user_by_id(text)
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                case["text"].as_str(),
                "{kind}"
            );
            store.delete_user(text).await.unwrap();
            let (remaining, count) = store.list_users(ListUsersParams::default()).await.unwrap();
            assert_eq!(count, 2, "{kind}");
            let remaining = JsValue::Array(
                remaining
                    .into_iter()
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
            assert_eq!(remaining, case["remaining"], "{kind}");
        }

        #[tokio::test]
        async fn primitive_update_id_memory_keeps_physical_scalar_and_colliding_rows() {
            for case in cases() {
                check::<crate::test_store::BundledSchema>(
                    &crate::test_store::MemoryStore::default(),
                    &case,
                )
                .await;
            }
        }

        #[tokio::test]
        async fn primitive_update_id_stateless_keeps_physical_scalar_and_colliding_rows() {
            for case in cases() {
                check::<crate::store::stateless::StatelessSchema>(
                    &crate::store::stateless::StatelessStore::default(),
                    &case,
                )
                .await;
            }
        }
    }

    mod falsy_id_cases {
        use crate as alibi_core;
        include!(
            "../../../../tests/integration/storage/plugin_flows/user_update_falsy_id_cases.rs"
        );
    }

    #[tokio::test]
    async fn falsy_update_ids_memory_follow_adapter_omission() {
        falsy_id_cases::exercise::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn falsy_update_ids_stateless_follow_adapter_omission() {
        falsy_id_cases::exercise::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn physical_primitives<S: AuthSchema<User = UserView>>(
        store: &impl UserStore<S>,
        supports_page: bool,
    ) {
        for (raw, label) in [(json!(2), "number"), (json!(true), "boolean")] {
            let output = crate::utils::json::JsValue::from(raw.clone())
                .coerce_string()
                .unwrap();
            let numeric = store
                .create_user(CreateUser {
                    name: Some(label.to_owned()),
                    email: Some(format!("{label}@example.test")),
                    adapter_native_fields: [("id".to_owned(), raw.into())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(numeric.id, output);
            assert!(store.get_user_by_id(&output).await.unwrap().is_none());
            assert!(
                store
                    .list_users_by_ids(&[output.clone()])
                    .await
                    .unwrap()
                    .is_empty()
            );
            if supports_page {
                assert!(
                    store
                        .list_users_by_ids_page(&[output.clone()], 10.0)
                        .await
                        .unwrap()
                        .is_empty()
                );
            } else {
                assert!(matches!(
                    store.list_users_by_ids_page(&[output.clone()], 10.0).await,
                    Err(crate::AuthError::NotImplemented(_))
                ));
            }
            assert!(
                store
                    .update_user(
                        &output,
                        UpdateUser {
                            name: Some("must not mutate".into()),
                            ..Default::default()
                        }
                    )
                    .await
                    .is_err()
            );
            store.delete_user(&output).await.unwrap();
            assert_eq!(
                store
                    .get_user_by_email(&format!("{label}@example.test").into())
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some(label)
            );

            let string = store
                .create_user(CreateUser {
                    id: Some(output.clone()),
                    name: Some("string".to_owned()),
                    email: Some(format!("string-{label}@example.test")),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(numeric.id, string.id);
            assert_eq!(
                store
                    .get_user_by_id(&output)
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("string")
            );
            assert_eq!(
                store
                    .list_users_by_ids(&[output.clone()])
                    .await
                    .unwrap()
                    .len(),
                1
            );
            if supports_page {
                assert_eq!(
                    store
                        .list_users_by_ids_page(&[output.clone()], 10.0)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
            }
            for (operator, expected) in [("eq", 1), ("in", 1)] {
                let filter_value = if operator == "in" {
                    vec![output.clone()].into()
                } else {
                    output.clone().into()
                };
                let (users, count) = store
                    .list_users(ListUsersParams {
                        filter_field: Some("id".into()),
                        filter_operator: Some(operator.into()),
                        filter_value: Some(filter_value),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert_eq!(count, expected);
                assert_eq!(users[0].name.as_deref(), Some("string"));
            }
            let (other, _) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_operator: Some("ne".into()),
                    filter_value: Some(output.clone().into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(other.iter().any(|user| user.name.as_deref() == Some(label)));
            store
                .update_user(
                    &output,
                    UpdateUser {
                        name: Some("changed string".into()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                store
                    .get_user_by_email(&format!("{label}@example.test").into())
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some(label)
            );
            store.delete_user(&output).await.unwrap();
            assert!(store.get_user_by_id(&output).await.unwrap().is_none());
            assert!(
                store
                    .get_user_by_email(&format!("{label}@example.test").into())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let (users, count) = store.list_users(ListUsersParams::default()).await.unwrap();
        assert_eq!(count, 2);
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn stateless_physical_primitive_ids_do_not_alias_string_ids() {
        physical_primitives::<StatelessSchema>(&StatelessStore::default(), true).await;
    }

    #[tokio::test]
    async fn memory_physical_primitive_ids_do_not_alias_string_ids() {
        physical_primitives::<BundledSchema>(&MemoryStore::default(), false).await;
    }

    #[test]
    fn primitive_identity_keys_use_javascript_number_values() {
        assert_eq!(
            MemoryUserId::supplied(Some(&crate::utils::json::JsValue::from(json!(2))))
                .unwrap()
                .unwrap()
                .0,
            MemoryUserId::supplied(Some(&crate::utils::json::JsValue::from(json!(2.0))))
                .unwrap()
                .unwrap()
                .0
        );
        assert_ne!(
            MemoryUserId::supplied(Some(&crate::utils::json::JsValue::from(json!(1))))
                .unwrap()
                .unwrap()
                .0,
            MemoryUserId::supplied(Some(&crate::utils::json::JsValue::from(json!(true))))
                .unwrap()
                .unwrap()
                .0
        );
        for raw in [
            json!(0),
            json!(-0.0),
            json!(false),
            json!(null),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(MemoryUserId::supplied(Some(&raw.into())).unwrap().is_none());
        }
    }

    async fn physical_relational_filters<S: AuthSchema<User = UserView>>(
        store: &impl UserStore<S>,
    ) {
        for (raw, label) in [
            (json!(2), "n2"),
            (json!("2"), "s2"),
            (json!(10), "n10"),
            (json!("10"), "s10"),
            (json!(true), "btrue"),
            (json!("true"), "strue"),
        ] {
            store
                .create_user(CreateUser {
                    name: Some(label.into()),
                    email: Some(format!("{label}@example.test")),
                    adapter_native_fields: [("id".to_owned(), raw.into())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // Expected sets come from the memory adapter's physical record[field] comparisons.
        let scalar_cases = [
            (
                "10",
                [
                    "btrue n2",
                    "btrue n10 n2 s10",
                    "s2 strue",
                    "n10 s10 s2 strue",
                ],
            ),
            (
                "2",
                [
                    "btrue s10",
                    "btrue n2 s10 s2",
                    "n10 strue",
                    "n10 n2 s2 strue",
                ],
            ),
            ("notnumeric", ["s10 s2", "s10 s2", "strue", "strue"]),
            (
                "",
                [
                    "",
                    "",
                    "btrue n10 n2 s10 s2 strue",
                    "btrue n10 n2 s10 s2 strue",
                ],
            ),
            (
                " \t\u{feff}",
                [
                    "",
                    "",
                    "btrue n10 n2 s10 s2 strue",
                    "btrue n10 n2 s10 s2 strue",
                ],
            ),
            (
                " 2 ",
                [
                    "btrue",
                    "btrue n2",
                    "n10 s10 s2 strue",
                    "n10 n2 s10 s2 strue",
                ],
            ),
            (
                "0x10",
                [
                    "btrue n10 n2",
                    "btrue n10 n2",
                    "s10 s2 strue",
                    "s10 s2 strue",
                ],
            ),
            (
                "0b10",
                [
                    "btrue",
                    "btrue n2",
                    "n10 s10 s2 strue",
                    "n10 n2 s10 s2 strue",
                ],
            ),
            (
                "0o10",
                [
                    "btrue n2",
                    "btrue n2",
                    "n10 s10 s2 strue",
                    "n10 s10 s2 strue",
                ],
            ),
            (
                "2e0",
                [
                    "btrue s10 s2",
                    "btrue n2 s10 s2",
                    "n10 strue",
                    "n10 n2 strue",
                ],
            ),
            (
                "Infinity",
                [
                    "btrue n10 n2 s10 s2",
                    "btrue n10 n2 s10 s2",
                    "strue",
                    "strue",
                ],
            ),
            (
                "-Infinity",
                [
                    "",
                    "",
                    "btrue n10 n2 s10 s2 strue",
                    "btrue n10 n2 s10 s2 strue",
                ],
            ),
            ("+0x10", ["", "", "s10 s2 strue", "s10 s2 strue"]),
            ("1_0", ["s10", "s10", "s2 strue", "s2 strue"]),
            ("inf", ["s10 s2", "s10 s2", "strue", "strue"]),
            ("\u{0085}", ["s10 s2 strue", "s10 s2 strue", "", ""]),
        ];
        let array_cases = [
            (
                vec![],
                [
                    "",
                    "",
                    "btrue n10 n2 s10 s2 strue",
                    "btrue n10 n2 s10 s2 strue",
                ],
            ),
            (
                vec!["2"],
                [
                    "btrue s10",
                    "btrue n2 s10 s2",
                    "n10 strue",
                    "n10 n2 s2 strue",
                ],
            ),
            (vec!["1", "0"], ["", "", "s10 s2 strue", "s10 s2 strue"]),
            (vec!["", ""], ["", "", "s10 s2 strue", "s10 s2 strue"]),
            (vec!["notnumeric"], ["s10 s2", "s10 s2", "strue", "strue"]),
        ];
        let cases = scalar_cases
            .into_iter()
            .map(|(value, expected)| (crate::UserFilterValue::from(value), expected))
            .chain(array_cases.into_iter().map(|(values, expected)| {
                (
                    values
                        .into_iter()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                        .into(),
                    expected,
                )
            }));
        for (value, expected) in cases {
            for field in ["id", "_id"] {
                for (operator, expected) in ["lt", "lte", "gt", "gte"].into_iter().zip(expected) {
                    let (users, count) = store
                        .list_users(ListUsersParams {
                            filter_field: Some(field.into()),
                            filter_operator: Some(operator.into()),
                            filter_value: Some(value.clone()),
                            sort_by: Some("name".into()),
                            sort_direction: Some("asc".into()),
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    let names = users
                        .iter()
                        .map(|user| user.name.as_deref().unwrap())
                        .collect::<Vec<_>>();
                    assert_eq!(names.join(" "), expected, "{field} {operator} {value:?}");
                    assert_eq!(count, names.len(), "{field} {operator} {value:?}");
                }
            }
        }

        for (operator, value, expected) in [
            ("eq", "2".into(), "s2"),
            ("ne", "2".into(), "btrue n10 n2 s10 strue"),
            (
                "in",
                vec!["2".to_owned(), "10".to_owned(), "true".to_owned()].into(),
                "s10 s2 strue",
            ),
            (
                "not_in",
                vec!["2".to_owned(), "10".to_owned(), "true".to_owned()].into(),
                "btrue n10 n2",
            ),
        ] {
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some("id".into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(value),
                    sort_by: Some("name".into()),
                    sort_direction: Some("asc".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let names = users
                .iter()
                .map(|user| user.name.as_deref().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(names.join(" "), expected, "{operator}");
            assert_eq!(count, names.len());
        }

        let (page, count) = store
            .list_users(ListUsersParams {
                filter_field: Some("id".into()),
                filter_operator: Some("gte".into()),
                filter_value: Some("10".into()),
                sort_by: Some("name".into()),
                sort_direction: Some("asc".into()),
                offset: Some(1),
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(count, 4);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].name.as_deref(), Some("s10"));
    }

    async fn physical_relational_utf16<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        for (raw, label) in [
            (json!("\u{10000}"), "astral"),
            (json!("\u{e000}"), "bmp"),
            (json!(2), "number"),
        ] {
            store
                .create_user(CreateUser {
                    name: Some(label.into()),
                    email: Some(format!("{label}@example.test")),
                    adapter_native_fields: [("id".to_owned(), raw.into())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for (value, expected) in [
            ("\u{e000}", ["astral", "astral bmp", "", "bmp"]),
            ("\u{10000}", ["", "astral", "bmp", "astral bmp"]),
        ] {
            for (operator, expected) in ["lt", "lte", "gt", "gte"].into_iter().zip(expected) {
                let (users, count) = store
                    .list_users(ListUsersParams {
                        filter_field: Some("id".into()),
                        filter_operator: Some(operator.into()),
                        filter_value: Some(value.into()),
                        sort_by: Some("name".into()),
                        sort_direction: Some("asc".into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let names = users
                    .iter()
                    .map(|user| user.name.as_deref().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(names.join(" "), expected, "{operator} {value:?}");
                assert_eq!(count, names.len());
            }
        }
    }

    #[tokio::test]
    async fn stateless_physical_primitive_id_relational_filters() {
        physical_relational_filters::<StatelessSchema>(&StatelessStore::default()).await;
    }

    #[tokio::test]
    async fn memory_physical_primitive_id_relational_filters() {
        physical_relational_filters::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn stateless_physical_primitive_id_relational_utf16() {
        physical_relational_utf16::<StatelessSchema>(&StatelessStore::default()).await;
    }

    #[tokio::test]
    async fn memory_physical_primitive_id_relational_utf16() {
        physical_relational_utf16::<BundledSchema>(&MemoryStore::default()).await;
    }

    async fn typed_filter_operands<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        for (raw, label) in [
            (json!(2), "n2"),
            (json!("2"), "s2"),
            (json!(10), "n10"),
            (json!("10"), "s10"),
            (json!(true), "btrue"),
            (json!("true"), "strue"),
        ] {
            store
                .create_user(CreateUser {
                    name: Some(label.into()),
                    email: Some(format!("{label}@example.test")),
                    adapter_native_fields: [("id".to_owned(), raw.into())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for (operator, raw, expected) in [
            ("lt", json!(10), "btrue n2 s2"),
            ("lt", json!("10"), "btrue n2"),
            ("lte", json!(true), "btrue"),
            ("lte", json!("true"), "s10 s2 strue"),
            ("eq", json!(2), "n2"),
            ("eq", json!(false), ""),
            ("ne", json!(false), "btrue n10 n2 s10 s2 strue"),
            ("eq", json!(["2"]), ""),
            ("ne", json!(["2"]), "btrue n10 n2 s10 s2 strue"),
            ("ne", json!(2), "btrue n10 s10 s2 strue"),
            ("eq", json!(true), "btrue"),
            ("ne", json!(true), "n10 n2 s10 s2 strue"),
            ("in", json!([2, 10]), "n10 n2"),
            ("not_in", json!([2, 10]), "btrue s10 s2 strue"),
            ("in", json!(["2", "10"]), "s10 s2"),
            ("not_in", json!(["2", "10"]), "btrue n10 n2 strue"),
            ("eq", json!([2]), ""),
            ("ne", json!([2]), "btrue n10 n2 s10 s2 strue"),
            ("lt", json!([10]), "btrue n2"),
            ("lte", json!([]), ""),
        ] {
            for field in ["id", "_id"] {
                let operand = serde_json::from_value(raw.clone()).unwrap();
                let (users, count) = store
                    .list_users(ListUsersParams {
                        filter_field: Some(field.into()),
                        filter_operator: Some(operator.into()),
                        filter_value: Some(operand),
                        sort_by: Some("name".into()),
                        sort_direction: Some("asc".into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let names = users
                    .iter()
                    .map(|user| user.name.as_deref().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(names.join(" "), expected, "{field} {operator} {raw}");
                assert_eq!(count, names.len());
            }
        }
    }

    #[tokio::test]
    async fn typed_user_filter_memory_operands() {
        typed_filter_operands::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn typed_user_filter_stateless_operands() {
        typed_filter_operands::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn legacy_filter_operands<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        use crate::UserFilterValue::{Multiple, Native, Scalar};

        let user = store
            .create_user(CreateUser {
                id: Some("unicode-filter".into()),
                name: Some("\u{10000}".into()),
                email: Some("alpha@example.test".into()),
                email_verified: Some(true),
                banned: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();

        for (field, operator, operand, expected) in [
            ("name", "lt", Scalar("\u{e000}".into()), true),
            ("name", "gte", Scalar("\u{e000}".into()), false),
            ("email", "lt", Multiple(vec!["z".into()]), true),
            ("email", "gt", Multiple(vec!["a".into()]), true),
            (
                "email",
                "lte",
                Multiple(vec!["alpha@example.test".into()]),
                true,
            ),
            ("banned", "eq", Scalar("not-true".into()), true),
            ("emailVerified", "eq", Scalar("true".into()), true),
            (
                "createdAt",
                "eq",
                Scalar(user.created_at.to_rfc3339()),
                false,
            ),
            (
                "createdAt",
                "ne",
                Scalar(user.created_at.to_rfc3339()),
                true,
            ),
            (
                "createdAt",
                "lte",
                Scalar(user.created_at.to_rfc3339()),
                false,
            ),
            (
                "createdAt",
                "gte",
                Scalar(user.created_at.timestamp_millis().to_string()),
                true,
            ),
            (
                "email",
                "in",
                Multiple(vec!["alpha@example.test".into()]),
                true,
            ),
        ] {
            for operand in [operand.clone(), Native(operand.native())] {
                let (users, count) = store
                    .list_users(ListUsersParams {
                        filter_field: Some(field.into()),
                        filter_operator: Some(operator.into()),
                        filter_value: Some(operand.clone()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    count,
                    usize::from(expected),
                    "{field} {operator} {operand:?}"
                );
                assert_eq!(users.len(), count);
                if expected {
                    assert_eq!(users[0].id, user.id);
                }
            }
        }
    }

    #[tokio::test]
    async fn legacy_user_filter_memory_operands_match_native_channel() {
        legacy_filter_operands::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn legacy_user_filter_stateless_operands_match_native_channel() {
        legacy_filter_operands::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn optional_user_sort<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        for (id, day, verified) in [
            ("b", 2, true),
            ("c", 1, true),
            ("a", 3, true),
            ("d", 4, false),
        ] {
            store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    email: Some(format!("{id}@example.test")),
                    email_verified: Some(verified),
                    created_at: Some(
                        chrono::DateTime::parse_from_rfc3339(&format!(
                            "2020-01-{day:02}T00:00:00Z"
                        ))
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    ),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let params = ListUsersParams {
            search_value: Some("@example.test".into()),
            filter_field: Some("emailVerified".into()),
            filter_value: Some("true".into()),
            ..Default::default()
        };
        let ids = |users: &[UserView]| {
            users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let native_order = "b c a";
        for sort_by in [None, Some("")] {
            for sort_direction in [None, Some("asc"), Some("desc")] {
                let query = ListUsersParams {
                    sort_by: sort_by.map(str::to_owned),
                    sort_direction: sort_direction.map(str::to_owned),
                    ..params.clone()
                };
                let (users, count) = store.list_users(query.clone()).await.unwrap();
                assert_eq!(ids(&users), native_order, "{sort_by:?} {sort_direction:?}");
                assert_eq!(count, 3);
                for (offset, limit) in [(0, 2), (1, 1), (2, 2), (3, 1)] {
                    let (page, total) = store
                        .list_users(ListUsersParams {
                            offset: Some(offset),
                            limit: Some(limit),
                            ..query.clone()
                        })
                        .await
                        .unwrap();
                    let expected = native_order
                        .split(' ')
                        .skip(offset)
                        .take(limit)
                        .collect::<Vec<_>>();
                    assert_eq!(ids(&page), expected.join(" "));
                    assert_eq!(total, 3);
                }
            }
        }
        for (direction, expected) in [
            (None, "c b a"),
            (Some("asc"), "c b a"),
            (Some("desc"), "a b c"),
        ] {
            let (users, count) = store
                .list_users(ListUsersParams {
                    sort_by: Some("createdAt".into()),
                    sort_direction: direction.map(str::to_owned),
                    ..params.clone()
                })
                .await
                .unwrap();
            assert_eq!(ids(&users), expected, "{direction:?}");
            assert_eq!(count, 3);
        }
        store
            .update_user(
                "c",
                UpdateUser {
                    name: Some("renamed".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let (users, count) = store.list_users(params.clone()).await.unwrap();
        assert_eq!(ids(&users), "b c a");
        assert_eq!(count, 3);
        store.delete_user("c").await.unwrap();
        let (users, count) = store.list_users(params.clone()).await.unwrap();
        assert_eq!(ids(&users), "b a");
        assert_eq!(count, 2);
        store
            .create_user(CreateUser {
                id: Some("c".into()),
                email: Some("c@example.test".into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        let (users, count) = store.list_users(params).await.unwrap();
        assert_eq!(ids(&users), "b a c");
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn optional_user_sort_memory_preserves_insertion_order() {
        optional_user_sort::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn optional_user_sort_stateless_preserves_insertion_order() {
        optional_user_sort::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn empty_user_list_selectors<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        store
            .create_user(CreateUser {
                id: Some("no-email".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .create_user(CreateUser {
                id: Some("with-email".into()),
                email: Some("alpha@example.test".into()),
                ..Default::default()
            })
            .await
            .unwrap();

        for (params, expected) in [
            (
                ListUsersParams {
                    search_value: Some("".into()),
                    ..Default::default()
                },
                vec!["no-email", "with-email"],
            ),
            (
                ListUsersParams {
                    search_value: Some("".into()),
                    search_field: Some("username".into()),
                    search_operator: Some("starts_with".into()),
                    ..Default::default()
                },
                vec!["no-email", "with-email"],
            ),
            (
                ListUsersParams {
                    search_value: Some("alpha".into()),
                    search_field: Some("".into()),
                    ..Default::default()
                },
                vec!["with-email"],
            ),
            (
                ListUsersParams {
                    filter_field: Some("".into()),
                    filter_value: Some("alpha@example.test".into()),
                    ..Default::default()
                },
                vec!["with-email"],
            ),
            (
                ListUsersParams {
                    filter_value: Some("".into()),
                    ..Default::default()
                },
                vec![],
            ),
        ] {
            let (users, count) = store.list_users(params.clone()).await.unwrap();
            let ids = users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(ids, expected, "{params:?}");
            assert_eq!(count, expected.len());
        }
    }

    #[tokio::test]
    async fn empty_user_list_selectors_memory_follow_admin_truthiness() {
        empty_user_list_selectors::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn empty_user_list_selectors_stateless_follow_admin_truthiness() {
        empty_user_list_selectors::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn ordinary_string_collation<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        for (id, value) in [
            ("z", Some("z")),
            ("upper-a", Some("A")),
            ("lower-a", Some("a")),
            ("accent", Some("é")),
            ("decomposed", Some("e\u{301}")),
            ("upper-e", Some("E")),
            ("lower-e", Some("e")),
            ("upper-z", Some("Z")),
            ("lower-b", Some("b")),
            ("upper-b", Some("B")),
            ("missing-1", None),
            ("missing-2", None),
            ("upper-accent", Some("É")),
        ] {
            let created = store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    name: value.map(str::to_owned),
                    email: value.map(|value| format!("{value}-{id}@example.test")),
                    username: value.map(str::to_owned),
                    role: value.map(str::to_owned),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(created.name.as_deref(), value);
            assert_eq!(created.username.as_deref(), value);
            assert_eq!(created.role.as_deref(), value);
            assert_eq!(
                created.email,
                value.map(|value| format!("{value}-{id}@example.test").to_lowercase())
            );
        }

        // Better Auth 1.7.18 memory-adapter.ts:176-225, Node default en-US.
        for field in ["name", "username", "role", "email"] {
            for direction in [None, Some("asc"), Some("desc")] {
                let expected = match (field, direction) {
                    ("email", Some("desc")) => {
                        "z upper-z upper-e upper-accent lower-e decomposed accent upper-b lower-b upper-a lower-a missing-1 missing-2"
                    }
                    ("email", _) => {
                        "missing-1 missing-2 lower-a upper-a lower-b upper-b accent decomposed lower-e upper-accent upper-e upper-z z"
                    }
                    (_, Some("desc")) => {
                        "upper-z z upper-accent accent decomposed upper-e lower-e upper-b lower-b upper-a lower-a missing-1 missing-2"
                    }
                    _ => {
                        "missing-1 missing-2 lower-a upper-a lower-b upper-b lower-e upper-e accent decomposed upper-accent z upper-z"
                    }
                };
                let params = ListUsersParams {
                    sort_by: Some(field.into()),
                    sort_direction: direction.map(str::to_owned),
                    ..Default::default()
                };
                let (users, count) = store.list_users(params.clone()).await.unwrap();
                let ids = users
                    .iter()
                    .map(|user| user.id.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(ids.join(" "), expected, "{field} {direction:?}");
                assert_eq!(count, 13, "{field} {direction:?}");

                for (offset, limit) in [(0, 4), (2, 5), (9, 6), (13, 2), (0, 0)] {
                    let (page, total) = store
                        .list_users(ListUsersParams {
                            offset: Some(offset),
                            limit: Some(limit),
                            ..params.clone()
                        })
                        .await
                        .unwrap();
                    let ids = page.iter().map(|user| user.id.as_str()).collect::<Vec<_>>();
                    assert_eq!(
                        ids,
                        expected
                            .split(' ')
                            .skip(offset)
                            .take(limit)
                            .collect::<Vec<_>>(),
                        "{field} {direction:?} offset={offset} limit={limit}"
                    );
                    assert_eq!(total, 13, "{field} {direction:?}");
                }
            }
        }
    }

    #[tokio::test]
    async fn ordinary_string_collation_memory_matches_locale_compare() {
        ordinary_string_collation::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn ordinary_string_collation_stateless_matches_locale_compare() {
        ordinary_string_collation::<StatelessSchema>(&StatelessStore::default()).await;
    }

    async fn homogeneous_id_sorting<S: AuthSchema<User = UserView>>(
        store: &impl UserStore<S>,
        numeric: bool,
    ) {
        use crate::utils::json::JsValue;
        let fixtures: Vec<(JsValue, &str)> = if numeric {
            vec![
                (JsValue::Number(20.0), "n20"),
                (JsValue::Number(2.0), "n2"),
                (JsValue::Number(10.0), "n10"),
                (JsValue::Number(-2.0), "negative"),
                (JsValue::Number(1.5), "fraction"),
                (JsValue::Number(f64::INFINITY), "infinity"),
                (JsValue::Number(f64::NEG_INFINITY), "negative-infinity"),
            ]
        } else {
            [
                ("z", "z"),
                ("A", "upper-a"),
                ("a", "lower-a"),
                ("é", "accent"),
                ("e\u{301}", "decomposed"),
                ("E", "upper-e"),
                ("e", "lower-e"),
                ("Z", "upper-z"),
                ("b", "lower-b"),
                ("B", "upper-b"),
                ("É", "upper-accent"),
            ]
            .into_iter()
            .map(|(id, label)| (JsValue::String(id.into()), label))
            .collect()
        };
        for (id, label) in &fixtures {
            store
                .create_user(CreateUser {
                    name: Some((*label).into()),
                    email: Some(format!("{label}@source-id.example.test")),
                    adapter_native_fields: [("id".into(), id.clone())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }

        // Better Auth 1.7.18 memory-adapter.ts:176-225; Node en-US oracle.
        for field in ["id", "_id"] {
            for direction in [None, Some("asc"), Some("desc")] {
                for filtered in [false, true] {
                    let expected = match (numeric, direction, filtered) {
                        (true, Some("desc"), false) => {
                            "infinity n20 n10 n2 fraction negative negative-infinity"
                        }
                        (true, _, false) => {
                            "negative-infinity negative fraction n2 n10 n20 infinity"
                        }
                        (true, Some("desc"), true) => "infinity n20 n10",
                        (true, _, true) => "n10 n20 infinity",
                        (false, Some("desc"), false) => {
                            "upper-z z upper-accent accent decomposed upper-e lower-e upper-b lower-b upper-a lower-a"
                        }
                        (false, _, false) => {
                            "lower-a upper-a lower-b upper-b lower-e upper-e accent decomposed upper-accent z upper-z"
                        }
                        (false, Some("desc"), true) => "upper-accent accent decomposed",
                        (false, _, true) => "accent decomposed upper-accent",
                    };
                    let params = ListUsersParams {
                        sort_by: Some(field.into()),
                        sort_direction: direction.map(str::to_owned),
                        filter_field: filtered.then(|| field.into()),
                        filter_operator: filtered
                            .then(|| if numeric { "gte" } else { "in" }.into()),
                        filter_value: filtered.then(|| {
                            serde_json::from_value(if numeric {
                                json!(10)
                            } else {
                                json!(["é", "e\u{301}", "É"])
                            })
                            .unwrap()
                        }),
                        ..Default::default()
                    };
                    let expected = expected.split(' ').collect::<Vec<_>>();
                    for (offset, limit) in [(0, 20), (0, 4), (2, 5), (9, 6), (13, 2), (0, 0)] {
                        let (users, count) = store
                            .list_users(ListUsersParams {
                                offset: Some(offset),
                                limit: Some(limit),
                                ..params.clone()
                            })
                            .await
                            .unwrap();
                        assert_eq!(count, expected.len(), "{numeric} {field} {direction:?}");
                        assert_eq!(
                            users
                                .iter()
                                .map(|user| user.name.as_deref().unwrap())
                                .collect::<Vec<_>>(),
                            expected
                                .iter()
                                .copied()
                                .skip(offset)
                                .take(limit)
                                .collect::<Vec<_>>(),
                            "{numeric} {field} {direction:?} {filtered} {offset} {limit}",
                        );
                    }
                }
            }
        }

        if numeric {
            store
                .create_user(CreateUser {
                    id: Some("string-outsider".into()),
                    email: Some("outside@other.test".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let (users, count) = store
                .list_users(ListUsersParams {
                    sort_by: Some("id".into()),
                    search_field: Some("email".into()),
                    search_operator: Some("ends_with".into()),
                    search_value: Some("@source-id.example.test".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(count, 7);
            assert_eq!(
                users
                    .iter()
                    .map(|user| user.name.as_deref().unwrap())
                    .collect::<Vec<_>>(),
                [
                    "negative-infinity",
                    "negative",
                    "fraction",
                    "n2",
                    "n10",
                    "n20",
                    "infinity"
                ],
            );
        }
    }

    #[tokio::test]
    async fn homogeneous_id_sorting_memory_uses_physical_numbers_and_collated_strings() {
        homogeneous_id_sorting::<BundledSchema>(&MemoryStore::default(), true).await;
        homogeneous_id_sorting::<BundledSchema>(&MemoryStore::default(), false).await;
    }

    #[tokio::test]
    async fn homogeneous_id_sorting_stateless_uses_physical_numbers_and_collated_strings() {
        homogeneous_id_sorting::<StatelessSchema>(&StatelessStore::default(), true).await;
        homogeneous_id_sorting::<StatelessSchema>(&StatelessStore::default(), false).await;
    }

    async fn update_preserves_row_order<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
        use crate::utils::json::{self, JsValue};
        let fixture =
            json::parse_value(include_str!("memory_user_update_order_cases.json")).unwrap();
        assert_eq!(fixture["better_auth"], "1.7.18");
        for id in ["first", "middle", "last"] {
            store
                .create_user(CreateUser {
                    id: Some(id.into()),
                    name: Some("tie".into()),
                    email: Some(format!("{id}@test")),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 5);
        for (index, case) in cases.iter().enumerate() {
            let id = case["id"].as_str().unwrap();
            if index == 0 {
                store
                    .update_user(
                        id,
                        UpdateUser {
                            email: Some(case["update"]["email"].as_str().unwrap().into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
            } else {
                store
                    .update_user_prepared(
                        id,
                        crate::store::PreparedUserUpdate {
                            data: case["update"].as_object().unwrap().clone(),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap();
            }
            for (key, params) in [
                ("ids", ListUsersParams::default()),
                (
                    "tied",
                    ListUsersParams {
                        sort_by: Some("name".into()),
                        sort_direction: Some("asc".into()),
                        ..Default::default()
                    },
                ),
                (
                    "page",
                    ListUsersParams {
                        offset: Some(1),
                        limit: Some(1),
                        ..Default::default()
                    },
                ),
            ] {
                let (users, count) = store.list_users(params).await.unwrap();
                assert_eq!(count, 3, "step {index}/{key}");
                let ids = JsValue::Array(
                    users
                        .iter()
                        .map(|user| JsValue::String(user.id.clone().into()))
                        .collect(),
                );
                assert_eq!(ids, case[key], "step {index}/{key}");
            }
            let first = store
                .get_user_by_id(case["ids"][0].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.email.as_deref(), Some("CASE@TEST"));
        }
        assert!(
            store
                .get_user_by_id("renamed-first")
                .await
                .unwrap()
                .is_none()
        );
        let (users, count) = store.list_users(ListUsersParams::default()).await.unwrap();
        assert_eq!(count, 3);
        assert_eq!(
            users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>(),
            ["middle", "middle", "last"]
        );
    }

    #[tokio::test]
    async fn memory_user_update_order_survives_typed_and_prepared_writes() {
        update_preserves_row_order::<BundledSchema>(&MemoryStore::default()).await;
    }

    #[tokio::test]
    async fn stateless_user_update_order_survives_typed_and_prepared_writes() {
        update_preserves_row_order::<StatelessSchema>(&StatelessStore::default()).await;
    }
}

mod memory_user_sort;
#[cfg(test)]
mod memory_user_sort_tests {
    use crate::store::{
        UserStore,
        stateless::{StatelessSchema, StatelessStore},
    };
    use crate::test_store::{BundledSchema, MemoryStore};
    use crate::utils::json::JsValue;
    use crate::{AuthSchema, CreateUser, ListUsersParams, UserView};

    #[derive(serde::Deserialize)]
    struct Oracle {
        node: String,
        v8: String,
        icu: String,
        locale: String,
        better_auth: String,
        cases: Vec<Case>,
    }

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        ids: Vec<JsValue>,
        asc: Vec<usize>,
        desc: Vec<usize>,
        filtered_asc: Vec<usize>,
        filtered_desc: Vec<usize>,
    }

    fn oracle() -> Oracle {
        let data: Oracle =
            serde_json::from_str(include_str!("memory_user_sort_cases.json")).unwrap();
        assert_eq!(data.node, "v26.13.0");
        assert_eq!(data.v8, "14.6.202.34-node.40");
        assert_eq!(data.icu, "78.3");
        assert_eq!(data.locale, "en-US");
        assert_eq!(data.better_auth, "1.7.18");
        assert_eq!(data.cases.len(), 77);
        data
    }

    async fn compare_case<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>, case: &Case) {
        for (index, id) in case.ids.iter().enumerate() {
            store
                .create_user(CreateUser {
                    name: Some(index.to_string()),
                    email: Some(format!(
                        "{index}@{}.fixture.test",
                        if index % 3 == 0 { "keep" } else { "other" },
                    )),
                    adapter_native_fields: [("id".into(), id.clone())].into(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for field in ["id", "_id"] {
            for direction in [None, Some("asc"), Some("desc")] {
                for filtered in [false, true] {
                    let expected = match (direction, filtered) {
                        (Some("desc"), false) => &case.desc,
                        (Some("desc"), true) => &case.filtered_desc,
                        (_, false) => &case.asc,
                        (_, true) => &case.filtered_asc,
                    };
                    for (offset, limit) in [
                        (0, case.ids.len() + 1),
                        (2, 5),
                        (expected.len().saturating_sub(2), 5),
                        (expected.len() + 3, 2),
                        (0, 0),
                    ] {
                        let (users, count) = store
                            .list_users(ListUsersParams {
                                sort_by: Some(field.into()),
                                sort_direction: direction.map(str::to_owned),
                                search_field: filtered.then(|| "email".into()),
                                search_value: filtered.then(|| "@keep.".into()),
                                offset: Some(offset),
                                limit: Some(limit),
                                ..Default::default()
                            })
                            .await
                            .unwrap();
                        let actual = users
                            .iter()
                            .map(|user| user.name.as_ref().unwrap().parse::<usize>().unwrap())
                            .collect::<Vec<_>>();
                        assert_eq!(count, expected.len(), "{}", case.name);
                        assert_eq!(
                            actual,
                            expected
                                .iter()
                                .copied()
                                .skip(offset)
                                .take(limit)
                                .collect::<Vec<_>>(),
                            "{} {field} {direction:?} filtered={filtered} offset={offset} limit={limit}",
                            case.name,
                        );
                    }
                }
            }
        }
        let (users, count) = store
            .list_users(ListUsersParams {
                limit: Some(case.ids.len() + 1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(count, case.ids.len());
        assert_eq!(
            users
                .iter()
                .map(|user| user.name.as_ref().unwrap().parse::<usize>().unwrap())
                .collect::<Vec<_>>(),
            (0..case.ids.len()).collect::<Vec<_>>(),
            "{}: sorting mutated physical insertion order",
            case.name,
        );
    }

    #[tokio::test]
    async fn mixed_id_sorting_memory_matches_pinned_runtime() {
        for case in oracle().cases {
            compare_case::<BundledSchema>(&MemoryStore::default(), &case).await;
        }
    }

    #[tokio::test]
    async fn mixed_id_sorting_stateless_matches_pinned_runtime() {
        for case in oracle().cases {
            compare_case::<StatelessSchema>(&StatelessStore::default(), &case).await;
        }
    }
}

mod migrations;
pub mod oauth_clients;
mod org_extensions;
pub mod scim;
mod scim_group_patch;
pub use scim_group_patch::{
    ScimGroupPatch, ScimGroupPatchKind, ScimGroupPatchOperation, apply_scim_group_patch,
    check_scim_group_cardinality, prepare_scim_group_patch,
};
mod secondary_sessions;
pub mod secondary_storage;
mod session_deletion;
mod sso;
pub mod stateless;
mod wallets;
use crate::schema::AuthSchema;
use contracts::create_user_data;
pub use contracts::{
    AccountStore, AdapterAfterHook, AdapterEvent, AfterCommitErrorPolicy, ApiKeyStore,
    AuthTransaction, BoxedTransactionValue, ConsumeApiKeyResult, DeviceCodeStore,
    InvitationCreateOptions, InvitationStore, ListOrganizationMembersParams, MemberPageQuery,
    MemberStore, NumericTextInput, OrganizationStore, PasskeyStore, PreparedUserUpdate,
    SessionCreatedHook, SessionRevocation, SessionStore, TransactionFuture, TransactionStore,
    TransactionWork, TwoFactorStore, TypedTransactionFuture, UserCreateHook, UserCreationDefaults,
    UserStore, UserUpdateFieldMetadata, UserUpdateHook, UserUpdateHookResult, UserUpdatePatch,
    VerificationStore, transaction, transaction_with_policy, verification_reservation_id,
    verification_reservation_key, write_transaction,
};
pub(crate) use contracts::{UserCreateStep, UserUpdateStep};
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
pub(crate) use decorated::{
    AdapterCallbacks, PluginStore, SessionCreatedCallbacks, UserTransforms,
};
pub use jwks::JwkStore;
pub use migrations::SchemaMigrator;
pub use oauth_clients::{
    CreateOAuthClient, CreateOAuthClientResource, CreateOAuthConsent, CreateOAuthResource,
    CreateOAuthToken, OAuthClient, OAuthClientResource, OAuthClientStore, OAuthConsent,
    OAuthResource, OAuthToken, OAuthTokenKind,
};
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};
pub use scim::{
    CreateScimGroup, CreateScimManagedConnection, CreateScimProjectionGrant, CreateScimUser,
    DecommissionScimManagedConnection, ReplaceScimGroup, ReplaceScimUser,
    RevokeScimManagedCredential, RotateScimManagedCredential, ScimAuthorizationSource,
    ScimConnectionBinding, ScimGroupMemberRecord, ScimGroupMemberships, ScimGroupPage,
    ScimGroupRecord, ScimIdentitySource, ScimIdentityState, ScimIdentityTombstone,
    ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedConnectionState,
    ScimManagedCreation, ScimManagedCredential, ScimManagedStore, ScimProjectedUserState,
    ScimProjectionCandidate, ScimProjectionPreparedUser, ScimRoleExistenceInput,
    ScimRoleMappingInput, ScimUserAttributes, ScimUserMutationContext, ScimUserPage,
    ScimUserRecord, scim_group_membership_key,
};
#[cfg(feature = "redis-cache")]
pub use secondary_storage::RedisAdapter;
pub use secondary_storage::{CacheAdapter, MemoryCacheAdapter};
pub(crate) use session_deletion::SessionDeletionHooks;
pub use session_deletion::{SessionDeletionHook, SessionDeletionWork};
pub use sso::{
    SsoFieldType, SsoProvider, SsoProviderStore, SsoProviderUpdate, SsoProviderUpdateWork,
    prepare_sso_fields, project_sso_provider, sso_field_column, sso_field_definition,
    validate_sso_fields,
};
pub use wallets::WalletAddressStore;

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + MemberStore
    + InvitationStore
    + OAuthClientStore
    + SsoProviderStore
    + ScimManagedStore
    + TeamStore
    + OrganizationRoleStore
    + WalletAddressStore
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + DeviceCodeStore
    + JwkStore
    + TransactionStore<S>
    + Send
    + Sync
{
}

impl<S, T> AuthStore<S> for T
where
    S: AuthSchema,
    T: UserStore<S>
        + SessionStore<S>
        + AccountStore<S>
        + VerificationStore<S>
        + OrganizationStore
        + MemberStore
        + InvitationStore
        + OAuthClientStore
        + SsoProviderStore
        + ScimManagedStore
        + TeamStore
        + OrganizationRoleStore
        + WalletAddressStore
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + DeviceCodeStore
        + JwkStore
        + TransactionStore<S>
        + Send
        + Sync,
{
}
