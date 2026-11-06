use super::memory_user_id::MemoryUserId;
use crate::store::{
    UserStore,
    stateless::{StatelessSchema, StatelessStore},
};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::{AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};
use serde_json::json;

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
                adapter_native_fields: [("id".to_owned(), raw)].into(),
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
        MemoryUserId::supplied(Some(&json!(2))).unwrap().0,
        MemoryUserId::supplied(Some(&json!(2.0))).unwrap().0
    );
    assert_ne!(
        MemoryUserId::supplied(Some(&json!(1))).unwrap().0,
        MemoryUserId::supplied(Some(&json!(true))).unwrap().0
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
        assert!(MemoryUserId::supplied(Some(&raw)).is_none());
    }
}
