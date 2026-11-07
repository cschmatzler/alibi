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

async fn duplicate_rows<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>, paged: bool) {
    let fixture = json::parse_value(include_str!("memory_user_duplicate_cases.json")).unwrap();
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
