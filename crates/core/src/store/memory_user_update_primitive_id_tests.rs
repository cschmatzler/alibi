use crate::store::UserStore;
use crate::utils::json::{self, JsValue};
use crate::{AuthSchema, CreateUser, ListUsersParams, UpdateUser, UserView};

fn cases() -> Vec<JsValue> {
    let fixture =
        json::parse_value(include_str!("memory_user_update_primitive_id_cases.json")).unwrap();
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
