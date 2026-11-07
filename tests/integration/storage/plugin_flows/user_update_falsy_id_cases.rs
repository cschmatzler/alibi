use alibi_core::store::UserStore;
use alibi_core::utils::json::{self, JsValue};
use alibi_core::{AuthSchema, AuthUser, CreateUser, UpdateUser};

pub(super) async fn exercise<S: AuthSchema>(store: &impl UserStore<S>) {
    let fixture = json::parse_value(include_str!(
        "../../../../crates/core/src/store/user_update_falsy_id_cases.json"
    ))
    .unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    let user = store
        .create_user(CreateUser {
            id: Some("fixed-user".into()),
            name: Some("initial".into()),
            email: Some("fixed@test".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(user.id(), "fixed-user");
    for case in cases {
        let kind = case["kind"].as_str().unwrap();
        let value = match kind {
            "absent" | "undefined" => JsValue::Undefined,
            "null" => JsValue::Null,
            "false" => JsValue::Bool(false),
            "zero" => JsValue::Number(0.0),
            "negative-zero" => JsValue::Number(-0.0),
            "nan" => JsValue::Number(f64::NAN),
            "empty" => JsValue::String("".into()),
            _ => panic!("unknown fixture kind: {kind}"),
        };
        let updated = store
            .update_user(
                "fixed-user",
                UpdateUser {
                    name: Some(kind.into()),
                    adapter_native_fields: if kind == "absent" {
                        Default::default()
                    } else {
                        [("id".into(), value)].into()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{kind}: {error}"));
        assert_eq!(updated.id(), case["id"].as_str().unwrap(), "{kind}");
        assert_eq!(updated.name().as_deref(), case["name"].as_str(), "{kind}");
        let stored = store.get_user_by_id("fixed-user").await.unwrap().unwrap();
        assert_eq!(stored.name().as_deref(), case["name"].as_str(), "{kind}");
    }
}
