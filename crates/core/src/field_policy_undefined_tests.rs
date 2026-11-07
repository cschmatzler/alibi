use super::{FieldConfig, FieldValues, SessionAdapterFields};
use crate::utils::json::JsValue;
use std::sync::{Arc, Mutex};

#[derive(Debug, serde::Deserialize)]
struct Observed {
    undefined: bool,
    value: JsValue,
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    creation: bool,
    required: bool,
    has_default: bool,
    on_update: bool,
    transform: bool,
    kind: String,
    input: JsValue,
    present: bool,
    expected: JsValue,
    events: Vec<String>,
    observed: Vec<Observed>,
}

#[derive(serde::Deserialize)]
struct Fixture {
    better_auth: String,
    cases: Vec<Case>,
}

async fn assert_factory_cases(asynchronous: bool) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("field_policy_undefined_cases.json")).unwrap();
    assert_eq!(fixture.better_auth, "1.7.18");
    assert_eq!(fixture.cases.len(), 256);
    for case in fixture.cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut field = FieldConfig::new(serde_json::json!({"type":"string"}));
        field.required = case.required;
        if case.has_default {
            let events = events.clone();
            field = field.default_callback(move || {
                events.lock().unwrap().push("default".to_owned());
                JsValue::String("default".into())
            });
        }
        if case.on_update {
            let events = events.clone();
            field = field.on_update(move || {
                events.lock().unwrap().push("update".to_owned());
                JsValue::String("updated".into())
            });
        }
        if case.transform {
            let events = events.clone();
            let observed = observed.clone();
            if asynchronous {
                field = field.transform_adapter_input(move |value| {
                    events.lock().unwrap().push("input".to_owned());
                    observed.lock().unwrap().push(value.clone());
                    async move { Ok(value) }
                });
            } else {
                field = field.transform(move |value| {
                    events.lock().unwrap().push("input".to_owned());
                    observed.lock().unwrap().push(value.cloned());
                    Ok(value.cloned())
                });
            }
        }
        let policy = SessionAdapterFields(Arc::new(
            [("marker".to_owned(), field)].into_iter().collect(),
        ));
        let mut fields = FieldValues::new();
        if case.kind != "absent" {
            _ = fields.insert(
                "marker".into(),
                if case.kind == "undefined" {
                    JsValue::Undefined
                } else {
                    case.input.clone()
                },
            );
        }
        policy.attach(&mut fields, case.creation);
        if asynchronous {
            fields.apply_adapter_transforms_async().await.unwrap();
        } else {
            fields.apply_adapter_transforms().unwrap();
        }
        assert_eq!(*events.lock().unwrap(), case.events, "{case:?}");
        let expected_inputs: Vec<_> = case
            .observed
            .iter()
            .map(|input| (!input.undefined).then_some(input.value.clone()))
            .collect();
        assert_eq!(*observed.lock().unwrap(), expected_inputs, "{case:?}");
        let stored = fields
            .get("marker")
            .cloned()
            .or_else(|| (!case.creation).then(|| JsValue::String("stored".into())));
        assert_eq!(stored.is_some(), case.present, "{case:?}");
        if case.present {
            assert_eq!(stored.as_ref(), Some(&case.expected), "{case:?}");
        }
        assert!(!fields.values().any(JsValue::is_undefined), "{case:?}");
        let snapshot = fields.clone();
        if asynchronous {
            fields.apply_adapter_transforms_async().await.unwrap();
        } else {
            fields.apply_adapter_transforms().unwrap();
        }
        assert_eq!(*fields, *snapshot, "{case:?}");
        assert_eq!(*events.lock().unwrap(), case.events, "{case:?}");
    }
}

async fn assert_memory_writes<S: crate::AuthSchema<User = crate::UserView>>(
    create_store: impl Fn(Arc<crate::AuthConfig>) -> Arc<dyn crate::AuthStore<S>>,
) {
    for on_update in [false, true] {
        let inputs = Arc::new(Mutex::new(Vec::new()));
        let observed = inputs.clone();
        let mut field = FieldConfig::new(serde_json::json!({"type":"string"}))
            .default_value(JsValue::String("default".into()));
        if on_update {
            field = field.on_update(|| JsValue::String("updated".into()));
        }
        field = field.transform_adapter_input(move |value| {
            observed.lock().unwrap().push(value.clone());
            async move { Ok(value) }
        });
        let mut config = crate::AuthConfig::default();
        _ = config.user.additional_fields.insert("marker".into(), field);
        let config = Arc::new(config);
        let physical = create_store(config.clone());
        let store = crate::AuthInitContext::new(config, physical.clone())
            .database_with_registered_transforms();
        let mut input = crate::CreateUser::new().with_email("undefined@fixture.test");
        _ = input
            .additional_fields
            .insert("marker".into(), JsValue::Undefined);
        let user = store.create_user(input).await.unwrap();
        assert_eq!(
            user.extension_fields["marker"],
            JsValue::String("default".into())
        );
        assert_eq!(
            *inputs.lock().unwrap(),
            [Some(JsValue::String("default".into()))]
        );
        for (value, expected) in [
            (
                None,
                JsValue::String(if on_update { "updated" } else { "default" }.into()),
            ),
            (
                Some(JsValue::Undefined),
                JsValue::String(if on_update { "updated" } else { "default" }.into()),
            ),
            (Some(JsValue::Null), JsValue::Null),
            (Some(JsValue::Bool(false)), JsValue::Bool(false)),
            (Some(JsValue::Number(0.0)), JsValue::Number(0.0)),
            (Some(JsValue::String("".into())), JsValue::String("".into())),
        ] {
            inputs.lock().unwrap().clear();
            let mut update = crate::UpdateUser::default();
            if let Some(value) = value.clone() {
                _ = update.additional_fields.insert("marker".into(), value);
            }
            let user = store.update_user(&user.id, update).await.unwrap();
            assert_eq!(user.extension_fields["marker"], expected);
            assert_eq!(
                physical
                    .get_user_by_id(&user.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .extension_fields["marker"],
                expected,
            );
            let missing = value.as_ref().is_none_or(JsValue::is_undefined);
            let expected_inputs: Vec<_> = if missing {
                if on_update {
                    vec![Some(JsValue::String("updated".into()))]
                } else {
                    vec![]
                }
            } else {
                vec![value]
            };
            assert_eq!(*inputs.lock().unwrap(), expected_inputs);
        }
    }
}

#[tokio::test]
async fn adapter_input_undefined_preserves_memory_values_and_on_update() {
    assert_memory_writes::<crate::test_store::BundledSchema>(|config| {
        Arc::new(crate::test_store::MemoryStore::new(config))
    })
    .await;
}

#[tokio::test]
async fn adapter_input_undefined_preserves_stateless_values_and_on_update() {
    assert_memory_writes::<crate::store::stateless::StatelessSchema>(|_| {
        Arc::new(crate::store::stateless::StatelessStore::default())
    })
    .await;
}

#[tokio::test]
async fn adapter_input_undefined_matches_synchronous_factory_cases() {
    assert_factory_cases(false).await;
}

#[tokio::test]
async fn adapter_input_undefined_matches_asynchronous_factory_cases() {
    assert_factory_cases(true).await;
}
