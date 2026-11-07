use super::endpoint::{definitions, validate};
use alibi_core::endpoint::{EndpointCall, EndpointOptions};
use alibi_core::utils::json::{self, JsValue};
use validator::Validate;

fn assert_source_inputs(operation: &str, expected_cases: usize) {
    let fixture = json::parse_value(include_str!("canonical_input_cases.json")).unwrap();
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 36);
    let operation_id = if operation == "registration" {
        "passkeyVerifyRegistration"
    } else {
        "updatePasskey"
    };
    let definition = definitions()
        .into_iter()
        .find(|definition| definition.operation_id == operation_id)
        .unwrap();
    let mut matched = 0;
    for case in cases
        .iter()
        .filter(|case| case["operation"].as_str() == Some(operation))
    {
        matched += 1;
        let mode = case["mode"].as_str().unwrap();
        let mut input = case["input"].as_object().unwrap().clone();
        for key in case["input_undefined"].as_array().unwrap() {
            _ = input.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
        }
        let call = EndpointCall::new(
            &definition,
            Some(JsValue::Object(input)),
            None,
            EndpointOptions::default(),
        );
        let result = validate(&call);
        if !case["success"].as_bool().unwrap() {
            let alibi_core::AuthError::Api {
                status, message, ..
            } = result.unwrap_err()
            else {
                panic!("{operation}/{mode}: expected a validation error");
            };
            assert_eq!(status, 400);
            assert_eq!(
                message,
                case["error"].as_str().unwrap(),
                "{operation}/{mode}"
            );
            continue;
        }
        let body = result
            .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"))
            .body
            .unwrap();
        let mut expected = case["expected"].as_object().unwrap().clone();
        for key in case["undefined"].as_array().unwrap() {
            _ = expected.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
        }
        assert_eq!(body, JsValue::Object(expected), "{operation}/{mode}");
        let keys = JsValue::Array(
            body.as_object()
                .unwrap()
                .keys()
                .cloned()
                .map(JsValue::String)
                .collect(),
        );
        assert_eq!(keys, case["keys"], "{operation}/{mode}");
        assert_eq!(
            json::to_string(&body).unwrap(),
            case["wire"].as_str().unwrap(),
            "{operation}/{mode}"
        );
        if operation == "registration" {
            let request: super::types::VerifyRegistrationRequest = json::from_value(body).unwrap();
            request
                .validate()
                .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"));
        } else {
            let request: super::types::UpdatePasskeyRequest = json::from_value(body)
                .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"));
            request.validate().unwrap();
        }
    }
    assert_eq!(matched, expected_cases);
}

#[test]
fn canonical_registration_input_matches_actual_source_schema() {
    assert_source_inputs("registration", 25);
}

#[test]
fn canonical_update_input_matches_actual_source_schema() {
    assert_source_inputs("update", 11);
}

#[test]
fn canonical_public_rename_output_keeps_utf16() {
    let value = json::parse_value(r#"{"passkey":{"name":"\ud800"}}"#).unwrap();
    let output: super::endpoint::PasskeyUpdated = json::from_value(value.clone()).unwrap();
    assert_eq!(
        json::to_js_value(&output.passkey).unwrap(),
        value["passkey"]
    );
}

#[tokio::test]
async fn canonical_passkey_optional_fields_keep_memory_undefined() {
    let fixture = json::parse_value(include_str!(
        "../../../core/src/store/passkey_field_presence_cases.json"
    ))
    .unwrap();
    let source = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["mode"] == "absent" && case["backend"] == "memory")
        .unwrap();
    let store = alibi_core::store::stateless::StatelessStore::default();
    use alibi_core::store::PasskeyStore;
    let row = store
        .create_passkey(alibi_core::CreatePasskey {
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
        .await
        .unwrap();
    let output = json::to_js_value(&alibi_core::wire::PasskeyView::from(&row)).unwrap();
    for field in source["undefined"].as_array().unwrap() {
        assert_eq!(
            output.get(field.as_str().unwrap()),
            Some(&JsValue::Undefined),
            "{}",
            field.as_str().unwrap()
        );
    }
}

#[tokio::test]
async fn canonical_passkey_names_survive_memory_rename_and_list() {
    use super::handlers::{PasskeyHandlerOutcome, list_user_passkeys_core, update_passkey_core};
    let fixture = json::parse_value(include_str!(
        "../../../core/src/store/passkey_name_cases.json"
    ))
    .unwrap();
    let ctx = alibi_core::AuthContext::<alibi_core::store::stateless::StatelessSchema>::new(
        std::sync::Arc::new(crate::test_helpers::create_test_config()),
        std::sync::Arc::new(alibi_core::store::stateless::StatelessStore::default()),
    );
    let user = ctx
        .database
        .create_user(alibi_core::CreateUser::new().with_email("passkey-names@test"))
        .await
        .unwrap();
    let mut count = 0;
    for case in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["backend"] == "memory")
    {
        count += 1;
        let created = ctx
            .database
            .create_passkey(alibi_core::CreatePasskey {
                user_id: user.id.clone(),
                name: case["registration"].clone(),
                credential_id: case["mode"].as_str().unwrap().into(),
                public_key: "public".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: JsValue::Undefined,
                created_at: JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap()),
                aaguid: JsValue::Undefined,
            })
            .await
            .unwrap();
        assert_eq!(
            json::to_js_value(&alibi_core::wire::PasskeyView::from(&created)).unwrap()["name"],
            case["create"]
        );
        let request: super::types::UpdatePasskeyRequest = json::from_value(JsValue::Object(
            [
                ("id".into(), JsValue::String(created.id.clone().into())),
                ("name".into(), case["update_input"].clone()),
            ]
            .into(),
        ))
        .unwrap();
        let PasskeyHandlerOutcome::Success(renamed) =
            update_passkey_core(&request, &user, &ctx).await.unwrap()
        else {
            panic!("rename rejected")
        };
        assert_eq!(
            json::to_js_value(&renamed).unwrap()["passkey"]["name"],
            case["rename"]
        );
        let listed = list_user_passkeys_core(&user, &ctx).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .find(|row| row["id"] == created.id.as_str())
                .unwrap()["name"],
            case["list"]
        );
        let wire = json::to_string(&listed).unwrap();
        let expected_wire = JsValue::Array(
            listed
                .into_iter()
                .map(|mut row| {
                    let fields = row.as_object_mut().unwrap();
                    assert_eq!(fields.shift_remove("transports"), Some(JsValue::Undefined));
                    assert_eq!(fields.shift_remove("aaguid"), Some(JsValue::Undefined));
                    assert_eq!(
                        fields["createdAt"],
                        JsValue::Date(chrono::DateTime::from_timestamp_millis(0).unwrap())
                    );
                    _ = fields.insert(
                        "createdAt".into(),
                        JsValue::String("1970-01-01T00:00:00.000Z".into()),
                    );
                    row
                })
                .collect(),
        );
        assert_eq!(json::parse_value(&wire).unwrap(), expected_wire);
        let stored = ctx
            .database
            .get_passkey_by_id(&created.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.name, case["list"]);
    }
    assert_eq!(count, 6);
}
