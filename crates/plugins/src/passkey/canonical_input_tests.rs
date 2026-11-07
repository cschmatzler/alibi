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
