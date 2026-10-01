pub(in crate::plugins) use better_auth_core::wire::PasskeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct VerifyRegistrationRequest {
    pub(super) response: better_auth_core::utils::json::JsValue,
    pub(super) name: Option<String>,
    #[serde(default = "no_registration_session")]
    pub(super) create_session: better_auth_core::utils::json::JsValue,
}

impl Validate for VerifyRegistrationRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        if self.create_session.is_boolean() {
            return Ok(());
        }
        let received = if self.create_session.is_null() {
            "null"
        } else if self.create_session.is_array() {
            "array"
        } else if self.create_session.is_object() {
            "object"
        } else if self.create_session.is_string() {
            "string"
        } else {
            "number"
        };
        let mut errors = validator::ValidationErrors::new();
        errors.add(
            "createSession",
            validator::ValidationError::new("boolean").with_message(
                format!("Invalid input: expected boolean, received {received}").into(),
            ),
        );
        Err(errors)
    }
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct VerifyAuthenticationRequest {
    #[validate(custom(function = "validate_authentication_response"))]
    pub(super) response: better_auth_core::utils::json::JsValue,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct DeletePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct UpdatePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
    #[validate(length(min = 1))]
    pub(super) name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct SessionResponse<S, U> {
    pub(in crate::plugins) session: S,
    pub(in crate::plugins) user: U,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct PasskeyResponse {
    pub(super) passkey: PasskeyView,
}

const fn no_registration_session() -> better_auth_core::utils::json::JsValue {
    better_auth_core::utils::json::JsValue::Bool(false)
}

fn validate_authentication_response(
    value: &better_auth_core::utils::json::JsValue,
) -> Result<(), validator::ValidationError> {
    use better_auth_core::utils::json::JsValue;
    let received = match value {
        JsValue::Object(_) => return Ok(()),
        JsValue::Array(_) => "array",
        JsValue::Null => "null",
        JsValue::Bool(_) => "boolean",
        JsValue::Number(_) => "number",
        JsValue::String(_) => "string",
    };
    Err(validator::ValidationError::new("record")
        .with_message(format!("Invalid input: expected record, received {received}").into()))
}
