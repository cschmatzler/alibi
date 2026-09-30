pub(crate) use better_auth_core::wire::PasskeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyRegistrationRequest {
    pub(super) response: better_auth_core::utils::json::JsValue,
    pub(super) name: Option<String>,
    #[serde(default = "no_registration_session")]
    pub(super) create_session: better_auth_core::utils::json::JsValue,
}

fn no_registration_session() -> better_auth_core::utils::json::JsValue {
    better_auth_core::utils::json::JsValue::Bool(false)
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
pub(crate) struct VerifyAuthenticationRequest {
    #[serde(deserialize_with = "better_auth_core::utils::json::deserialize_value")]
    #[validate(custom(function = "validate_authentication_response"))]
    pub(super) response: serde_json::Value,
}

fn validate_authentication_response(
    value: &serde_json::Value,
) -> Result<(), validator::ValidationError> {
    let received = match value {
        serde_json::Value::Object(_) => return Ok(()),
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
    };
    Err(validator::ValidationError::new("record")
        .with_message(format!("Invalid input: expected record, received {received}").into()))
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdatePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
    #[validate(length(min = 1))]
    pub(super) name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
pub(crate) struct SessionResponse<S: Serialize, U: Serialize> {
    pub(crate) session: S,
    pub(crate) user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct PasskeyResponse {
    pub(super) passkey: PasskeyView,
}
