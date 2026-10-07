pub(in crate::plugins) use alibi_core::wire::PasskeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct VerifyRegistrationRequest {
    #[serde(default, deserialize_with = "optional_name")]
    pub(super) response: Option<alibi_core::utils::json::JsValue>,
    #[serde(default, deserialize_with = "optional_name")]
    pub(super) name: Option<alibi_core::utils::json::JsValue>,
    #[serde(default = "no_registration_session")]
    pub(super) create_session: alibi_core::utils::json::JsValue,
}

impl Validate for VerifyRegistrationRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        if self.response.is_none() {
            let mut errors = validator::ValidationErrors::new();
            errors.add(
                "response",
                validator::ValidationError::new("nonoptional")
                    .with_message("Invalid input: expected nonoptional, received undefined".into()),
            );
            return Err(errors);
        }
        if let Some(name) = &self.name
            && !name.is_string()
        {
            let mut errors = validator::ValidationErrors::new();
            errors.add(
                "name",
                validator::ValidationError::new("string").with_message(
                    format!(
                        "Invalid input: expected string, received {}",
                        received_type(name)
                    )
                    .into(),
                ),
            );
            return Err(errors);
        }
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct VerifyAuthenticationRequest {
    #[serde(default, deserialize_with = "optional_name")]
    pub(super) response: Option<alibi_core::utils::json::JsValue>,
}
impl Validate for VerifyAuthenticationRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self.response.as_ref() {
            Some(value) if value.is_object() => Ok(()),
            value => {
                let received = value.map_or("undefined", received_type);
                let mut errors = validator::ValidationErrors::new();
                errors.add(
                    "response",
                    validator::ValidationError::new("record").with_message(
                        format!("Invalid input: expected record, received {received}").into(),
                    ),
                );
                Err(errors)
            }
        }
    }
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
    #[validate(custom(function = "validate_trimmed_name"))]
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

const fn no_registration_session() -> alibi_core::utils::json::JsValue {
    alibi_core::utils::json::JsValue::Bool(false)
}

fn optional_name<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<alibi_core::utils::json::JsValue>, D::Error> {
    alibi_core::utils::json::JsValue::deserialize(decoder).map(Some)
}
fn received_type(value: &alibi_core::utils::json::JsValue) -> &'static str {
    use alibi_core::utils::json::JsValue;
    match value {
        JsValue::Null => "null",
        JsValue::Array(_) => "array",
        JsValue::Object(_) => "object",
        JsValue::Bool(_) => "boolean",
        JsValue::Number(_) => "number",
        JsValue::String(_) => "string",
    }
}

fn validate_trimmed_name(value: &str) -> Result<(), validator::ValidationError> {
    if super::registration::trim_name(value).is_empty() {
        return Err(validator::ValidationError::new("length")
            .with_message("Too small: expected string to have >=1 characters".into()));
    }
    Ok(())
}
