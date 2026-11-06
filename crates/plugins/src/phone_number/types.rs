use crate::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use alibi_core::error::codes;
use alibi_core::{AuthError, wire::UserView};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct PhoneOtpDelivery {
    pub phone_number: String,
    pub code: String,
}

impl std::fmt::Debug for PhoneOtpDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneOtpDelivery").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct PhoneNumberVerification {
    pub phone_number: String,
    pub user: UserView,
}

impl std::fmt::Debug for PhoneNumberVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneNumberVerification")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub(super) struct SendRequest {
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
}

/// Credential input for the public phone sign-in operation.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignInRequest {
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    pub password: String,
    #[serde(rename = "rememberMe", skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct VerifyRequest {
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    pub code: String,
    #[serde(rename = "disableSession")]
    pub disable_session: Option<bool>,
    #[serde(rename = "updatePhoneNumber")]
    pub update_phone_number: Option<bool>,
    pub username: Option<alibi_core::utils::json::JsValue>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<alibi_core::utils::json::JsValue>,
    pub image: Option<String>,
    #[serde(rename = "phoneNumberVerified")]
    pub phone_number_verified: Option<alibi_core::utils::json::JsValue>,
}

/// Proof and replacement credential for the public phone password-reset operation.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResetRequest {
    pub otp: String,
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

impl RequestBody for SendRequest {
    const FIELDS: &'static [JsonField] = &[JsonField::string("phoneNumber", true)];
}

impl RequestBody for SignInRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("phoneNumber", true),
        JsonField::string("password", true),
        JsonField {
            name: "rememberMe",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ];
}

impl RequestBody for VerifyRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("phoneNumber", true),
        JsonField::string("code", true),
        JsonField {
            name: "disableSession",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
        JsonField {
            name: "updatePhoneNumber",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ];
}

impl RequestBody for ResetRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("otp", true),
        JsonField::string("phoneNumber", true),
        JsonField::string("newPassword", true),
    ];
}

pub(super) const fn phone_error(
    status: u16,
    code: &'static str,
    message: &'static str,
) -> AuthError {
    AuthError::Upstream {
        status,
        code,
        message,
    }
}

// Pinned parseUserInput applies the registered schema to signup's additional
// fields. The verified field is input:false, whose guard uses JS truthiness.
pub(crate) fn reject_verified_input(
    input: Option<&alibi_core::utils::json::JsValue>,
) -> Result<(), AuthError> {
    use alibi_core::utils::json::JsValue as Value;
    let truthy = match input {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => *value != 0.0 && !value.is_nan(),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Date(_) | Value::Array(_) | Value::Object(_)) => true,
    };
    if truthy {
        return Err(phone_error(
            400,
            codes::FIELD_NOT_ALLOWED,
            "phoneNumberVerified is not allowed to be set",
        ));
    }
    Ok(())
}

pub(crate) async fn parse_signup_phone(
    _ctx: &alibi_core::AuthContext<impl alibi_core::AuthSchema>,
    input: Option<&alibi_core::utils::json::JsValue>,
) -> Result<Option<String>, AuthError> {
    use alibi_core::utils::json::JsValue as Value;
    if input.is_some_and(|value| match value {
        Value::Null | Value::Bool(false) => false,
        Value::String(value) => !value.is_empty(),
        Value::Number(value) => *value != 0.0 && !value.is_nan(),
        Value::Bool(true) | Value::Date(_) | Value::Array(_) | Value::Object(_) => true,
    }) {
        return Err(phone_error(
            400,
            codes::PHONE_NUMBER_CANNOT_BE_SET,
            "Phone number can only be set by verifying it",
        ));
    }
    Ok(input
        .filter(|value| !value.is_null())
        .map(|_| String::new()))
}
