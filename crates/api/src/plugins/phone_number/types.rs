use crate::plugins::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};

use better_auth_core::{AuthError, wire::UserView};

use serde::Deserialize;

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

#[derive(Deserialize)]
pub(super) struct SignInRequest {
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    pub password: String,
    #[serde(rename = "rememberMe")]
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
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    pub image: Option<String>,
    #[serde(rename = "phoneNumberVerified")]
    pub phone_number_verified: Option<better_auth_core::utils::json::JsValue>,
}

#[derive(Deserialize)]
pub(super) struct ResetRequest {
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
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn reject_verified_input(
    input: Option<&better_auth_core::utils::json::JsValue>,
) -> Result<(), AuthError> {
    use better_auth_core::utils::json::JsValue as Value;
    let truthy = match input {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => *value != 0.0 && !value.is_nan(),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    };
    if truthy {
        return Err(phone_error(
            400,
            "FIELD_NOT_ALLOWED",
            "phoneNumberVerified is not allowed to be set",
        ));
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn parse_signup_phone(
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
    input: Option<&better_auth_core::utils::json::JsValue>,
) -> Result<Option<String>, AuthError> {
    use better_auth_core::utils::json::JsValue as Value;
    match input {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        // The pinned SQLite adapter coerces these scalar inputs to its TEXT
        // column. Arrays and objects fail user insertion, leaving no rows.
        Some(Value::Bool(value)) => Ok(Some(if *value { "1" } else { "0" }.into())),
        Some(Value::Number(value)) => {
            use better_auth_core::store::NumericTextInput;
            // A valid JSON number can overflow the JavaScript f64 range.
            // Preserve its number type through validation, then apply the same
            // rounding/overflow before the adapter chooses INTEGER or REAL.
            let number = *value;
            // Bun's SQLite binding uses JavaScriptCore isAnyInt(), whose
            // signed Int52 range excludes negative zero. Other values bind REAL.
            let input_2 = if (-2_251_799_813_685_248.0..2_251_799_813_685_248.0).contains(&number)
                && number.fract() == 0.0
                && !(number == 0.0 && number.is_sign_negative())
            {
                NumericTextInput::Integer(number as i64)
            } else {
                NumericTextInput::Real(number)
            };
            Ok(Some(ctx.database.coerce_user_text_number(input_2).await?))
        }
        Some(Value::Array(_) | Value::Object(_)) => Err(phone_error(
            422,
            "FAILED_TO_CREATE_USER",
            "Failed to create user",
        )),
    }
}
