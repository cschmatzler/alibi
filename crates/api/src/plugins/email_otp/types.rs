use crate::plugins::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use serde::{Deserialize, Serialize};

/// Code scope. Codes issued for one operation cannot authorize another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailOtpType {
    #[serde(rename = "email-verification")]
    EmailVerification,
    #[serde(rename = "sign-in")]
    SignIn,
    #[serde(rename = "forget-password")]
    ForgetPassword,
    #[serde(rename = "change-email")]
    ChangeEmail,
}

impl EmailOtpType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email-verification",
            Self::SignIn => "sign-in",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
}

/// Delivery data. Debug intentionally omits the authentication secret.
#[derive(Clone)]
pub struct EmailOtpDelivery {
    pub email: String,
    pub otp: String,
    pub otp_type: EmailOtpType,
}

impl std::fmt::Debug for EmailOtpDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpDelivery")
            .field("otp_type", &self.otp_type)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpResendStrategy {
    Rotate,
    Reuse,
}

#[derive(Deserialize)]
pub(super) struct SendRequest {
    pub email: String,
    #[serde(rename = "type")]
    pub otp_type: EmailOtpType,
}

#[derive(Deserialize)]
pub(super) struct CheckRequest {
    pub email: String,
    #[serde(rename = "type")]
    pub otp_type: EmailOtpType,
    pub otp: String,
}

#[derive(Deserialize)]
pub(super) struct VerifyRequest {
    pub email: String,
    pub otp: String,
}

#[derive(Deserialize)]
pub(super) struct SignInRequest {
    pub email: String,
    pub otp: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EmailRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub(super) struct PasswordRequest {
    pub email: String,
    pub otp: String,
    pub password: String,
}

#[derive(Deserialize)]
pub(super) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    pub new_email: String,
    pub otp: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ConfirmChangeRequest {
    #[serde(rename = "newEmail")]
    pub new_email: String,
    pub otp: String,
}

macro_rules! request_fields {
    ($name:ty, $($field:expr),+ $(,)?) => {
        impl RequestBody for $name { const FIELDS: &'static [JsonField] = &[$($field),+]; }
    };
}

request_fields!(
    SendRequest,
    JsonField::string("email", true),
    JsonField {
        name: "type",
        kind: JsonFieldKind::OneOf(&[
            "email-verification",
            "sign-in",
            "forget-password",
            "change-email"
        ]),
        required: true
    }
);
request_fields!(
    CheckRequest,
    JsonField::string("email", true),
    JsonField {
        name: "type",
        kind: JsonFieldKind::OneOf(&[
            "email-verification",
            "sign-in",
            "forget-password",
            "change-email"
        ]),
        required: true
    },
    JsonField::string("otp", true)
);
request_fields!(
    VerifyRequest,
    JsonField::string("email", true),
    JsonField::string("otp", true)
);
request_fields!(
    SignInRequest,
    JsonField::string("email", true),
    JsonField::string("otp", true),
    JsonField::string("name", false),
    JsonField::string("image", false)
);
request_fields!(EmailRequest, JsonField::string("email", true));
request_fields!(
    PasswordRequest,
    JsonField::string("email", true),
    JsonField::string("otp", true),
    JsonField::string("password", true)
);
request_fields!(
    ChangeEmailRequest,
    JsonField::string("newEmail", true),
    JsonField::string("otp", false)
);
request_fields!(
    ConfirmChangeRequest,
    JsonField::string("newEmail", true),
    JsonField::string("otp", true)
);

pub(super) fn identifier(otp_type: EmailOtpType, email: &str) -> String {
    format!("{}-otp-{email}", otp_type.as_str())
}

pub(super) fn split_value(value: &str) -> (&str, usize) {
    match value.rsplit_once(':') {
        Some((code, attempts)) => (code, attempts.parse().unwrap_or(0)),
        None => (value, 0),
    }
}
