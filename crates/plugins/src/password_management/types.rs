use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request body for `POST /request-password-reset`.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(crate) email: String,
    #[serde(rename = "redirectTo")]
    pub(crate) redirect_to: Option<String>,
}

/// Request body for `POST /reset-password`.
#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    pub(crate) new_password: String,
    pub(crate) token: Option<String>,
}

/// Request body for `POST /change-password`.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    pub new_password: String,
    #[serde(rename = "currentPassword")]
    pub current_password: String,
    #[serde(
        default,
        rename = "revokeOtherSessions",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoke_other_sessions: Option<bool>,
}

/// Request body for `POST /verify-password`.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

/// Result of successful current-owner password verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyPasswordResponse {
    pub status: bool,
}

impl crate::authentication_helpers::RequestBody for VerifyPasswordRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] =
        &[crate::authentication_helpers::JsonField::string(
            "password", true,
        )];
}

/// Query parameters for `GET /reset-password/{token}`.
#[derive(Debug, Deserialize)]
pub(crate) struct ResetPasswordTokenQuery {
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Response body for `POST /request-password-reset`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RequestPasswordResetResponse {
    pub(crate) status: bool,
    pub(crate) message: String,
}

/// Response body for `POST /change-password`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordResponse<U> {
    pub token: Option<String>,
    pub user: U,
}

impl crate::authentication_helpers::RequestBody for ResetPasswordRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField::string("newPassword", true),
        crate::authentication_helpers::JsonField::string("token", false),
    ];
}
impl crate::authentication_helpers::RequestBody for ChangePasswordRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField::string("newPassword", true),
        crate::authentication_helpers::JsonField::string("currentPassword", true),
        crate::authentication_helpers::JsonField {
            name: "revokeOtherSessions",
            kind: crate::authentication_helpers::JsonFieldKind::Boolean,
            required: false,
        },
    ];
}
