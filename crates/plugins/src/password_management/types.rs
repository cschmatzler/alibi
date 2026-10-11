use serde::{Deserialize, Serialize};
use validator::Validate;

/// Input for `requestPasswordReset` and `POST /request-password-reset`.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[serde(
        default,
        rename = "redirectTo",
        skip_serializing_if = "Option::is_none"
    )]
    pub redirect_to: Option<String>,
}

/// Input for the public `resetPassword` operation and `POST /reset-password`.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    pub new_password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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

/// Input for the trusted, pathless `setPassword` server operation.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct SetPasswordRequest {
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

impl crate::authentication_helpers::RequestBody for SetPasswordRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] =
        &[crate::authentication_helpers::JsonField::string(
            "newPassword",
            true,
        )];
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
pub struct RequestPasswordResetResponse {
    pub status: bool,
    pub message: String,
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

impl crate::authentication_helpers::RequestBody for RequestPasswordResetRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField {
            name: "email",
            kind: crate::authentication_helpers::JsonFieldKind::Email,
            required: true,
        },
        crate::authentication_helpers::JsonField::string("redirectTo", false),
    ];
}

/// Required logical query for `requestPasswordResetCallback`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResetPasswordCallbackQuery {
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
}
impl crate::authentication_helpers::RequestBody for ResetPasswordCallbackQuery {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] =
        &[crate::authentication_helpers::JsonField::string(
            "callbackURL",
            true,
        )];
}
