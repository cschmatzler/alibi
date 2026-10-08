use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request body for `POST /request-password-reset`.
#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct RequestPasswordResetRequest {
    #[validate(email(message = "Invalid email address"))]
    pub(in crate::plugins) email: String,
    #[serde(rename = "redirectTo")]
    pub(in crate::plugins) redirect_to: Option<String>,
}

/// Request body for `POST /reset-password`.
#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    pub(in crate::plugins) new_password: String,
    pub(in crate::plugins) token: Option<String>,
}

/// Request body for `POST /change-password`.
#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    pub(in crate::plugins) new_password: String,
    #[serde(rename = "currentPassword")]
    pub(in crate::plugins) current_password: String,
    #[serde(default, rename = "revokeOtherSessions")]
    pub(in crate::plugins) revoke_other_sessions: Option<bool>,
}

/// Request body for `POST /verify-password`.
#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct VerifyPasswordRequest {
    pub(in crate::plugins) password: String,
}

/// Query parameters for `GET /reset-password/{token}`.
#[derive(Debug, Deserialize)]
pub(in crate::plugins) struct ResetPasswordTokenQuery {
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
}

/// Response body for `POST /request-password-reset`.
#[derive(Debug, Serialize, Deserialize)]
pub(in crate::plugins) struct RequestPasswordResetResponse {
    pub(in crate::plugins) status: bool,
    pub(in crate::plugins) message: String,
}

/// Response body for `POST /change-password`.
#[derive(Debug, Serialize)]
pub(in crate::plugins) struct ChangePasswordResponse<U> {
    pub(in crate::plugins) token: Option<String>,
    pub(in crate::plugins) user: U,
}

/// Result of the reset-password-token core function.
pub(in crate::plugins) enum ResetPasswordTokenResult {
    Redirect(String),
}

impl crate::plugins::authentication_helpers::RequestBody for ResetPasswordRequest {
    const FIELDS: &'static [crate::plugins::authentication_helpers::JsonField] = &[
        crate::plugins::authentication_helpers::JsonField::string("newPassword", true),
        crate::plugins::authentication_helpers::JsonField::string("token", false),
    ];
}
impl crate::plugins::authentication_helpers::RequestBody for ChangePasswordRequest {
    const FIELDS: &'static [crate::plugins::authentication_helpers::JsonField] = &[
        crate::plugins::authentication_helpers::JsonField::string("newPassword", true),
        crate::plugins::authentication_helpers::JsonField::string("currentPassword", true),
        crate::plugins::authentication_helpers::JsonField {
            name: "revokeOtherSessions",
            kind: crate::plugins::authentication_helpers::JsonFieldKind::Boolean,
            required: false,
        },
    ];
}
