use serde::{Deserialize, Deserializer, Serialize};
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
    #[validate(length(min = 1, message = "New password is required"))]
    pub(in crate::plugins) new_password: String,
    pub(in crate::plugins) token: Option<String>,
}

/// Request body for `POST /change-password`.
#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    #[validate(length(min = 1, message = "New password is required"))]
    pub(in crate::plugins) new_password: String,
    #[serde(rename = "currentPassword")]
    #[validate(length(min = 1, message = "Current password is required"))]
    pub(in crate::plugins) current_password: String,
    #[serde(
        default,
        rename = "revokeOtherSessions",
        deserialize_with = "deserialize_bool_or_string"
    )]
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

/// Deserialize a value that can be either a boolean or a string ("true"/"false") into Option<bool>.
/// This is needed because the better-auth TypeScript SDK sends `revokeOtherSessions` as a boolean,
/// while some clients may send it as a string.
fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = alibi_core::utils::json::deserialize_optional_value(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(b)),
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom(format!(
                "invalid value for revokeOtherSessions: {s}"
            ))),
        },
        Some(other) => Err(serde::de::Error::custom(format!(
            "invalid type for revokeOtherSessions: {other}"
        ))),
    }
}
