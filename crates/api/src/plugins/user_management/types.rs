use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    pub(in crate::plugins) new_email: String,
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct DeleteUserRequest {
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
    pub(in crate::plugins) password: Option<String>,
    pub(in crate::plugins) token: Option<String>,
}

/// Query parameters for token-based verification endpoints.
#[derive(Debug, Deserialize)]
pub(in crate::plugins) struct TokenQuery {
    pub(in crate::plugins) token: String,
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
}
