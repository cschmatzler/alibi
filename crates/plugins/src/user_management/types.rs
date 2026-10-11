use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    pub(crate) new_email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Body of the public `deleteUser` server operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub struct DeleteUserRequest {
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl crate::authentication_helpers::RequestBody for DeleteUserRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField::string("callbackURL", false),
        crate::authentication_helpers::JsonField::string("password", false),
        crate::authentication_helpers::JsonField::string("token", false),
    ];
}

/// Query parameters for token-based verification endpoints.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}
