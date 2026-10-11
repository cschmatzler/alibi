use serde::{Deserialize, Serialize};
use validator::Validate;

/// Body of the public `changeEmail` server operation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ChangeEmailRequest {
    #[serde(rename = "newEmail")]
    #[validate(email(message = "Invalid email address"))]
    pub new_email: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

impl crate::authentication_helpers::RequestBody for ChangeEmailRequest {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField {
            name: "newEmail",
            kind: crate::authentication_helpers::JsonFieldKind::Email,
            required: true,
        },
        crate::authentication_helpers::JsonField::string("callbackURL", false),
    ];
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

/// Query of the public `deleteUserCallback` server operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserCallbackQuery {
    pub token: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

impl crate::authentication_helpers::RequestBody for DeleteUserCallbackQuery {
    const FIELDS: &'static [crate::authentication_helpers::JsonField] = &[
        crate::authentication_helpers::JsonField::string("token", true),
        crate::authentication_helpers::JsonField::string("callbackURL", false),
    ];
}
