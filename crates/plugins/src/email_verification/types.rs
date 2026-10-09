use crate::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct SendVerificationEmailRequest {
    pub(crate) email: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

impl RequestBody for SendVerificationEmailRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField {
            name: "email",
            kind: JsonFieldKind::Email,
            required: true,
        },
        JsonField::string("callbackURL", false),
    ];
}

/// Query parameters for `GET /verify-email`.
#[derive(Debug, Deserialize)]
pub(crate) struct VerifyEmailQuery {
    pub(crate) token: String,
    #[serde(rename = "callbackURL")]
    pub(crate) callback_url: Option<String>,
}

/// Result of the verify-email core function.
pub(crate) enum VerifyEmailResult {
    Redirect {
        url: String,
        session_token: Option<String>,
    },
    Json {
        body: serde_json::Value,
        session_token: Option<String>,
    },
}
