use crate::plugins::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(in crate::plugins) struct SendVerificationEmailRequest {
    pub(in crate::plugins) email: String,
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
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
pub(in crate::plugins) struct VerifyEmailQuery {
    pub(in crate::plugins) token: String,
    #[serde(rename = "callbackURL")]
    pub(in crate::plugins) callback_url: Option<String>,
}

/// Result of the verify-email core function.
pub(in crate::plugins) enum VerifyEmailResult {
    Redirect {
        url: String,
        session_token: Option<String>,
    },
    Json {
        body: serde_json::Value,
        session_token: Option<String>,
    },
}
