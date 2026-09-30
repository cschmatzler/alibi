//! Shared schemas for the core email-verification HTTP boundary.

use better_auth_core::{AuthRequest, AuthResponse};
use serde::de::DeserializeOwned;
use serde_json::Value;

// This is the exact practical-email grammar used by the pinned Zod runtime.
// The HTML5/validator grammar accepts addresses such as `x@y.c` and local
// punctuation which Better Auth rejects, so those validators are unsuitable.
pub(crate) fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.split('.').any(str::is_empty) {
        return false;
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_'+-.".contains(&b))
        || !local
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b"_+-".contains(b))
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() > 1
        && labels
            .last()
            .is_some_and(|last| last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic()))
        && labels.iter().all(|label| {
            label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Clone, Copy)]
pub(crate) enum JsonFieldKind {
    String,
    Email,
}

pub(crate) struct JsonField {
    pub name: &'static str,
    pub kind: JsonFieldKind,
    pub required: bool,
}

impl JsonField {
    pub(crate) const fn string(name: &'static str, required: bool) -> Self {
        Self {
            name,
            kind: JsonFieldKind::String,
            required,
        }
    }
}

pub(crate) trait RequestBody: DeserializeOwned {
    const FIELDS: &'static [JsonField];
}

/// Parse the upstream schema at the HTTP boundary. The error includes all
/// failed fields in declaration order, including explicitly null optionals.
pub(crate) fn parse_body<T: RequestBody>(req: &AuthRequest) -> Result<T, AuthResponse> {
    let value: Value = req
        .body_as_json()
        .map_err(|_| validation_response("[body] Invalid JSON"))?;
    let Some(object) = value.as_object() else {
        return Err(validation_response(&format!(
            "[body] Invalid input: expected object, received {}",
            json_type(Some(&value))
        )));
    };
    let mut issues = Vec::new();
    for field in T::FIELDS {
        let value = object.get(field.name);
        if value.is_none() && !field.required {
            continue;
        }
        let issue = match field.kind {
            JsonFieldKind::String | JsonFieldKind::Email
                if !value.is_some_and(Value::is_string) =>
            {
                Some(format!(
                    "Invalid input: expected string, received {}",
                    json_type(value)
                ))
            }
            JsonFieldKind::Email if !value.and_then(Value::as_str).is_some_and(is_valid_email) => {
                Some("Invalid email address".to_string())
            }
            _ => None,
        };
        if let Some(issue) = issue {
            issues.push(format!("[body.{}] {issue}", field.name));
        }
    }
    if !issues.is_empty() {
        return Err(validation_response(&issues.join("; ")));
    }
    serde_json::from_value(value).map_err(|_| validation_response("[body] Invalid input"))
}

fn json_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

pub(crate) fn validation_response(message: &str) -> AuthResponse {
    AuthResponse::json(
        400,
        &serde_json::json!({"code":"VALIDATION_ERROR","message":message}),
    )
    .unwrap_or_else(|_| AuthResponse::text(400, "Validation failed"))
}
