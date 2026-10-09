use alibi_core::types::{MultipartFiles, ParsedRequestBody};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthError, AuthRequest, AuthResponse, AuthResult};
use serde::de::DeserializeOwned;

#[derive(Clone, Copy)]
pub(crate) enum JsonFieldKind {
    String,
    NonEmptyString,
    Email,
    Boolean,
    Record,
    OneOf(&'static [&'static str]),
}

pub(crate) struct JsonField {
    pub name: &'static str,
    pub kind: JsonFieldKind,
    pub required: bool,
}

impl JsonField {
    #[must_use]
    pub(crate) const fn string(name: &'static str, required: bool) -> Self {
        Self {
            name,
            kind: JsonFieldKind::String,
            required,
        }
    }
}

pub(crate) trait RequestBody: DeserializeOwned + 'static {
    const FIELDS: &'static [JsonField];
}

pub(crate) fn parse_email(email: &str) -> AuthResult<String> {
    let normalized = email.to_lowercase();
    if !is_valid_email(&normalized) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        });
    }
    Ok(normalized)
}

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

/// Parse the upstream schema at the HTTP boundary. The error includes all
/// failed fields in declaration order, including explicitly null optionals.
pub(crate) fn parse_body<T: RequestBody>(req: &AuthRequest) -> Result<T, AuthResponse> {
    parse_body_with_fields(req, T::FIELDS)
}

/// Parse schemas whose required fields depend on trusted plugin configuration.
pub(crate) fn parse_body_with_fields<T: DeserializeOwned + 'static>(
    req: &AuthRequest,
    fields: &[JsonField],
) -> Result<T, AuthResponse> {
    parse_body_with_fields_and_ignored(req, fields, &[])
}

/// Remove configured unknown fields before schema validation without serializing
/// the remaining JavaScript numbers (which may include infinity or signed zero).
pub(crate) fn parse_body_with_ignored_fields<T: RequestBody>(
    req: &AuthRequest,
    ignored: &[&str],
) -> Result<T, AuthResponse> {
    parse_body_with_fields_and_ignored(req, T::FIELDS, ignored)
}

pub(in crate::authentication_helpers) fn parse_body_with_fields_and_ignored<
    T: DeserializeOwned + 'static,
>(
    req: &AuthRequest,
    fields: &[JsonField],
    ignored: &[&str],
) -> Result<T, AuthResponse> {
    // Source object schemas inspect fields on decoded streams/buffers too.
    // Those transport objects have no schema fields; retain their raw bytes,
    // but validate missing properties instead of reparsing them as JSON.
    let opaque = req
        .extensions()
        .get::<ParsedRequestBody>()
        .is_some_and(|body| matches!(&*body, ParsedRequestBody::Opaque(_)));
    let mut value: JsValue = if opaque {
        JsValue::Object(indexmap::IndexMap::default())
    } else {
        req.body_as_json().map_err(|_error| {
            AuthResponse::json(
                400,
                &serde_json::json!({"code":"BAD_REQUEST","message":"Invalid JSON in request body"}),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Invalid JSON in request body"))
        })?
    };
    if let JsValue::Object(object) = &mut value {
        for field in ignored {
            _ = object.shift_remove(*field);
        }
    }
    let Some(object) = value.as_object() else {
        return Err(validation_response(&format!(
            "[body] Invalid input: expected object, received {}",
            json_type(Some(&value))
        )));
    };
    let mut issues = Vec::new();
    for field in fields {
        let field_value = object.get(field.name);
        if field_value.is_none() && !field.required {
            continue;
        }
        let received_type = if req
            .extensions()
            .get::<MultipartFiles>()
            .is_some_and(|files| files.0.contains_key(field.name))
        {
            "Blob"
        } else {
            json_type(field_value)
        };
        let issue = match field.kind {
            JsonFieldKind::String | JsonFieldKind::NonEmptyString | JsonFieldKind::Email
                if !field_value.is_some_and(JsValue::is_string) =>
            {
                Some(format!(
                    "Invalid input: expected string, received {received_type}"
                ))
            }
            JsonFieldKind::NonEmptyString
                if field_value
                    .and_then(JsValue::as_str)
                    .is_some_and(str::is_empty) =>
            {
                Some("Too small: expected string to have >=1 characters".to_owned())
            }
            JsonFieldKind::Boolean if !field_value.is_some_and(JsValue::is_boolean) => Some(
                format!("Invalid input: expected boolean, received {received_type}"),
            ),
            JsonFieldKind::Email
                if !field_value
                    .and_then(JsValue::as_str)
                    .is_some_and(is_valid_email) =>
            {
                Some("Invalid email address".to_owned())
            }
            JsonFieldKind::OneOf(choices)
                if !field_value
                    .and_then(JsValue::as_str)
                    .is_some_and(|value| choices.contains(&value)) =>
            {
                Some(format!(
                    "Invalid option: expected one of {}",
                    choices
                        .iter()
                        .map(|choice| format!("\"{choice}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                ))
            }
            JsonFieldKind::Record if !field_value.is_some_and(JsValue::is_object) => Some(format!(
                "Invalid input: expected record, received {received_type}"
            )),
            _ => None,
        };
        if let Some(issue) = issue {
            issues.push(format!("[body.{}] {issue}", field.name));
        }
    }
    if !issues.is_empty() {
        return Err(validation_response(&issues.join("; ")));
    }
    alibi_core::utils::json::from_value(value)
        .map_err(|_error| validation_response("[body] Invalid input"))
}

pub(crate) const fn json_type(value: Option<&JsValue>) -> &'static str {
    match value {
        None => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Bool(_)) => "boolean",
        Some(JsValue::Number(number)) if number.is_infinite() && number.is_sign_negative() => {
            "-Infinity"
        }
        Some(JsValue::Number(number)) if number.is_infinite() => "Infinity",
        Some(JsValue::Number(_)) => "number",
        Some(JsValue::String(_)) => "string",
        Some(JsValue::Array(_)) => "array",
        Some(JsValue::Object(_)) => "object",
    }
}

pub(crate) fn validation_response(message: &str) -> AuthResponse {
    AuthResponse::json(
        400,
        &serde_json::json!({"code":"VALIDATION_ERROR","message":message}),
    )
    .unwrap_or_else(|_| AuthResponse::text(400, "Validation failed"))
}
