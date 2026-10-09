//! Shared validation for genuine logical calls, independent of HTTP decoding.
use super::authentication_helpers::{JsonField, JsonFieldKind, is_valid_email, json_type};
use alibi_core::endpoint::EndpointDefinition;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthError, AuthResponse, AuthResult, HttpMethod};

pub(super) fn definition(
    name: &'static str,
    operation_id: &'static str,
    path: Option<&str>,
    method: HttpMethod,
) -> EndpointDefinition {
    EndpointDefinition {
        name,
        operation_id,
        path: path.map(str::to_owned),
        method,
    }
}

pub(super) fn validation(message: impl Into<String>) -> AuthError {
    AuthError::Api {
        status: 400,
        code: Some("VALIDATION_ERROR".into()),
        message: message.into(),
    }
}

pub(super) fn validate_fields(
    value: Option<&JsValue>,
    location: &str,
    fields: &[JsonField],
) -> AuthResult<JsValue> {
    let Some(object) = value.and_then(JsValue::as_object) else {
        return Err(validation(format!(
            "[{location}] Invalid input: expected object, received {}",
            json_type(value)
        )));
    };
    let mut issues = Vec::new();
    for field in fields {
        let value = object.get(field.name);
        if value.is_none() && !field.required {
            continue;
        }
        let expected = match field.kind {
            JsonFieldKind::String | JsonFieldKind::NonEmptyString | JsonFieldKind::Email => {
                "string"
            }
            JsonFieldKind::Boolean => "boolean",
            JsonFieldKind::Record => "record",
            JsonFieldKind::OneOf(_) => "enum",
        };
        let valid_type = match field.kind {
            JsonFieldKind::String | JsonFieldKind::NonEmptyString | JsonFieldKind::Email => {
                value.is_some_and(JsValue::is_string)
            }
            JsonFieldKind::Boolean => value.is_some_and(JsValue::is_boolean),
            JsonFieldKind::Record => value.is_some_and(JsValue::is_object),
            JsonFieldKind::OneOf(choices) => value
                .and_then(JsValue::as_str)
                .is_some_and(|value| choices.contains(&value)),
        };
        let issue = if let JsonFieldKind::OneOf(choices) = field.kind {
            (!valid_type).then(|| {
                format!(
                    "Invalid option: expected one of {}",
                    choices
                        .iter()
                        .map(|choice| format!("\"{choice}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
        } else if !valid_type {
            Some(format!(
                "Invalid input: expected {expected}, received {}",
                json_type(value)
            ))
        } else {
            match field.kind {
                JsonFieldKind::NonEmptyString
                    if value.and_then(JsValue::as_str).is_some_and(str::is_empty) =>
                {
                    Some("Too small: expected string to have >=1 characters".into())
                }
                JsonFieldKind::Email
                    if !value.and_then(JsValue::as_str).is_some_and(is_valid_email) =>
                {
                    Some("Invalid email address".into())
                }
                _ => None,
            }
        };
        if let Some(issue) = issue {
            issues.push(format!("[{location}.{}] {issue}", field.name));
        }
    }
    if !issues.is_empty() {
        return Err(validation(issues.join("; ")));
    }
    Ok(JsValue::Object(
        object
            .iter()
            .filter(|(name, _)| fields.iter().any(|field| field.name == name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    ))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used by value as a `map_err` callback"
)]
pub(super) fn error_response(response: AuthResponse) -> AuthError {
    let body = alibi_core::utils::json::from_slice::<JsValue>(&response.body).ok();
    AuthError::Api {
        status: response.status,
        code: body
            .as_ref()
            .and_then(|body| body.get("code"))
            .and_then(JsValue::as_str)
            .map(str::to_owned),
        message: body
            .as_ref()
            .and_then(|body| body.get("message"))
            .and_then(JsValue::as_str)
            .unwrap_or("Invalid endpoint input")
            .to_owned(),
    }
}
