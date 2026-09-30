use better_auth_core::{AuthRequest, AuthResponse};
use serde_json::{Map, Value, json};

use crate::plugins::authentication_helpers::is_valid_email;

#[derive(Debug)]
pub(super) struct VerifyBody {
    pub message: String,
    pub signature: String,
    pub email: Option<String>,
}

fn error(message: String) -> AuthResponse {
    AuthResponse::json(400, &json!({"message":message,"code":"VALIDATION_ERROR"}))
        .unwrap_or_else(|_| AuthResponse::text(400, "Invalid request body"))
}

fn received(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::String(_)) => "string",
        Some(Value::Number(_)) => "number",
    }
}

fn body(request: &AuthRequest, optional: bool) -> Result<Map<String, Value>, AuthResponse> {
    let parsed = request
        .body
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|_| {
            AuthResponse::json(
                400,
                &json!({"message":"Invalid JSON in request body","code":"BAD_REQUEST"}),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Invalid JSON in request body"))
        })?;
    match parsed {
        None if optional => Ok(Map::new()),
        Some(Value::Object(body)) => Ok(body),
        value => Err(error(format!(
            "[body] Invalid input: expected object, received {}",
            received(value.as_ref())
        ))),
    }
}

fn unknown_keys(body: &Map<String, Value>, known: &[&str]) -> Option<String> {
    let mut keys: Vec<&str> = body
        .keys()
        .map(String::as_str)
        .filter(|key| !known.contains(key))
        .collect();
    // JavaScript enumerates canonical numeric indexes first. The stable sort
    // retains insertion order for ordinary property names.
    keys.sort_by_key(|key| {
        key.parse::<u32>()
            .ok()
            .filter(|index| *index != u32::MAX && index.to_string() == *key)
            .map_or((1, 0), |index| (0, index))
    });
    if keys.is_empty() {
        return None;
    }
    let formatted = keys
        .iter()
        .map(|key| format!("\"{key}\""))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "[body] Unrecognized key{}: {formatted}",
        if keys.len() == 1 { "" } else { "s" }
    ))
}

pub(super) fn nonce_body(request: &AuthRequest) -> Result<(), AuthResponse> {
    let body = body(request, true)?;
    if let Some(message) = unknown_keys(&body, &[]) {
        return Err(error(message));
    }
    Ok(())
}

pub(super) fn verify_body(
    request: &AuthRequest,
    anonymous: bool,
) -> Result<VerifyBody, AuthResponse> {
    let body = body(request, false)?;
    let mut errors = Vec::new();
    let mut aborted = false;
    for field in ["message", "signature"] {
        match body.get(field) {
            Some(Value::String(value)) if value.is_empty() => errors.push(format!(
                "[body.{field}] Too small: expected string to have >=1 characters"
            )),
            Some(Value::String(_)) => {}
            value => {
                aborted = true;
                errors.push(format!(
                    "[body.{field}] Invalid input: expected string, received {}",
                    received(value)
                ));
            }
        }
    }
    match body.get("email") {
        None => {}
        Some(Value::String(email)) if !is_valid_email(email) => {
            errors.push("[body.email] Invalid email address".to_owned())
        }
        Some(Value::String(_)) => {}
        value => {
            aborted = true;
            errors.push(format!(
                "[body.email] Invalid input: expected string, received {}",
                received(value)
            ));
        }
    }
    if let Some(unknown) = unknown_keys(&body, &["message", "signature", "email"]) {
        errors.push(unknown);
        aborted = true;
    }
    if !anonymous
        && !aborted
        && body
            .get("email")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        errors.push(
            "[body.email] Email is required when the anonymous plugin option is disabled."
                .to_owned(),
        );
    }
    if !errors.is_empty() {
        return Err(error(errors.join("; ")));
    }
    Ok(VerifyBody {
        message: body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        signature: body
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        email: body.get("email").and_then(Value::as_str).map(str::to_owned),
    })
}
