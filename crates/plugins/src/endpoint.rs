//! Shared validation for genuine logical calls, independent of HTTP decoding.
use super::authentication_helpers::{JsonField, field_issue, json_type};
use alibi_core::endpoint::{EndpointDefinition, EndpointResponse};
use alibi_core::error::codes;
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
        code: Some(codes::VALIDATION_ERROR.into()),
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
        let issue = field_issue(field.kind, value, json_type(value));
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
            .filter(|(name, _)| fields.iter().any(|field| Some(field.name) == name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    ))
}

/// Convert a plugin handler's HTTP response into an endpoint response, keeping
/// its status and headers. Errors keep the generated error payload.
pub(super) fn from_auth_response(output: AuthResponse) -> AuthResult<EndpointResponse> {
    convert_auth_response(output, false)
}

/// Like [`from_auth_response`], for handlers whose errors must not carry the
/// generated error payload.
pub(super) fn from_auth_response_without_error_body(
    output: AuthResponse,
) -> AuthResult<EndpointResponse> {
    convert_auth_response(output, true)
}

fn convert_auth_response(
    output: AuthResponse,
    without_error_body: bool,
) -> AuthResult<EndpointResponse> {
    let body: JsValue = alibi_core::utils::json::from_slice(&output.body)?;
    let mut response = if output.status >= 400 {
        let response = EndpointResponse::error(error_response(output.clone()));
        if without_error_body {
            response.without_error_body()
        } else {
            response
        }
    } else {
        EndpointResponse::value(body)
    };
    response.set_status(Some(output.status));
    response.merge_headers(output.headers);
    Ok(response)
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
