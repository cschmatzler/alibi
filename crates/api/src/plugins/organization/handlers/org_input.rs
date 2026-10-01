//! Pinned organization request schemas, validated before authentication.
use better_auth_core::utils::json::JsValue;
use better_auth_core::{AuthError, AuthRequest, AuthResponse};
use serde_json::{Value, json};

use crate::plugins::organization::types::{
    CreateOrganizationRequest, DeleteOrganizationRequest, NullableStringField,
    SetActiveOrganizationRequest, UpdateOrganizationData, UpdateOrganizationRequest,
};

fn response(status: u16, code: &str, message: impl Into<String>) -> AuthResponse {
    AuthResponse::json(status, &json!({"code":code,"message":message.into()}))
        .unwrap_or_else(|_| AuthResponse::text(status, "Invalid request body"))
}

fn kind(value: Option<&JsValue>) -> &'static str {
    match value {
        None => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Bool(_)) => "boolean",
        Some(JsValue::Number(value)) if value.is_nan() => "NaN",
        Some(JsValue::Number(value)) if *value == f64::INFINITY => "Infinity",
        Some(JsValue::Number(value)) if *value == f64::NEG_INFINITY => "-Infinity",
        Some(JsValue::Number(_)) => "number",
        Some(JsValue::String(_)) => "string",
        Some(JsValue::Array(_)) => "array",
        Some(JsValue::Object(_)) => "object",
    }
}

fn expected(path: &str, expected: &str, value: Option<&JsValue>) -> String {
    format!(
        "[{path}] Invalid input: expected {expected}, received {}",
        kind(value)
    )
}

fn decode(req: &AuthRequest) -> Result<Option<JsValue>, AuthResponse> {
    let Some(bytes) = req.body.as_deref() else {
        return Ok(None);
    };
    let original = req
        .header("content-type")
        .map(String::as_str)
        .unwrap_or_default();
    let normalized = original.to_ascii_lowercase();
    let media = normalized.split(';').next().unwrap_or_default().trim();
    // Better Call checks the allowlist before decoding, including its containing
    // media-type match. Keep the original header in the rejection message.
    if !media.contains("application/json") {
        let message = if normalized.is_empty() {
            "Content-Type is required. Allowed types: application/json".to_owned()
        } else {
            format!("Content-Type \"{original}\" is not allowed. Allowed types: application/json")
        };
        return Err(response(415, "UNSUPPORTED_MEDIA_TYPE", message));
    }
    let json_media = normalized
        .strip_prefix("application/")
        .is_some_and(|subtype| {
            subtype.starts_with("json")
                || subtype.find("+json").is_some_and(|index| {
                    subtype.get(..index).is_some_and(|prefix| {
                        prefix
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
                    })
                })
        });
    if !json_media {
        // An allowed but non-JSON media type reaches Better Call's ReadableStream
        // fallback. Zod sees an object with no declared own fields.
        return Ok(Some(JsValue::Object(Default::default())));
    }
    better_auth_core::utils::json::from_slice::<JsValue>(bytes)
        .map(Some)
        .map_err(|_| response(400, "BAD_REQUEST", "Invalid JSON in request body"))
}

fn object(value: Option<&JsValue>, path: &str) -> Result<(), String> {
    if value.is_some_and(JsValue::is_object) {
        Ok(())
    } else {
        Err(expected(path, "object", value))
    }
}

fn string(
    value: Option<&JsValue>,
    path: &str,
    required: bool,
    min_one: bool,
    nullish: bool,
    issues: &mut Vec<String>,
) -> Option<String> {
    match value {
        None if !required => None,
        Some(JsValue::Null) if nullish => None,
        Some(JsValue::String(value)) => {
            if min_one && value.is_empty() {
                issues.push(format!(
                    "[{path}] Too small: expected string to have >=1 characters"
                ));
            }
            Some(value.clone())
        }
        value => {
            issues.push(expected(path, "string", value));
            None
        }
    }
}

fn record(value: Option<&JsValue>, path: &str, issues: &mut Vec<String>) -> Option<Value> {
    match value {
        None => None,
        Some(value) if value.is_object() => match value.to_json_value() {
            Ok(value) => Some(value),
            Err(_) => {
                issues.push(format!("[{path}] Invalid JSON value"));
                None
            }
        },
        value => {
            issues.push(expected(path, "record", value));
            None
        }
    }
}

fn validate(issues: Vec<String>) -> Result<(), AuthResponse> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(response(400, "VALIDATION_ERROR", issues.join("; ")))
    }
}

pub(super) fn create(req: &AuthRequest) -> Result<CreateOrganizationRequest, AuthResponse> {
    let decoded = decode(req)?;
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let input = decoded.as_ref();
    let get = |key| input.and_then(|value| value.get(key));
    let mut issues = Vec::new();
    let name = string(get("name"), "body.name", true, true, false, &mut issues);
    let slug = string(get("slug"), "body.slug", true, true, false, &mut issues);
    // userId is coercible for every JSON value and never selects an HTTP principal.
    let logo = string(get("logo"), "body.logo", false, false, true, &mut issues);
    let metadata = record(get("metadata"), "body.metadata", &mut issues);
    let keep = get("keepCurrentActiveOrganization").and_then(|value| {
        let parsed = value.as_bool();
        if parsed.is_none() {
            issues.push(expected(
                "body.keepCurrentActiveOrganization",
                "boolean",
                Some(value),
            ));
        }
        parsed
    });
    validate(issues)?;
    Ok(CreateOrganizationRequest {
        name: name.unwrap_or_default(),
        slug: slug.unwrap_or_default(),
        logo,
        metadata,
        keep_current_active_organization: keep,
    })
}

pub(super) fn update(
    req: &AuthRequest,
) -> Result<
    (
        UpdateOrganizationRequest,
        Option<indexmap::IndexMap<String, JsValue>>,
    ),
    AuthResponse,
> {
    let decoded = decode(req)?;
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let input = decoded.as_ref();
    let get = |key| input.and_then(|value| value.get(key));
    let mut issues = Vec::new();
    let data = get("data");
    let data_valid = match object(data, "body.data") {
        Ok(()) => true,
        Err(message) => {
            issues.push(message);
            false
        }
    };
    let mut fields = UpdateOrganizationData {
        name: None,
        slug: None,
        logo: None,
        metadata: None,
    };
    if data_valid {
        let get = |key| data.and_then(|value| value.get(key));
        fields.name = string(
            get("name"),
            "body.data.name",
            false,
            true,
            false,
            &mut issues,
        );
        fields.slug = string(
            get("slug"),
            "body.data.slug",
            false,
            true,
            false,
            &mut issues,
        );
        let logo = get("logo");
        let parsed_logo = string(logo, "body.data.logo", false, false, true, &mut issues);
        fields.logo = logo.map(|_| parsed_logo);
        fields.metadata = record(get("metadata"), "body.data.metadata", &mut issues);
    }
    let organization_id = string(
        get("organizationId"),
        "body.organizationId",
        false,
        false,
        false,
        &mut issues,
    );
    validate(issues)?;
    let raw_metadata = data
        .and_then(|data| data.get("metadata"))
        .and_then(JsValue::as_object)
        .cloned();
    Ok((
        UpdateOrganizationRequest {
            organization_id,
            data: fields,
        },
        raw_metadata,
    ))
}

pub(super) fn delete(req: &AuthRequest) -> Result<DeleteOrganizationRequest, AuthResponse> {
    let decoded = decode(req)?;
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let value = decoded
        .as_ref()
        .and_then(|value| value.get("organizationId"));
    let mut issues = Vec::new();
    let id = string(
        value,
        "body.organizationId",
        true,
        false,
        false,
        &mut issues,
    );
    validate(issues)?;
    Ok(DeleteOrganizationRequest {
        organization_id: id.unwrap_or_default(),
    })
}

pub(super) fn set_active(req: &AuthRequest) -> Result<SetActiveOrganizationRequest, AuthResponse> {
    let decoded = decode(req)?;
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let get = |key| decoded.as_ref().and_then(|value| value.get(key));
    let mut issues = Vec::new();
    let id = get("organizationId");
    let parsed_id = string(id, "body.organizationId", false, false, true, &mut issues);
    let organization_id = match id {
        None => NullableStringField::Missing,
        Some(JsValue::Null) => NullableStringField::Null,
        _ => parsed_id.map_or(NullableStringField::Missing, NullableStringField::Value),
    };
    let organization_slug = string(
        get("organizationSlug"),
        "body.organizationSlug",
        false,
        false,
        false,
        &mut issues,
    );
    validate(issues)?;
    Ok(SetActiveOrganizationRequest {
        organization_id,
        organization_slug,
    })
}

pub(in crate::plugins::organization) fn validate_trusted_create(
    body: &CreateOrganizationRequest,
) -> Result<(), AuthError> {
    let mut issues = Vec::new();
    for (name, value) in [("name", &body.name), ("slug", &body.slug)] {
        if value.is_empty() {
            issues.push(format!(
                "[body.{name}] Too small: expected string to have >=1 characters"
            ));
        }
    }
    if let Some(metadata) = &body.metadata {
        let value = JsValue::from(metadata.clone());
        if !value.is_object() {
            issues.push(expected("body.metadata", "record", Some(&value)));
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AuthError::Api {
            status: 400,
            code: Some("VALIDATION_ERROR".into()),
            message: issues.join("; "),
        })
    }
}
