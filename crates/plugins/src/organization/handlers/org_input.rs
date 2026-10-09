//! Pinned organization request schemas, validated before authentication.
use crate::organization::types::{
    CreateOrganizationRequest, DeleteOrganizationRequest, NullableStringField, RemoveMemberRequest,
    RoleInput, SetActiveOrganizationRequest, UpdateMemberRoleRequest, UpdateOrganizationData,
    UpdateOrganizationRequest,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthError, AuthRequest, AuthResponse};
use serde_json::{Value, json};

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
        return Ok(Some(JsValue::Object(indexmap::IndexMap::default())));
    }
    alibi_core::utils::json::from_slice::<JsValue>(bytes)
        .map(Some)
        .map_err(|_error| response(400, "BAD_REQUEST", "Invalid JSON in request body"))
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
        Some(value) if value.is_object() => value.to_json_value().map_or_else(
            |_| {
                issues.push(format!("[{path}] Invalid JSON value"));
                None
            },
            Some,
        ),
        value => {
            issues.push(expected(path, "record", value));
            None
        }
    }
}

fn validate(issues: &[String]) -> Result<(), AuthResponse> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(response(400, "VALIDATION_ERROR", issues.join("; ")))
    }
}

pub(super) fn create(req: &AuthRequest) -> Result<CreateOrganizationRequest, AuthResponse> {
    create_value(decode(req)?)
}

pub(in crate::organization) fn create_value(
    decoded: Option<JsValue>,
) -> Result<CreateOrganizationRequest, AuthResponse> {
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let input = decoded.as_ref();
    let get = |key| {
        let value = input?;
        value.get(key)
    };
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
    validate(&(issues))?;
    Ok(CreateOrganizationRequest {
        additional_fields: input
            .and_then(JsValue::as_object)
            .cloned()
            .unwrap_or_default(),
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
    update_value(decode(req)?)
}

pub(in crate::organization) fn update_value(
    decoded: Option<JsValue>,
) -> Result<
    (
        UpdateOrganizationRequest,
        Option<indexmap::IndexMap<String, JsValue>>,
    ),
    AuthResponse,
> {
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let input = decoded.as_ref();
    let get = |key| {
        let value = input?;
        value.get(key)
    };
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
        additional_fields: data
            .and_then(JsValue::as_object)
            .cloned()
            .unwrap_or_default(),
        name: None,
        slug: None,
        logo: None,
        metadata: None,
    };
    if data_valid {
        let get_2 = |key| {
            let value = data?;
            value.get(key)
        };
        fields.name = string(
            get_2("name"),
            "body.data.name",
            false,
            true,
            false,
            &mut issues,
        );
        fields.slug = string(
            get_2("slug"),
            "body.data.slug",
            false,
            true,
            false,
            &mut issues,
        );
        let logo = get_2("logo");
        let parsed_logo = string(logo, "body.data.logo", false, false, true, &mut issues);
        fields.logo = logo.map(|_| parsed_logo);
        fields.metadata = record(get_2("metadata"), "body.data.metadata", &mut issues);
    }
    let organization_id = string(
        get("organizationId"),
        "body.organizationId",
        false,
        false,
        false,
        &mut issues,
    );
    validate(&(issues))?;
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
    validate(&(issues))?;
    Ok(DeleteOrganizationRequest {
        organization_id: id.unwrap_or_default(),
    })
}

pub(super) fn set_active(req: &AuthRequest) -> Result<SetActiveOrganizationRequest, AuthResponse> {
    set_active_value(decode(req)?)
}

pub(in crate::organization) fn set_active_value(
    decoded: Option<JsValue>,
) -> Result<SetActiveOrganizationRequest, AuthResponse> {
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let get = |key| {
        let value = decoded.as_ref()?;
        value.get(key)
    };
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
    validate(&(issues))?;
    Ok(SetActiveOrganizationRequest {
        organization_id,
        organization_slug,
    })
}

pub(in crate::organization) fn validate_trusted_create(
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

pub(super) fn member_role_update(
    req: &AuthRequest,
) -> Result<UpdateMemberRoleRequest, AuthResponse> {
    member_role_update_value(decode(req)?)
}

pub(in crate::organization) fn member_role_update_value(
    decoded: Option<JsValue>,
) -> Result<UpdateMemberRoleRequest, AuthResponse> {
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let get = |key| {
        let value = decoded.as_ref()?;
        value.get(key)
    };
    let role = match get("role") {
        Some(JsValue::String(value)) => Some(RoleInput::One(value.clone())),
        Some(JsValue::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(RoleInput::Many),
        _ => None,
    };
    let mut issues = Vec::new();
    if role.is_none() {
        issues.push("[body.role] Invalid input".to_owned());
    }
    let member_id = string(
        get("memberId"),
        "body.memberId",
        true,
        false,
        false,
        &mut issues,
    );
    let organization_id = string(
        get("organizationId"),
        "body.organizationId",
        false,
        false,
        false,
        &mut issues,
    );
    validate(&(issues))?;
    Ok(UpdateMemberRoleRequest {
        role: role.ok_or_else(|| response(400, "VALIDATION_ERROR", "[body.role] Invalid input"))?,
        member_id: member_id.ok_or_else(|| {
            response(
                400,
                "VALIDATION_ERROR",
                expected("body.memberId", "string", get("memberId")),
            )
        })?,
        organization_id,
    })
}

pub(super) fn member_remove(req: &AuthRequest) -> Result<RemoveMemberRequest, AuthResponse> {
    let decoded = decode(req)?;
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let get = |key| {
        let value = decoded.as_ref()?;
        value.get(key)
    };
    let mut issues = Vec::new();
    let member_id_or_email = string(
        get("memberIdOrEmail"),
        "body.memberIdOrEmail",
        true,
        false,
        false,
        &mut issues,
    );
    let organization_id = string(
        get("organizationId"),
        "body.organizationId",
        false,
        false,
        false,
        &mut issues,
    );
    validate(&(issues))?;
    Ok(RemoveMemberRequest {
        member_id_or_email: member_id_or_email.ok_or_else(|| {
            response(
                400,
                "VALIDATION_ERROR",
                expected("body.memberIdOrEmail", "string", get("memberIdOrEmail")),
            )
        })?,
        organization_id,
    })
}

/// The invitation schema accepts email strings; the endpoint validates the
/// address only after authentication, before organization authority and hooks.
pub(super) fn invitation_create(
    req: &AuthRequest,
) -> Result<super::super::types::InviteMemberRequest, AuthResponse> {
    invitation_create_value(decode(req)?)
}

pub(in crate::organization) fn invitation_create_value(
    decoded: Option<JsValue>,
) -> Result<super::super::types::InviteMemberRequest, AuthResponse> {
    use super::super::types::{InviteMemberRequest, TeamInput};
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let get = |key| decoded.as_ref().and_then(|value| value.get(key));
    let mut issues = Vec::new();
    let email = string(get("email"), "body.email", true, false, false, &mut issues);
    let role = match get("role") {
        Some(JsValue::String(value)) => Some(RoleInput::One(value.clone())),
        Some(JsValue::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .map(RoleInput::Many),
        _ => None,
    };
    if role.is_none() {
        issues.push("[body.role] Invalid input".into());
    }
    let organization_id = string(
        get("organizationId"),
        "body.organizationId",
        false,
        false,
        false,
        &mut issues,
    );
    let resend = match get("resend") {
        None => None,
        Some(JsValue::Bool(value)) => Some(*value),
        value => {
            issues.push(expected("body.resend", "boolean", value));
            None
        }
    };
    let team_id = match get("teamId") {
        None => None,
        Some(JsValue::String(value)) => Some(TeamInput::One(value.clone())),
        Some(JsValue::Array(values)) => {
            let ids = values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>();
            if ids.is_none() {
                issues.push("[body.teamId] Invalid input".into());
            }
            ids.map(TeamInput::Many)
        }
        _ => {
            issues.push("[body.teamId] Invalid input".into());
            None
        }
    };
    validate(&issues)?;
    Ok(InviteMemberRequest {
        email: email.unwrap_or_default(),
        role: role.unwrap_or_else(|| RoleInput::Many(Vec::new())),
        organization_id,
        resend,
        team_id,
    })
}

pub(super) fn invitation_id(req: &AuthRequest) -> Result<String, AuthResponse> {
    invitation_id_value(decode(req)?)
}

pub(in crate::organization) fn invitation_id_value(
    decoded: Option<JsValue>,
) -> Result<String, AuthResponse> {
    object(decoded.as_ref(), "body")
        .map_err(|message| response(400, "VALIDATION_ERROR", message))?;
    let mut issues = Vec::new();
    let id = string(
        decoded.as_ref().and_then(|value| value.get("invitationId")),
        "body.invitationId",
        true,
        false,
        false,
        &mut issues,
    );
    validate(&issues)?;
    Ok(id.unwrap_or_default())
}
