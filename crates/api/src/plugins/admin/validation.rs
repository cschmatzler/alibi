//! Route-local HTTP schemas from the pinned admin endpoints.
use better_auth_core::{AuthRequest, AuthResponse, utils::json::JsValue};
use serde::de::DeserializeOwned;
use serde_json::json;

fn response(status: u16, code: &str, message: impl Into<String>) -> AuthResponse {
    AuthResponse::json(status, &json!({"code":code,"message":message.into()}))
        .unwrap_or_else(|_| AuthResponse::text(status, "Validation failed"))
}
fn kind(value: Option<&JsValue>) -> &'static str {
    match value {
        None => "undefined",
        Some(JsValue::Null) => "null",
        Some(JsValue::Bool(_)) => "boolean",
        Some(JsValue::Number(_)) => "number",
        Some(JsValue::String(_)) => "string",
        Some(JsValue::Array(_)) => "array",
        Some(JsValue::Object(_)) => "object",
    }
}
fn expected(field: &str, expected: &str, value: Option<&JsValue>) -> String {
    format!(
        "[{field}] Invalid input: expected {expected}, received {}",
        kind(value)
    )
}
fn schema_error(issues: Vec<String>) -> AuthResponse {
    response(400, "VALIDATION_ERROR", issues.join("; "))
}
fn json_media_type(value: &str) -> bool {
    let Some(subtype) = value.strip_prefix("application/") else {
        return false;
    };
    subtype.starts_with("json")
        || subtype.find("+json").is_some_and(|index| {
            subtype[..index]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
        })
}

/// Media and JSON parsing also apply to the schema-less stop-impersonating route.
pub(super) fn parse(req: &AuthRequest) -> Result<Option<JsValue>, AuthResponse> {
    let Some(bytes) = req.body.as_deref() else {
        // Bun materializes an incoming empty chunked JSON stream as null.
        let chunked = req.headers.get("transfer-encoding").is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        });
        let json = req
            .headers
            .get("content-type")
            .is_some_and(|value| json_media_type(&value.to_ascii_lowercase()));
        return Ok((chunked && json).then_some(JsValue::Null));
    };
    let content_type = req
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or_default();
    let normalized = content_type.to_ascii_lowercase();
    if !normalized
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .contains("application/json")
    {
        let message = if normalized.is_empty() {
            "Content-Type is required. Allowed types: application/json".to_string()
        } else {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
            )
        };
        return Err(response(415, "UNSUPPORTED_MEDIA_TYPE", message));
    }
    if !json_media_type(&normalized) {
        // Better-call returns a ReadableStream for its accepted non-JSON media
        // spellings; object schemas see no declared fields on that stream.
        return Ok(Some(JsValue::Object(Default::default())));
    }
    better_auth_core::utils::json::from_slice(bytes)
        .map(Some)
        .map_err(|_| response(400, "BAD_REQUEST", "Invalid JSON in request body"))
}

#[derive(Clone, Copy)]
enum Rule {
    String,
    OptionalString,
    Id,
    NonemptyId,
    NonemptyPassword,
    Role,
    OptionalRole,
    Record,
    OptionalRecord,
    OptionalNumber,
}

fn fields(route: &str) -> &'static [(&'static str, Rule)] {
    use Rule::*;
    match route {
        "set-role" => &[("userId", Id), ("role", Role)],
        "create-user" => &[
            ("email", String),
            ("password", OptionalString),
            ("name", String),
            ("role", OptionalRole),
            ("data", OptionalRecord),
        ],
        "update-user" => &[("userId", Id), ("data", Record)],
        "ban-user" => &[
            ("userId", Id),
            ("banReason", OptionalString),
            ("banExpiresIn", OptionalNumber),
        ],
        "revoke-user-session" => &[("sessionToken", String)],
        "set-user-password" => &[("newPassword", NonemptyPassword), ("userId", NonemptyId)],
        "has-permission" => &[("userId", Id), ("role", OptionalString)],
        _ => &[("userId", Id)],
    }
}

fn coerce_string(value: &JsValue) -> Option<String> {
    Some(match value {
        JsValue::Null => "null".into(),
        JsValue::Bool(value) => value.to_string(),
        JsValue::Number(value) => ryu_js::Buffer::new().format(*value).to_string(),
        JsValue::String(value) => value.clone(),
        // JSON cannot supply callable methods. An own toString shadows the
        // inherited conversion and makes z.coerce.string fail its type check.
        JsValue::Object(value) => {
            if value.contains_key("toString") {
                return None;
            } else {
                "[object Object]".into()
            }
        }
        JsValue::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    Some(String::new())
                } else {
                    coerce_string(value)
                }
            })
            .collect::<Option<Vec<_>>>()?
            .join(","),
    })
}
fn valid_role(value: &JsValue) -> bool {
    value.is_string()
        || value
            .as_array()
            .is_some_and(|roles| roles.iter().all(JsValue::is_string))
}
fn valid_permissions(value: Option<&JsValue>) -> bool {
    value
        .and_then(JsValue::as_object)
        .is_some_and(|permissions| {
            permissions.values().all(|actions| {
                actions
                    .as_array()
                    .is_some_and(|actions| actions.iter().all(JsValue::is_string))
            })
        })
}

pub(super) fn body<T: DeserializeOwned + 'static>(req: &AuthRequest) -> Result<T, AuthResponse> {
    let value = parse(req)?;
    let route = req.path.rsplit('/').next().unwrap_or_default();
    let Some(JsValue::Object(mut input)) = value else {
        let mut issues = vec![expected("body", "object", value.as_ref())];
        if route == "has-permission" {
            issues.push("[body] Invalid input".into());
        }
        return Err(schema_error(issues));
    };
    let mut issues = Vec::new();
    for &(field, rule) in fields(route) {
        let value = input.get(field);
        if value.is_none()
            && (matches!(
                rule,
                Rule::OptionalString
                    | Rule::OptionalRole
                    | Rule::OptionalRecord
                    | Rule::OptionalNumber
            ) || (route == "has-permission" && field == "userId"))
        {
            continue;
        }
        let path = format!("body.{field}");
        match rule {
            Rule::Id | Rule::NonemptyId => {
                if let Some(value) = value {
                    if let Some(value) = coerce_string(value) {
                        if matches!(rule, Rule::NonemptyId) && value.is_empty() {
                            issues.push(format!("[{path}] userId cannot be empty"));
                        }
                        let _ = input.insert(field.into(), JsValue::String(value));
                    } else {
                        issues.push(expected(&path, "string", Some(value)));
                    }
                } else {
                    issues.push(expected(&path, "nonoptional", None));
                }
            }
            Rule::String | Rule::OptionalString | Rule::NonemptyPassword => {
                if let Some(value) = value.and_then(JsValue::as_str) {
                    if matches!(rule, Rule::NonemptyPassword) && value.is_empty() {
                        issues.push(format!("[{path}] newPassword cannot be empty"));
                    }
                } else {
                    issues.push(expected(&path, "string", value));
                }
            }
            Rule::Role | Rule::OptionalRole => {
                if !value.is_some_and(valid_role) {
                    issues.push(format!("[{path}] Invalid input"));
                }
            }
            Rule::Record | Rule::OptionalRecord => {
                if !value.is_some_and(JsValue::is_object) {
                    issues.push(expected(&path, "record", value));
                }
            }
            Rule::OptionalNumber => {
                if !value.and_then(JsValue::as_f64).is_some_and(f64::is_finite) {
                    issues.push(expected(&path, "number", value));
                }
            }
        }
    }
    if route == "has-permission" {
        let singular = valid_permissions(input.get("permission"));
        let plural = valid_permissions(input.get("permissions"));
        match (singular, plural) {
            (true, true) => {
                issues.push("[body] Invalid input: more than one option matched".into())
            }
            (false, false) => issues.push("[body] Invalid input".into()),
            (true, false) => {
                let _ = input.shift_remove("permissions");
            }
            (false, true) => {
                let _ = input.shift_remove("permission");
            }
        }
    }
    if !issues.is_empty() {
        return Err(schema_error(issues));
    }
    better_auth_core::utils::json::from_value(JsValue::Object(input))
        .map_err(|_| response(400, "VALIDATION_ERROR", "[body] Invalid input"))
}

pub(super) fn get_user(req: &AuthRequest) -> Result<super::types::GetUserQuery, AuthResponse> {
    let _ = parse(req)?;
    req.query
        .get("id")
        .map(|id| super::types::GetUserQuery { id: id.clone() })
        .ok_or_else(|| schema_error(vec![expected("query.id", "string", None)]))
}
pub(super) fn list_users(req: &AuthRequest) -> Result<(), AuthResponse> {
    let _ = parse(req)?;
    let mut issues = Vec::new();
    for (field, options) in [
        ("searchField", &["email", "name"][..]),
        (
            "searchOperator",
            &["contains", "starts_with", "ends_with"][..],
        ),
        ("sortDirection", &["asc", "desc"][..]),
        (
            "filterOperator",
            &[
                "eq",
                "ne",
                "lt",
                "lte",
                "gt",
                "gte",
                "in",
                "not_in",
                "contains",
                "starts_with",
                "ends_with",
            ][..],
        ),
    ] {
        if let Some(value) = req.query.get(field)
            && !options.contains(&value.as_str())
        {
            issues.push(format!(
                "[query.{field}] Invalid option: expected one of {}",
                options
                    .iter()
                    .map(|value| format!("\"{value}\""))
                    .collect::<Vec<_>>()
                    .join("|")
            ));
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(schema_error(issues))
    }
}

/// Equivalent to zod's pinned ASCII email grammar, applied after role authority.
pub(super) fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let Some(last) = local.as_bytes().last() else {
        return false;
    };
    if !(last.is_ascii_alphanumeric() || b"_+-".contains(last))
        || local.starts_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_'+-.".contains(&byte))
    {
        return false;
    }
    let mut labels = domain.rsplit('.');
    let Some(tld) = labels.next() else {
        return false;
    };
    if tld.len() < 2 || !tld.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    let mut count = 0;
    for label in labels {
        count += 1;
        if !label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    count > 0
}
