//! Route-local HTTP schemas from the pinned admin endpoints.
use alibi_core::{AuthRequest, AuthResponse, utils::json::JsValue};
use serde::de::DeserializeOwned;
use serde_json::json;

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

fn response(status: u16, code: &str, message: impl Into<String>) -> AuthResponse {
    AuthResponse::json(status, &json!({"code":code,"message":message.into()}))
        .unwrap_or_else(|_| AuthResponse::text(status, "Validation failed"))
}

const fn kind(value: Option<&JsValue>) -> &'static str {
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

fn schema_error(issues: &[String]) -> AuthResponse {
    response(400, "VALIDATION_ERROR", issues.join("; "))
}

fn json_media_type(value: &str) -> bool {
    let Some(subtype) = value.strip_prefix("application/") else {
        return false;
    };
    subtype.starts_with("json")
        || subtype.find("+json").is_some_and(|index| {
            subtype
                .get(..index)
                .unwrap_or_default()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
        })
}

/// Media and JSON parsing also apply to the schema-less stop-impersonating route.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
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
            "Content-Type is required. Allowed types: application/json".to_owned()
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
        return Ok(Some(JsValue::Object(indexmap::IndexMap::default())));
    }
    alibi_core::utils::json::from_slice(bytes)
        .map(Some)
        .map_err(|_error| response(400, "BAD_REQUEST", "Invalid JSON in request body"))
}

fn fields(route: &str) -> &'static [(&'static str, Rule)] {
    use Rule::{
        Id, NonemptyId, NonemptyPassword, OptionalNumber, OptionalRecord, OptionalRole,
        OptionalString, Record, Role, String,
    };
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
        JsValue::Number(value) => ryu_js::Buffer::new().format(*value).to_owned(),
        JsValue::String(value) => value.clone(),
        // JSON cannot supply callable methods. An own toString shadows the
        // inherited conversion and makes z.coerce.string fail its type check.
        JsValue::Object(value) => {
            if value.contains_key("toString") {
                return None;
            }
            "[object Object]".into()
        }
        JsValue::Array(values) => values
            .iter()
            .map(|value_2| {
                if value_2.is_null() {
                    Some(String::new())
                } else {
                    coerce_string(value_2)
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

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn body<T: DeserializeOwned + 'static>(req: &AuthRequest) -> Result<T, AuthResponse> {
    let value = parse(req)?;
    let route = req.path.rsplit('/').next().unwrap_or_default();
    let Some(JsValue::Object(mut input)) = value else {
        let mut issues = vec![expected("body", "object", value.as_ref())];
        if route == "has-permission" {
            issues.push("[body] Invalid input".into());
        }
        return Err(schema_error(&(issues)));
    };
    let mut issues = Vec::new();
    for &(field, rule) in fields(route) {
        let value_2 = input.get(field);
        if value_2.is_none()
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
                if let Some(value_2_3) = value_2 {
                    if let Some(coerced_value) = coerce_string(value_2_3) {
                        if matches!(rule, Rule::NonemptyId) && coerced_value.is_empty() {
                            issues.push(format!("[{path}] userId cannot be empty"));
                        }
                        drop(input.insert(field.into(), JsValue::String(coerced_value)));
                    } else {
                        issues.push(expected(&path, "string", Some(value_2_3)));
                    }
                } else {
                    issues.push(expected(&path, "nonoptional", None));
                }
            }
            Rule::String | Rule::OptionalString | Rule::NonemptyPassword => {
                if let Some(value_4) = value_2.and_then(JsValue::as_str) {
                    if matches!(rule, Rule::NonemptyPassword) && value_4.is_empty() {
                        issues.push(format!("[{path}] newPassword cannot be empty"));
                    }
                } else {
                    issues.push(expected(&path, "string", value_2));
                }
            }
            Rule::Role | Rule::OptionalRole => {
                if !value_2.is_some_and(valid_role) {
                    issues.push(format!("[{path}] Invalid input"));
                }
            }
            Rule::Record | Rule::OptionalRecord => {
                if !value_2.is_some_and(JsValue::is_object) {
                    issues.push(expected(&path, "record", value_2));
                }
            }
            Rule::OptionalNumber => {
                if !value_2
                    .and_then(JsValue::as_f64)
                    .is_some_and(f64::is_finite)
                {
                    issues.push(expected(&path, "number", value_2));
                }
            }
        }
    }
    if route == "has-permission" {
        let singular = valid_permissions(input.get("permission"));
        let plural = valid_permissions(input.get("permissions"));
        match (singular, plural) {
            (true, true) => {
                issues.push("[body] Invalid input: more than one option matched".into());
            }
            (false, false) => issues.push("[body] Invalid input".into()),
            (true, false) => {
                drop(input.shift_remove("permissions"));
            }
            (false, true) => {
                drop(input.shift_remove("permission"));
            }
        }
    }
    if !issues.is_empty() {
        return Err(schema_error(&(issues)));
    }
    alibi_core::utils::json::from_value(JsValue::Object(input))
        .map_err(|_error| response(400, "VALIDATION_ERROR", "[body] Invalid input"))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn get_user(req: &AuthRequest) -> Result<super::types::GetUserQuery, AuthResponse> {
    drop(parse(req)?);
    match req.query_values("id") {
        Some([id]) => Ok(super::types::GetUserQuery { id: id.clone() }),
        Some(_) => Err(schema_error(&[
            "[query.id] Invalid input: expected string, received array".into(),
        ])),
        None => Err(schema_error(&[expected("query.id", "string", None)])),
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn list_users(req: &AuthRequest) -> Result<(), AuthResponse> {
    drop(parse(req)?);
    let mut issues = Vec::new();
    // Query arrays are materialized by repeated names before the endpoint
    // schema. Retain schema field order, including string/number unions.
    for (field, options) in [
        ("searchValue", None),
        ("searchField", Some(&["email", "name"][..])),
        (
            "searchOperator",
            Some(&["contains", "starts_with", "ends_with"][..]),
        ),
        ("limit", None),
        ("offset", None),
        ("sortBy", None),
        ("sortDirection", Some(&["asc", "desc"][..])),
        ("filterField", None),
        (
            "filterOperator",
            Some(
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
        ),
    ] {
        let Some(values) = req.query_values(field) else {
            continue;
        };
        if let Some(options) = options {
            if !matches!(values, [value] if options.contains(&value.as_str())) {
                issues.push(format!(
                    "[query.{field}] Invalid option: expected one of {}",
                    options
                        .iter()
                        .map(|value| format!("\"{value}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                ));
            }
        } else if values.len() != 1 {
            issues.push(if matches!(field, "limit" | "offset") {
                format!("[query.{field}] Invalid input")
            } else {
                format!("[query.{field}] Invalid input: expected string, received array")
            });
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(schema_error(&(issues)))
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
