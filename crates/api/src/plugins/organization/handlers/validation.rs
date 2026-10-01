//! Wire validation for the organization access-control schemas.
use better_auth_core::types::OrganizationPermissions;

use better_auth_core::{AuthRequest, AuthResponse};

use serde_json::{Map, Value, json};

#[derive(Debug)]
pub(super) struct Issue(Vec<String>);

impl From<Issue> for AuthResponse {
    fn from(value: Issue) -> Self {
        error(value.0.join("; "))
    }
}

#[derive(Debug, Default)]
pub(super) struct Issues(Vec<String>);

impl Issues {
    pub(super) fn take<T>(&mut self, result: Result<T, Issue>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(issue) => {
                self.0.extend(issue.0);
                None
            }
        }
    }

    pub(super) fn push(&mut self, message: impl Into<String>) {
        self.0.push(message.into());
    }

    pub(super) fn response(self) -> Option<AuthResponse> {
        (!self.0.is_empty()).then(|| Issue(self.0).into())
    }
}

pub(super) fn error(message: impl Into<String>) -> AuthResponse {
    response("VALIDATION_ERROR", message)
}

pub(super) fn issue(message: impl Into<String>) -> Issue {
    Issue(vec![message.into()])
}

fn response(code: &str, message: impl Into<String>) -> AuthResponse {
    AuthResponse::json(400, &json!({"code":code,"message":message.into()}))
        .unwrap_or_else(|_| AuthResponse::text(400, "Validation failed"))
}

const fn kind(value: Option<&Value>) -> &'static str {
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

fn expected(path: &str, expected: &str, value: Option<&Value>) -> Issue {
    issue(format!(
        "[{path}] Invalid input: expected {expected}, received {}",
        kind(value)
    ))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn body_object(req: &AuthRequest) -> Result<Map<String, Value>, AuthResponse> {
    let Some(bytes) = req.body.as_deref() else {
        // Bun's incoming empty chunked JSON stream materializes null. An absent
        // stream and direct empty byte buffer have distinct upstream errors.
        let chunked = req.headers.get("transfer-encoding").is_some_and(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        });
        let json = req.headers.get("content-type").is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.strip_prefix("application/").is_some_and(|subtype| {
                subtype.starts_with("json")
                    || subtype.find("+json").is_some_and(|index| {
                        subtype
                            .get(..index)
                            .unwrap_or_default()
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
                    })
            })
        });
        return Err(expected("body", "object", (chunked && json).then_some(&Value::Null)).into());
    };
    let value = better_auth_core::utils::json::from_slice::<Value>(bytes)
        .map_err(|_error| response("BAD_REQUEST", "Invalid JSON in request body"))?;
    object(Some(&value), "body").cloned().map_err(Into::into)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn object<'a>(
    value: Option<&'a Value>,
    path: &str,
) -> Result<&'a Map<String, Value>, Issue> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| expected(path, "object", value))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn optional_string(
    input: &Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<Option<String>, Issue> {
    input
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| expected(path, "string", Some(value)))
        })
        .transpose()
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn required_string(
    input: &Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<String, Issue> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| expected(path, "string", input.get(field)))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn permissions(
    value: Option<&Value>,
    path: &str,
) -> Result<OrganizationPermissions, Issue> {
    let input = value
        .and_then(Value::as_object)
        .ok_or_else(|| expected(path, "record", value))?;
    let mut permissions = OrganizationPermissions::new();
    let mut issues = Vec::new();
    let mut entries = input.iter().collect::<Vec<_>>();
    // Object.entries enumerates array-index keys first, numerically, while
    // retaining insertion order for other resource names.
    entries.sort_by_key(|(resource, _)| {
        resource
            .parse::<u32>()
            .ok()
            .filter(|index| *index != u32::MAX && index.to_string() == **resource)
            .map_or((true, 0), |index| (false, index))
    });
    for (resource, actions) in entries {
        let action_path = format!("{path}.{resource}");
        let Some(actions) = actions.as_array() else {
            issues.extend(expected(&action_path, "array", Some(actions)).0);
            continue;
        };
        let mut granted = Vec::with_capacity(actions.len());
        for (index, action) in actions.iter().enumerate() {
            if let Some(action) = action.as_str() {
                granted.push(action.to_owned());
            } else {
                issues
                    .extend(expected(&format!("{action_path}.{index}"), "string", Some(action)).0);
            }
        }
        drop(permissions.insert(resource.to_owned(), granted));
    }
    if issues.is_empty() {
        Ok(permissions)
    } else {
        Err(Issue(issues))
    }
}
