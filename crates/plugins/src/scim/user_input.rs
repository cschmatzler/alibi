//! Field diagnostics for the User create/replace input shared by both transports.
use super::user_attributes::{ENTERPRISE_SCHEMA, USER_SCHEMA};
use alibi_core::utils::javascript::trim;
use serde_json::Value;

#[derive(Default)]
struct Issues {
    messages: Vec<String>,
    fatal: bool,
}
impl Issues {
    fn add(&mut self, path: &str, message: impl std::fmt::Display) {
        self.messages.push(format!("[{path}] {message}"));
    }
    fn wrong_type(&mut self, path: &str, expected: &str, value: Option<&Value>) {
        let received = match value {
            None => "undefined",
            Some(Value::Null) => "null",
            Some(Value::Bool(_)) => "boolean",
            Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Array(_)) => "array",
            Some(Value::Object(_)) => "object",
        };
        self.add(
            path,
            format_args!("Invalid input: expected {expected}, received {received}"),
        );
        self.fatal = true;
    }
    fn string(&mut self, path: &str, value: Option<&Value>, max: usize) {
        let Some(value) = value.and_then(Value::as_str) else {
            self.wrong_type(path, "string", value);
            return;
        };
        let size = trim(value).encode_utf16().count();
        if size == 0 {
            self.add(path, "Too small: expected string to have >=1 characters");
        }
        if size > max {
            self.add(
                path,
                format_args!("Too big: expected string to have <={max} characters"),
            );
        }
    }
    fn optional_strings(&mut self, value: &Value, path: &str, fields: &[(&str, usize)]) {
        for (key, max) in fields {
            if let Some(value) = value.get(*key) {
                self.string(&format!("{path}.{key}"), Some(value), *max);
            }
        }
    }
    fn boolean(&mut self, path: &str, value: &Value) {
        if !value.is_boolean() {
            self.wrong_type(path, "boolean", Some(value));
        }
    }
}

/// Preserve field order and repeated schema issues from the pinned input schema.
/// The canonical profile parser remains the admission owner for all attributes.
pub(super) fn detail(raw: &Value) -> String {
    let mut issues = Issues::default();
    if !raw.is_object() {
        issues.wrong_type("body", "object", Some(raw));
        return issues.messages.join("; ");
    }
    if let Some(schemas) = raw.get("schemas").and_then(Value::as_array) {
        if schemas.is_empty() {
            issues.add(
                "body.schemas",
                "Too small: expected array to have >=1 items",
            );
        }
        if schemas.len() > 2 {
            issues.add("body.schemas", "Too big: expected array to have <=2 items");
        }
        for (index, schema) in schemas.iter().enumerate() {
            if !schema.is_string() {
                issues.wrong_type(&format!("body.schemas.{index}"), "string", Some(schema));
            }
        }
        if schemas.iter().all(Value::is_string) {
            for schema in schemas.iter().filter_map(Value::as_str) {
                if ![USER_SCHEMA, ENTERPRISE_SCHEMA].contains(&schema) {
                    issues.add(
                        "body.schemas",
                        format_args!("Unsupported SCIM User schema {schema}"),
                    );
                }
                if schemas
                    .iter()
                    .filter(|value| value.as_str() == Some(schema))
                    .count()
                    > 1
                {
                    issues.add(
                        "body.schemas",
                        format_args!("SCIM User schema {schema} must not be duplicated"),
                    );
                }
            }
            if !schemas
                .iter()
                .any(|value| value.as_str() == Some(USER_SCHEMA))
            {
                issues.add(
                    "body.schemas",
                    format_args!("schemas must contain {USER_SCHEMA}"),
                );
            }
        }
    } else {
        issues.wrong_type("body.schemas", "array", raw.get("schemas"));
    }
    issues.string("body.userName", raw.get("userName"), 512);
    issues.optional_strings(raw, "body", &[("externalId", 1024), ("displayName", 1024)]);
    if let Some(name) = raw.get("name") {
        if name.is_object() {
            issues.optional_strings(
                name,
                "body.name",
                &[
                    ("formatted", 1024),
                    ("givenName", 256),
                    ("familyName", 256),
                    ("middleName", 256),
                    ("honorificPrefix", 256),
                    ("honorificSuffix", 256),
                ],
            );
        } else {
            issues.wrong_type("body.name", "object", Some(name));
        }
    }
    if let Some(emails) = raw.get("emails") {
        if let Some(emails) = emails.as_array() {
            if emails.len() > 20 {
                issues.add("body.emails", "Too big: expected array to have <=20 items");
            }
            for (index, email) in emails.iter().enumerate() {
                let path = format!("body.emails.{index}");
                if !email.is_object() {
                    issues.wrong_type(&path, "object", Some(email));
                    continue;
                }
                let path_value = format!("{path}.value");
                if let Some(value) = email.get("value").and_then(Value::as_str) {
                    if !crate::authentication_helpers::is_valid_email(value) {
                        issues.add(&path_value, "Invalid email address");
                    }
                    if value.encode_utf16().count() > 254 {
                        issues.add(
                            &path_value,
                            "Too big: expected string to have <=254 characters",
                        );
                    }
                } else {
                    issues.wrong_type(&path_value, "string", email.get("value"));
                }
                if let Some(primary) = email.get("primary") {
                    issues.boolean(&format!("{path}.primary"), primary);
                }
                issues.optional_strings(email, &path, &[("type", 256)]);
            }
        } else {
            issues.wrong_type("body.emails", "array", Some(emails));
        }
    }
    for (key, max) in [
        ("title", 1024),
        ("userType", 256),
        ("preferredLanguage", 256),
        ("locale", 256),
        ("timezone", 256),
    ] {
        if let Some(value) = raw.get(key) {
            let value = match value.as_array() {
                Some(values) if values.len() == 1 => values.first().unwrap_or(value),
                _ => value,
            };
            issues.string(&format!("body.{key}"), Some(value), max);
            if value.as_array().is_some_and(Vec::is_empty) {
                issues.add(
                    &format!("body.{key}"),
                    "Too small: expected array to have >=1 items",
                );
            }
        }
    }
    if let Some(active) = raw.get("active") {
        issues.boolean("body.active", active);
    }
    if !issues.fatal
        && raw
            .get("emails")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        && !raw
            .get("userName")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                let value = trim(value);
                value.encode_utf16().count() <= 254
                    && crate::authentication_helpers::is_valid_email(value)
            })
    {
        issues.add(
            "body.emails",
            "emails must contain an email when userName is not an email address",
        );
    }
    if issues.messages.is_empty() {
        "Invalid SCIM User attributes".into()
    } else {
        issues.messages.join("; ")
    }
}
