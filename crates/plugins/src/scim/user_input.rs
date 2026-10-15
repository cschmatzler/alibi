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
    fn scalar(&mut self, path: &str, raw: &Value, max: usize) {
        let value = match raw.as_array() {
            Some(values) if values.len() == 1 => values.first().unwrap_or(raw),
            _ => raw,
        };
        self.string(path, Some(value), max);
        if value.as_array().is_some_and(Vec::is_empty) {
            self.add(path, "Too small: expected array to have >=1 items");
        }
    }
    fn complex_values(&mut self, name: &str, raw: &Value) {
        let path = format!("body.{name}");
        let Some(values) = raw.as_array() else {
            self.wrong_type(&path, "array", Some(raw));
            return;
        };
        let mut items = Self::default();
        for (index, value) in values.iter().enumerate() {
            let path = format!("{path}.{index}");
            let mut item = Self::default();
            if !value.is_object() {
                items.wrong_type(&path, "object", Some(value));
                continue;
            }
            if name == "emails" {
                let field = format!("{path}.value");
                if let Some(email) = value.get("value").and_then(Value::as_str) {
                    if !crate::authentication_helpers::is_valid_email(email) {
                        item.add(&field, "Invalid email address");
                    }
                    if email.encode_utf16().count() > 254 {
                        item.add(&field, "Too big: expected string to have <=254 characters");
                    }
                } else {
                    item.wrong_type(&field, "string", value.get("value"));
                }
                if let Some(primary) = value.get("primary") {
                    item.boolean(&format!("{path}.primary"), primary);
                }
                item.optional_strings(value, &path, &[("type", 256)]);
            } else {
                if name == "addresses" {
                    item.optional_strings(
                        value,
                        &path,
                        &[
                            ("formatted", 1024),
                            ("streetAddress", 1024),
                            ("locality", 256),
                            ("region", 256),
                            ("postalCode", 256),
                            ("country", 256),
                        ],
                    );
                } else {
                    item.string(&format!("{path}.value"), value.get("value"), 1024);
                    if name != "phoneNumbers" {
                        item.optional_strings(value, &path, &[("display", 1024)]);
                    }
                }
                item.optional_strings(value, &path, &[("type", 256)]);
                if let Some(primary) = value.get("primary") {
                    item.boolean(&format!("{path}.primary"), primary);
                }
                if name == "addresses"
                    && !item.fatal
                    && ![
                        "formatted",
                        "streetAddress",
                        "locality",
                        "region",
                        "postalCode",
                        "country",
                    ]
                    .iter()
                    .any(|key| value.get(*key).is_some())
                {
                    item.add(&path, "addresses must contain at least one address value");
                }
            }
            items.fatal |= item.fatal;
            items.messages.extend(item.messages);
        }
        let max = if name == "emails" { 20 } else { 10 };
        if values.len() > max {
            items.add(
                &path,
                format_args!("Too big: expected array to have <={max} items"),
            );
        }
        if !items.fatal {
            if values
                .iter()
                .filter(|value| value.get("primary").and_then(Value::as_bool) == Some(true))
                .count()
                > 1
            {
                items.add(
                    &path,
                    format_args!("{name} cannot contain multiple primary values"),
                );
            }
            if name == "emails" {
                let mut pairs = std::collections::HashSet::new();
                if values.iter().any(|value| {
                    !pairs.insert((
                        value
                            .get("type")
                            .and_then(Value::as_str)
                            .map(|value| trim(value).to_lowercase()),
                        value
                            .get("value")
                            .and_then(Value::as_str)
                            .map(|value| trim(value).to_lowercase()),
                    ))
                }) {
                    items.add(
                        &path,
                        "emails cannot contain duplicate type and value pairs",
                    );
                }
            }
            let mut types = std::collections::HashSet::new();
            if values
                .iter()
                .filter_map(|value| value.get("type").and_then(Value::as_str))
                .any(|value| !types.insert(trim(value).to_lowercase()))
            {
                items.add(
                    &path,
                    format_args!("{name} cannot contain duplicate defined types"),
                );
            }
        }
        self.fatal |= items.fatal;
        self.messages.extend(items.messages);
    }
    fn manager(&mut self, path: &str, raw: &Value) {
        let mut branch = Self::default();
        if raw.is_string() {
            branch.string(path, Some(raw), 256);
        } else if let Some(values) = raw.as_array() {
            for (index, value) in values.iter().enumerate() {
                let path = format!("{path}.{index}");
                if value.is_object() {
                    branch.optional_strings(
                        value,
                        &path,
                        &[("value", 256), ("$ref", 2048), ("displayName", 1024)],
                    );
                } else {
                    branch.wrong_type(&path, "object", Some(value));
                }
            }
            if values.len() != 1 {
                branch.add(
                    path,
                    if values.is_empty() {
                        "Too small: expected array to have exactly 1 items"
                    } else {
                        "Too big: expected array to have exactly 1 items"
                    },
                );
            }
        } else if raw.is_object() {
            branch.optional_strings(
                raw,
                path,
                &[("value", 256), ("$ref", 2048), ("displayName", 1024)],
            );
        } else {
            branch.fatal = true;
        }
        if branch.fatal {
            self.add(path, "Invalid input");
            self.fatal = true;
        } else {
            self.messages.extend(branch.messages);
        }
    }
    fn enterprise(&mut self, raw: &Value) {
        let path = format!("body.{ENTERPRISE_SCHEMA}");
        if !raw.is_object() {
            self.wrong_type(&path, "object", Some(raw));
            return;
        }
        for (key, max) in [
            ("employeeNumber", 256),
            ("costCenter", 256),
            ("organization", 1024),
            ("division", 1024),
            ("department", 1024),
        ] {
            if let Some(value) = raw.get(key) {
                self.scalar(&format!("{path}.{key}"), value, max);
            }
        }
        if let Some(manager) = raw.get("manager") {
            self.manager(&format!("{path}.manager"), manager);
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
        for (index, schema) in schemas.iter().enumerate() {
            if !schema.is_string() {
                issues.wrong_type(&format!("body.schemas.{index}"), "string", Some(schema));
            }
        }
        if schemas.is_empty() {
            issues.add(
                "body.schemas",
                "Too small: expected array to have >=1 items",
            );
        }
        if schemas.len() > 2 {
            issues.add("body.schemas", "Too big: expected array to have <=2 items");
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
        issues.complex_values("emails", emails);
    }
    for (key, max) in [
        ("title", 1024),
        ("userType", 256),
        ("preferredLanguage", 256),
        ("locale", 256),
        ("timezone", 256),
    ] {
        if let Some(value) = raw.get(key) {
            issues.scalar(&format!("body.{key}"), value, max);
        }
    }
    for name in ["phoneNumbers", "addresses", "roles", "entitlements"] {
        if let Some(values) = raw.get(name) {
            issues.complex_values(name, values);
        }
    }
    if let Some(active) = raw.get("active") {
        issues.boolean("body.active", active);
    }
    if let Some(enterprise) = raw.get(ENTERPRISE_SCHEMA) {
        issues.enterprise(enterprise);
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
    if !issues.fatal
        && raw.get(ENTERPRISE_SCHEMA).is_some()
        && !raw
            .get("schemas")
            .and_then(Value::as_array)
            .is_some_and(|schemas| {
                schemas
                    .iter()
                    .any(|schema| schema.as_str() == Some(ENTERPRISE_SCHEMA))
            })
    {
        issues.add(
            "body.schemas",
            format_args!("The Enterprise User extension requires {ENTERPRISE_SCHEMA} in schemas"),
        );
    }
    if !issues.fatal && serialized_size(raw).is_some_and(|size| size > 65535) {
        issues.add(
            "body",
            "SCIM User attributes exceed the supported serialized size",
        );
    }
    if issues.messages.is_empty() {
        "Invalid SCIM User attributes".into()
    } else {
        issues.messages.join("; ")
    }
}

/// Size of the schema's normalized input, before canonical defaults are added.
/// Unknown fields and absent optionals do not participate in the source limit.
pub(super) fn serialized_size(raw: &Value) -> Option<usize> {
    fn selected(
        raw: &Value,
        keys: &[&str],
        scalar: bool,
        email: bool,
    ) -> serde_json::Map<String, Value> {
        let mut result = serde_json::Map::new();
        for key in keys {
            if let Some(value) = raw.get(*key) {
                let value = if scalar {
                    value
                        .as_array()
                        .filter(|values| values.len() == 1)
                        .and_then(|values| values.first())
                        .unwrap_or(value)
                } else {
                    value
                };
                let value = value
                    .as_str()
                    .map(|value| {
                        if email && *key == "value" {
                            value.to_owned()
                        } else if *key == "type" {
                            trim(value).to_lowercase()
                        } else {
                            trim(value).to_owned()
                        }
                    })
                    .map_or_else(|| value.clone(), Value::String);
                _ = result.insert((*key).into(), value);
            }
        }
        result
    }
    _ = raw.as_object()?;
    let mut result = selected(
        raw,
        &["userName", "externalId", "displayName", "active"],
        false,
        false,
    );
    result.extend(selected(
        raw,
        &[
            "title",
            "userType",
            "preferredLanguage",
            "locale",
            "timezone",
        ],
        true,
        false,
    ));
    if let Some(schemas) = raw.get("schemas") {
        _ = result.insert("schemas".into(), schemas.clone());
    }
    if let Some(name) = raw.get("name") {
        _ = result.insert(
            "name".into(),
            Value::Object(selected(
                name,
                &[
                    "formatted",
                    "givenName",
                    "familyName",
                    "middleName",
                    "honorificPrefix",
                    "honorificSuffix",
                ],
                false,
                false,
            )),
        );
    }
    for (key, fields) in [
        ("emails", &["value", "primary", "type"][..]),
        ("phoneNumbers", &["value", "primary", "type"][..]),
        (
            "addresses",
            &[
                "formatted",
                "streetAddress",
                "locality",
                "region",
                "postalCode",
                "country",
                "type",
                "primary",
            ][..],
        ),
        ("roles", &["value", "display", "type", "primary"][..]),
        ("entitlements", &["value", "display", "type", "primary"][..]),
    ] {
        if let Some(values) = raw.get(key).and_then(Value::as_array) {
            _ = result.insert(
                key.into(),
                Value::Array(
                    values
                        .iter()
                        .map(|value| Value::Object(selected(value, fields, false, key == "emails")))
                        .collect(),
                ),
            );
        }
    }
    if let Some(enterprise) = raw.get(ENTERPRISE_SCHEMA) {
        let mut fields = selected(
            enterprise,
            &[
                "employeeNumber",
                "costCenter",
                "organization",
                "division",
                "department",
            ],
            true,
            false,
        );
        if let Some(manager) = enterprise.get("manager") {
            let manager = manager
                .as_array()
                .and_then(|values| values.first())
                .unwrap_or(manager);
            let normalized = if let Some(value) = manager.as_str() {
                serde_json::Map::from_iter([("value".into(), Value::String(trim(value).into()))])
            } else {
                selected(manager, &["value", "$ref"], false, false)
            };
            if !normalized.is_empty() {
                _ = fields.insert("manager".into(), Value::Object(normalized));
            }
        }
        _ = result.insert(ENTERPRISE_SCHEMA.into(), Value::Object(fields));
    }
    serde_json::to_string(&result)
        .ok()
        .map(|serialized| serialized.encode_utf16().count())
}
