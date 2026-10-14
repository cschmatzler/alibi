//! Validation and normalization of persisted canonical SCIM User attributes.
use alibi_core::store::ScimUserRecord;
use serde_json::{Map, Value, json};
pub(super) const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(super) const ENTERPRISE_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// Reconstruct legacy mirrors before applying the same canonical contract.
pub(super) fn read(user: &ScimUserRecord) -> Option<Value> {
    let raw = if let Some(serialized) = user
        .serialized_attributes
        .as_ref()
        .filter(|value| !value.is_empty())
    {
        if serialized.encode_utf16().count() > 65535 {
            return None;
        }
        serde_json::from_str(serialized).ok()?
    } else {
        let mut name = json!({"formatted":user.formatted_name});
        if let Some(fields) = name.as_object_mut() {
            for (key, value) in [
                ("givenName", &user.given_name),
                ("familyName", &user.family_name),
            ] {
                if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
                    _ = fields.insert(key.into(), Value::String(value.clone()));
                }
            }
        }
        json!({"schemas":[USER_SCHEMA],"name":name,"emails":serde_json::from_str::<Value>(&user.serialized_emails).ok()?})
    };
    canonical(&raw)
}
pub(super) fn canonical(raw: &Value) -> Option<Value> {
    let raw = raw.as_object()?;
    let schemas = raw.get("schemas")?.as_array()?;
    if schemas.is_empty() || schemas.len() > 2 {
        return None;
    }
    let mut has_core = false;
    let mut has_enterprise = false;
    for schema in schemas {
        match schema.as_str()? {
            USER_SCHEMA if !has_core => has_core = true,
            ENTERPRISE_SCHEMA if !has_enterprise => has_enterprise = true,
            _ => return None,
        }
    }
    if !has_core {
        return None;
    }
    let schemas = if has_enterprise {
        json!([USER_SCHEMA, ENTERPRISE_SCHEMA])
    } else {
        json!([USER_SCHEMA])
    };
    let name = fields(
        raw.get("name")?,
        &[
            ("formatted", 1024),
            ("givenName", 256),
            ("familyName", 256),
            ("middleName", 256),
            ("honorificPrefix", 256),
            ("honorificSuffix", 256),
        ],
        &["formatted"],
        false,
    )?;
    let emails = complex_values(raw.get("emails")?, "emails")?;
    let mut output = fields(
        &Value::Object(raw.clone()),
        &[
            ("title", 1024),
            ("userType", 256),
            ("preferredLanguage", 256),
            ("locale", 256),
            ("timezone", 256),
        ],
        &[],
        false,
    )?;
    _ = output.insert("schemas".into(), schemas);
    _ = output.insert("name".into(), Value::Object(name));
    _ = output.insert("emails".into(), Value::Array(emails));
    for name in ["phoneNumbers", "addresses", "roles", "entitlements"] {
        if let Some(value) = raw.get(name) {
            _ = output.insert(name.into(), Value::Array(complex_values(value, name)?));
        }
    }
    if let Some(value) = raw.get("enterprise") {
        if !has_enterprise {
            return None;
        }
        let raw = value.as_object()?;
        let mut enterprise = fields(
            value,
            &[
                ("employeeNumber", 256),
                ("costCenter", 256),
                ("organization", 1024),
                ("division", 1024),
                ("department", 1024),
            ],
            &[],
            true,
        )?;
        if let Some(manager) = raw.get("manager") {
            let manager = fields(manager, &[("value", 256), ("$ref", 2048)], &[], false)?;
            if manager.is_empty() {
                return None;
            }
            _ = enterprise.insert("manager".into(), Value::Object(manager));
        }
        _ = output.insert("enterprise".into(), Value::Object(enterprise));
    }
    Some(Value::Object(output))
}
fn fields(
    raw: &Value,
    definitions: &[(&str, usize)],
    required: &[&str],
    single: bool,
) -> Option<Map<String, Value>> {
    let raw = raw.as_object()?;
    let mut output = Map::new();
    for (name, max) in definitions {
        if let Some(value) = raw.get(*name) {
            let value = if single {
                match value.as_array() {
                    Some(values) if values.len() == 1 => values.first()?,
                    _ => value,
                }
            } else {
                value
            };
            let value = alibi_core::utils::javascript::trim(value.as_str()?);
            if value.is_empty() || value.encode_utf16().count() > *max {
                return None;
            }
            let value = if *name == "type" {
                value.to_lowercase()
            } else {
                value.into()
            };
            _ = output.insert((*name).into(), Value::String(value));
        }
    }
    for name in required {
        if !output.contains_key(*name) {
            return None;
        }
    }
    Some(output)
}
fn complex_values(raw: &Value, kind: &str) -> Option<Vec<Value>> {
    let values = raw.as_array()?;
    let is_email = kind == "emails";
    if values.len() > if is_email { 20 } else { 10 } || (is_email && values.is_empty()) {
        return None;
    }
    let mut output = Vec::new();
    let mut primary = 0;
    let mut types = std::collections::HashSet::new();
    let mut emails = std::collections::HashSet::new();
    for value in values {
        let raw = value.as_object()?;
        let mut item = match kind {
            "emails" => {
                let address = raw.get("value")?.as_str()?;
                if address.encode_utf16().count() > 254
                    || !crate::authentication_helpers::is_valid_email(address)
                {
                    return None;
                }
                let mut item = fields(value, &[("type", 256)], &[], false)?;
                _ = item.insert("value".into(), Value::String(address.into()));
                item
            }
            "phoneNumbers" => fields(value, &[("value", 1024), ("type", 256)], &["value"], false)?,
            "addresses" => {
                let item = fields(
                    value,
                    &[
                        ("formatted", 1024),
                        ("streetAddress", 1024),
                        ("locality", 256),
                        ("region", 256),
                        ("postalCode", 256),
                        ("country", 256),
                        ("type", 256),
                    ],
                    &[],
                    false,
                )?;
                if !item.keys().any(|name| name != "type") {
                    return None;
                }
                item
            }
            _ => fields(
                value,
                &[("value", 1024), ("display", 1024), ("type", 256)],
                &["value"],
                false,
            )?,
        };
        if let Some(value) = raw.get("primary") {
            let flag = value.as_bool()?;
            if flag {
                primary += 1;
            }
            _ = item.insert("primary".into(), Value::Bool(flag));
        } else if is_email {
            return None;
        }
        if let Some(kind) = item.get("type").and_then(Value::as_str)
            && !types.insert(kind.to_owned())
        {
            return None;
        }
        if is_email {
            let key = (
                item.get("type").and_then(Value::as_str).map(str::to_owned),
                item.get("value")?.as_str()?.to_lowercase(),
            );
            if !emails.insert(key) {
                return None;
            }
        }
        output.push(Value::Object(item));
    }
    if primary > 1 || (is_email && primary != 1) {
        return None;
    }
    Some(output)
}
