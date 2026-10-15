//! Input normalization shared by User creation and replacement.
use super::user_attributes::{self, ENTERPRISE_SCHEMA, USER_SCHEMA};
use alibi_core::utils::javascript::trim;
use serde_json::{Value, json};
pub(super) struct Profile {
    pub user_name: String,
    pub primary_email: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub active: bool,
    pub attributes: Value,
}
fn text(raw: &Value, key: &str, max: usize) -> Result<Option<String>, ()> {
    let Some(value) = raw.get(key) else {
        return Ok(None);
    };
    let value = trim(value.as_str().ok_or(())?);
    if value.is_empty() || value.encode_utf16().count() > max {
        return Err(());
    }
    Ok(Some(value.into()))
}
pub(super) fn parse(raw: &Value) -> Option<Profile> {
    let user_name = text(raw, "userName", 512).ok()??;
    let external_id = text(raw, "externalId", 1024).ok()?;
    let display_name = text(raw, "displayName", 1024).ok()?;
    let active = raw.get("active").map_or(Some(true), Value::as_bool)?;
    let mut attrs = raw.as_object()?.clone();
    let _ = attrs.remove("enterprise");
    if let Some(name) = raw.get("name") {
        _ = name.as_object()?;
    }
    let name = raw.get("name").cloned().unwrap_or(json!({}));
    let mut normalized_name = serde_json::Map::new();
    for (key, max) in [
        ("formatted", 1024),
        ("givenName", 256),
        ("familyName", 256),
        ("middleName", 256),
        ("honorificPrefix", 256),
        ("honorificSuffix", 256),
    ] {
        if let Some(value) = text(&name, key, max).ok()? {
            _ = normalized_name.insert(key.into(), json!(value));
        }
    }
    let emails = match raw.get("emails") {
        Some(value) => value.as_array()?.clone(),
        None => Vec::new(),
    };
    if emails.len() > 20 {
        return None;
    }
    let mut normalized_emails = Vec::new();
    let mut explicit = 0;
    for email in emails {
        let value = email.get("value")?.as_str()?;
        if value.encode_utf16().count() > 254
            || !crate::authentication_helpers::is_valid_email(value)
        {
            return None;
        }
        let mut item = json!({"value":value.to_lowercase(),"primary":email.get("primary").map_or(Some(false),Value::as_bool)?});
        if item.get("primary").and_then(Value::as_bool) == Some(true) {
            explicit += 1;
        }
        if let Some(kind) = text(&email, "type", 256).ok()? {
            _ = item
                .as_object_mut()?
                .insert("type".into(), json!(kind.to_lowercase()));
        }
        normalized_emails.push(item);
    }
    if explicit > 1 {
        return None;
    }
    if normalized_emails.is_empty() {
        if user_name.encode_utf16().count() > 254
            || !crate::authentication_helpers::is_valid_email(&user_name)
        {
            return None;
        }
        normalized_emails.push(json!({"value":user_name.to_lowercase(),"primary":true}));
    }
    let selected = normalized_emails
        .iter()
        .position(|value| value.get("primary").and_then(Value::as_bool) == Some(true))
        .or_else(|| {
            normalized_emails
                .iter()
                .position(|value| value.get("type").and_then(Value::as_str) == Some("work"))
        })
        .unwrap_or(0);
    for (index, value) in normalized_emails.iter_mut().enumerate() {
        _ = value
            .as_object_mut()?
            .insert("primary".into(), json!(index == selected));
    }
    let primary_email = normalized_emails
        .get(selected)?
        .get("value")?
        .as_str()?
        .to_owned();
    let composed = ["givenName", "familyName"]
        .iter()
        .filter_map(|key| normalized_name.get(*key).and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let formatted = normalized_name
        .get("formatted")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| display_name.clone())
        .unwrap_or_else(|| {
            if composed.is_empty() {
                primary_email.clone()
            } else {
                composed
            }
        });
    _ = normalized_name.insert("formatted".into(), json!(formatted));
    _ = attrs.insert("name".into(), Value::Object(normalized_name));
    _ = attrs.insert("emails".into(), json!(normalized_emails));
    for key in [
        "title",
        "userType",
        "preferredLanguage",
        "locale",
        "timezone",
    ] {
        if let Some(value) = attrs.get_mut(key)
            && let Some(values) = value.as_array()
        {
            if values.len() != 1 {
                return None;
            }
            *value = values.first()?.clone();
        }
    }
    if let Some(extension) = attrs.remove(ENTERPRISE_SCHEMA) {
        let mut extension = extension.as_object()?.clone();
        if let Some(manager) = extension.remove("manager") {
            let manager = if let Some(value) = manager.as_str() {
                json!({"value":value})
            } else if let Some(values) = manager.as_array() {
                if values.len() != 1 {
                    return None;
                }
                values.first()?.clone()
            } else {
                manager
            };
            _ = manager.as_object()?;
            let mut result = serde_json::Map::new();
            for (key, max) in [("value", 256), ("$ref", 2048), ("displayName", 1024)] {
                if let Some(value) = text(&manager, key, max).ok()?
                    && key != "displayName"
                {
                    _ = result.insert(key.into(), json!(value));
                }
            }
            if !result.is_empty() {
                _ = extension.insert("manager".into(), json!(result));
            }
        }
        _ = attrs.insert("enterprise".into(), json!(extension));
    }
    let attributes = user_attributes::canonical(&Value::Object(attrs))?;
    // Bound the validated request, including its top-level scalar profile fields.
    let mut bounded = attributes.as_object()?.clone();
    _ = bounded.insert("userName".into(), json!(user_name));
    if let Some(value) = &external_id {
        _ = bounded.insert("externalId".into(), json!(value));
    }
    if let Some(value) = &display_name {
        _ = bounded.insert("displayName".into(), json!(value));
    }
    if raw.get("active").is_some() {
        _ = bounded.insert("active".into(), json!(active));
    }
    if serde_json::to_string(&bounded).ok()?.encode_utf16().count() > 65535 {
        return None;
    }
    if !attributes
        .get("schemas")?
        .as_array()?
        .iter()
        .any(|value| value == USER_SCHEMA)
    {
        return None;
    }
    Some(Profile {
        user_name,
        primary_email,
        display_name: display_name.unwrap_or(formatted),
        external_id,
        active,
        attributes,
    })
}
impl Profile {
    pub(super) fn prepare(
        &self,
        connection: &str,
    ) -> alibi_core::AuthResult<alibi_core::store::ScimUserAttributes> {
        let name = self.attributes.get("name").unwrap_or(&Value::Null);
        let emails = self.attributes.get("emails").unwrap_or(&Value::Null);
        let index = |kind: Option<&str>| -> alibi_core::AuthResult<String> {
            let mut keys = emails
                .as_array()
                .into_iter()
                .flatten()
                .filter(|email| {
                    kind.is_none_or(|kind| email.get("type").and_then(Value::as_str) == Some(kind))
                })
                .map(|email| {
                    super::resources::scoped_key(&[
                        "scim-email-value",
                        email.get("value").and_then(Value::as_str).unwrap_or(""),
                    ])
                })
                .collect::<alibi_core::AuthResult<Vec<_>>>()?;
            keys.sort();
            keys.dedup();
            Ok(format!("|{}|", keys.join("|")))
        };
        Ok(alibi_core::store::ScimUserAttributes {
            user_name: self.user_name.clone(),
            user_name_key: super::resources::scoped_key(&[
                "scim-user-name",
                connection,
                &self.user_name.to_lowercase(),
            ])?,
            primary_email: self.primary_email.clone(),
            work_email_value_index: index(Some("work"))?,
            email_value_index: index(None)?,
            display_name: self.display_name.clone(),
            formatted_name: name
                .get("formatted")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            given_name: name
                .get("givenName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            family_name: name
                .get("familyName")
                .and_then(Value::as_str)
                .map(str::to_owned),
            serialized_emails: serde_json::to_string(emails)?,
            serialized_attributes: Some(serde_json::to_string(&self.attributes)?),
            external_id: self.external_id.clone(),
            external_id_key: self
                .external_id
                .as_ref()
                .map(|value| {
                    super::resources::scoped_key(&["scim-user-external-id", connection, value])
                })
                .transpose()?,
            active: self.active,
        })
    }
}
