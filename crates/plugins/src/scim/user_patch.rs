//! Ordered SCIM User changes, evaluated against a transaction-owned resource.
use super::{
    attribute_names::{self, Attribute},
    null_attributes::Target,
    user_attributes::{self, ENTERPRISE_SCHEMA, USER_SCHEMA},
    user_profile::{self, Profile},
};
use alibi_core::utils::json::JsValue as Value;
use alibi_core::{
    AuthError, AuthResult,
    store::{ScimGroupPatchKind as Kind, ScimGroupPatchOperation as Operation, ScimUserRecord},
    utils::javascript::trim,
};
use indexmap::IndexMap as Map;

trait MutablePatchValue {
    fn as_object_mut(&mut self) -> Option<&mut Map<String, Value>>;
}
impl MutablePatchValue for Value {
    fn as_object_mut(&mut self) -> Option<&mut Map<String, Value>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }
}
fn error(detail: impl Into<String>, kind: &str) -> AuthError {
    AuthError::Api {
        status: 400,
        code: Some(kind.into()),
        message: detail.into(),
    }
}
fn invalid(detail: impl Into<String>) -> AuthError {
    error(detail, "invalidValue")
}
fn unsupported(path: &str) -> AuthError {
    error(
        format!("User PATCH path {path} is not supported"),
        "invalidPath",
    )
}
fn scalar(value: &Value) -> &Value {
    match value.as_array() {
        Some(values) if values.len() == 1 => values.first().unwrap_or(&Value::Null),
        _ => value,
    }
}
fn string(value: &Value, path: &str) -> AuthResult<String> {
    scalar(value)
        .as_str()
        .map(trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("{path} must be a non-empty string")))
}
fn email(value: &Value) -> AuthResult<String> {
    let value = value
        .as_str()
        .filter(|value| {
            value.encode_utf16().count() <= 254
                && crate::authentication_helpers::is_valid_email(value)
        })
        .ok_or_else(|| invalid("emails.value must be an email"))?;
    Ok(value.to_lowercase())
}
fn get_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
fn field<'a>(value: &'a Map<String, Value>, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .and_then(|_| path.get(prefix.len()..))
}
fn relative(path: &str) -> String {
    let path = trim(path);
    let core = format!("{USER_SCHEMA}:");
    let path = prefix(path, &core).unwrap_or(path);
    let enterprise = format!("{ENTERPRISE_SCHEMA}:");
    if let Some(path) = prefix(path, &enterprise) {
        return format!("enterprise.{path}");
    }
    if path.eq_ignore_ascii_case(ENTERPRISE_SCHEMA) {
        return "enterprise".into();
    }
    if path.eq_ignore_ascii_case("manager") || prefix(path, "manager.").is_some() {
        return format!("enterprise.{path}");
    }
    path.into()
}
struct State {
    document: Map<String, Value>,
    name: Map<String, Value>,
    emails: Vec<Value>,
    user_name: String,
    display_name: String,
    external_id: Option<String>,
    active: bool,
}
impl State {
    fn primary(&self) -> &str {
        self.emails
            .iter()
            .find(|item| item.get("primary").and_then(Value::as_bool) == Some(true))
            .or_else(|| self.emails.first())
            .and_then(|item| get_string(item, "value"))
            .unwrap_or("")
    }
    fn formatted(&self) -> &str {
        field(&self.name, "formatted")
    }
    fn formatted_set(&mut self, value: String) {
        if self.display_name == self.formatted() {
            self.display_name.clone_from(&value);
        }
        _ = self.name.insert("formatted".into(), Value::String(value));
    }
    fn set_emails(&mut self, value: &Value) -> AuthResult<()> {
        let values = value
            .as_array()
            .filter(|values| !values.is_empty() && values.len() <= 20)
            .ok_or_else(|| invalid("emails must contain between 1 and 20 valid emails"))?;
        let mut emails = Vec::new();
        let mut primaries = 0;
        let mut tuples = std::collections::HashSet::new();
        let mut types = std::collections::HashSet::new();
        for item in values {
            let address = email(item.get("value").unwrap_or(&Value::Null))
                .map_err(|_| invalid("emails must contain between 1 and 20 valid emails"))?;
            let mut item_out = Map::new();
            _ = item_out.insert("value".into(), Value::String(address.clone()));
            let primary = match item.get("primary") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| invalid("emails must contain between 1 and 20 valid emails"))?,
            };
            if primary {
                primaries += 1;
            }
            _ = item_out.insert("primary".into(), Value::Bool(primary));
            let kind = if let Some(value) = item.get("type") {
                let value = value
                    .as_str()
                    .map(trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid("emails must contain between 1 and 20 valid emails"))?;
                Some(value.to_lowercase())
            } else {
                None
            };
            if !tuples.insert((kind.clone(), address)) {
                return Err(invalid(
                    "emails cannot contain duplicate type and value pairs",
                ));
            }
            if let Some(kind) = kind {
                if !types.insert(kind.clone()) {
                    return Err(invalid("emails cannot contain duplicate defined types"));
                }
                _ = item_out.insert("type".into(), Value::String(kind));
            }
            emails.push(Value::Object(item_out));
        }
        if primaries > 1 {
            return Err(invalid("emails cannot contain multiple primary values"));
        }
        let chosen = emails
            .iter()
            .position(|value| value.get("primary").and_then(Value::as_bool) == Some(true))
            .or_else(|| {
                emails
                    .iter()
                    .position(|value| get_string(value, "type") == Some("work"))
            })
            .unwrap_or(0);
        for (index, item) in emails.iter_mut().enumerate() {
            if let Some(item) = item.as_object_mut() {
                _ = item.insert("primary".into(), Value::Bool(index == chosen));
            }
        }
        self.emails = emails;
        Ok(())
    }
    fn add_emails(&mut self, value: &Value) -> AuthResult<()> {
        let incoming = value
            .as_array()
            .filter(|values| !values.is_empty() && values.len() <= 20)
            .ok_or_else(|| invalid("emails must contain between 1 and 20 valid emails"))?;
        let mut additions = Vec::<Value>::new();
        for item in incoming {
            let address = email(item.get("value").unwrap_or(&Value::Null))
                .map_err(|_| invalid("emails must contain between 1 and 20 valid emails"))?;
            let kind = item
                .get("type")
                .map(|value| string(value, "emails.type").map(|value| value.to_lowercase()))
                .transpose()?;
            let primary = match item.get("primary") {
                None => false,
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| invalid("emails must contain between 1 and 20 valid emails"))?,
            };
            let mut normalized = Value::Object(
                [
                    ("value".into(), Value::String(address)),
                    ("primary".into(), Value::Bool(primary)),
                ]
                .into_iter()
                .collect(),
            );
            if let Some(kind) = kind
                && let Some(object) = normalized.as_object_mut()
            {
                _ = object.insert("type".into(), Value::String(kind));
            }
            if let Some(existing) = additions.iter_mut().find(|existing| {
                existing.get("value") == normalized.get("value")
                    && existing.get("type") == normalized.get("type")
            }) {
                if primary && let Some(object) = existing.as_object_mut() {
                    _ = object.insert("primary".into(), Value::Bool(true));
                }
            } else {
                additions.push(normalized);
            }
        }
        if additions
            .iter()
            .filter(|value| value.get("primary").and_then(Value::as_bool) == Some(true))
            .count()
            > 1
        {
            return Err(invalid("emails cannot contain multiple primary values"));
        }
        additions.retain(|item| {
            !self.emails.iter().any(|old| {
                old.get("value") == item.get("value") && old.get("type") == item.get("type")
            })
        });
        if additions.is_empty() {
            return Ok(());
        }
        let mut combined = self.emails.clone();
        if additions
            .iter()
            .any(|item| item.get("primary").and_then(Value::as_bool) == Some(true))
        {
            for item in &mut combined {
                if let Some(object) = item.as_object_mut() {
                    _ = object.insert("primary".into(), Value::Bool(false));
                }
            }
        }
        combined.extend(additions);
        self.set_emails(&Value::Array(combined))
    }
    fn apply(&mut self, op: Kind, path: &str, value: &Value) -> AuthResult<()> {
        let relative = relative(path);
        let normalized = relative.to_lowercase();
        let remove = op == Kind::Remove;
        if matches!(normalized.as_str(), "id" | "schemas" | "meta")
            || normalized.starts_with("meta.")
        {
            return Err(error(format!("{path} is read-only"), "mutability"));
        }
        match normalized.as_str() {
            "username" => {
                if remove {
                    return Err(error("userName is read-only", "mutability"));
                }
                self.user_name = string(value, "userName")?;
            }
            "externalid" => {
                self.external_id = if remove {
                    None
                } else {
                    Some(string(value, "externalId")?)
                }
            }
            "active" => {
                self.active = if remove {
                    true
                } else {
                    scalar(value)
                        .as_bool()
                        .ok_or_else(|| invalid("active must be a boolean"))?
                }
            }
            "displayname" => {
                self.display_name = if remove {
                    self.formatted().into()
                } else {
                    string(value, "displayName")?
                }
            }
            "name" => {
                if remove {
                    for key in [
                        "givenName",
                        "familyName",
                        "middleName",
                        "honorificPrefix",
                        "honorificSuffix",
                    ] {
                        _ = self.name.shift_remove(key);
                    }
                    let next = if self.display_name.is_empty() {
                        self.primary().into()
                    } else {
                        self.display_name.clone()
                    };
                    self.formatted_set(next);
                } else {
                    let name = value
                        .as_object()
                        .ok_or_else(|| invalid("name must be an object"))?;
                    for (key, value) in name {
                        let canonical = match key.to_lowercase().as_str() {
                            "formatted" => "formatted",
                            "givenname" => "givenName",
                            "familyname" => "familyName",
                            "middlename" => "middleName",
                            "honorificprefix" => "honorificPrefix",
                            "honorificsuffix" => "honorificSuffix",
                            _ => {
                                return Err(error(
                                    format!("User attribute name.{key} is not supported"),
                                    "invalidPath",
                                ));
                            }
                        };
                        let value = string(value, &format!("name.{canonical}"))?;
                        if canonical == "formatted" {
                            self.formatted_set(value);
                        } else {
                            _ = self.name.insert(canonical.into(), Value::String(value));
                        }
                    }
                }
            }
            "name.formatted" => {
                let composed = [
                    field(&self.name, "givenName"),
                    field(&self.name, "familyName"),
                ]
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
                let next = if remove {
                    if !composed.is_empty() {
                        composed
                    } else if !self.display_name.is_empty() {
                        self.display_name.clone()
                    } else {
                        self.primary().into()
                    }
                } else {
                    string(value, "name.formatted")?
                };
                self.formatted_set(next);
            }
            "name.givenname"
            | "name.familyname"
            | "name.middlename"
            | "name.honorificprefix"
            | "name.honorificsuffix" => {
                let canonical = match normalized.as_str() {
                    "name.givenname" => "givenName",
                    "name.familyname" => "familyName",
                    "name.middlename" => "middleName",
                    "name.honorificprefix" => "honorificPrefix",
                    _ => "honorificSuffix",
                };
                if remove {
                    _ = self.name.shift_remove(canonical);
                } else {
                    let value = string(value, &format!("name.{canonical}"))?;
                    _ = self.name.insert(canonical.into(), Value::String(value));
                }
            }
            "emails" => {
                if remove {
                    return Err(invalid("emails cannot be removed"));
                }
                if op == Kind::Add {
                    self.add_emails(value)?;
                } else {
                    self.set_emails(value)?;
                }
            }
            "emails.value" => {
                if remove {
                    return Err(invalid("emails.value cannot be removed"));
                }
                let replacement = email(value)?;
                let mut emails = self.emails.clone();
                for item in &mut emails {
                    if let Some(item) = item.as_object_mut() {
                        _ = item.insert("value".into(), Value::String(replacement.clone()));
                    }
                }
                self.set_emails(&Value::Array(emails))?;
            }
            _ => {
                if let Some((root, selector, sub)) = filtered(&relative)
                    && root.eq_ignore_ascii_case("emails")
                    && sub
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case("value"))
                {
                    match selector {
                        Selector::Type(kind) => {
                            let mut emails = self.emails.clone();
                            if remove {
                                emails
                                    .retain(|item| get_string(item, "type") != Some(kind.as_str()));
                                if emails.len() == self.emails.len() {
                                    return Ok(());
                                }
                            } else {
                                let replacement = email(value)?;
                                if emails
                                    .iter()
                                    .any(|item| get_string(item, "type") == Some(kind.as_str()))
                                {
                                    for item in &mut emails {
                                        if get_string(item, "type") == Some(kind.as_str())
                                            && let Some(item) = item.as_object_mut()
                                        {
                                            _ = item.insert(
                                                "value".into(),
                                                Value::String(replacement.clone()),
                                            );
                                        }
                                    }
                                } else {
                                    emails.push(Value::Object(
                                        [
                                            ("value".into(), Value::String(replacement)),
                                            ("type".into(), Value::String(kind)),
                                            ("primary".into(), Value::Bool(false)),
                                        ]
                                        .into_iter()
                                        .collect(),
                                    ));
                                }
                            }
                            self.set_emails(&Value::Array(emails))?;
                        }
                        Selector::Primary(true) => {
                            if remove {
                                return Err(invalid("emails.value cannot be removed"));
                            }
                            let replacement = email(value)?;
                            let mut emails = self.emails.clone();
                            if !emails.iter().any(|item| {
                                item.get("primary").and_then(Value::as_bool) == Some(true)
                            }) {
                                return Err(error(
                                    "No primary email matches the PATCH path",
                                    "noTarget",
                                ));
                            }
                            for item in &mut emails {
                                if item.get("primary").and_then(Value::as_bool) == Some(true)
                                    && let Some(item) = item.as_object_mut()
                                {
                                    _ = item
                                        .insert("value".into(), Value::String(replacement.clone()));
                                }
                            }
                            self.set_emails(&Value::Array(emails))?;
                        }
                        Selector::Primary(false) => return Err(unsupported(path)),
                    }
                } else {
                    generic(&mut self.document, op, path, value)?;
                }
            }
        }
        Ok(())
    }
}
/// A User PATCH path resolved against the declared attributes.
enum ResolvedPath {
    EnterpriseRoot,
    Attribute {
        attribute: &'static Attribute,
        sub: Option<&'static Attribute>,
        selected: bool,
    },
}
fn resolve_path(path: &str) -> Option<ResolvedPath> {
    let canonical = relative(path);
    if canonical.eq_ignore_ascii_case("enterprise") {
        return Some(ResolvedPath::EnterpriseRoot);
    }
    let enterprise = prefix(&canonical, "enterprise.");
    let attributes = if enterprise.is_some() {
        attribute_names::enterprise()
    } else {
        attribute_names::user()
    };
    let relative = enterprise.unwrap_or(&canonical);
    let (root, selected, sub) = if let Some((root, _, sub)) = filtered(relative) {
        (root, true, sub)
    } else {
        let segments = relative.split('.').collect::<Vec<_>>();
        if segments.len() > 2 || segments.iter().any(|segment| segment.is_empty()) {
            return None;
        }
        (
            segments.first().copied().unwrap_or("").to_owned(),
            false,
            segments.get(1).map(|segment| (*segment).to_owned()),
        )
    };
    let attribute = attribute_names::find(attributes, &root)?;
    let sub = match sub {
        Some(name) => Some(attribute_names::find(&attribute.sub_attributes, &name)?),
        None => None,
    };
    if selected && !attribute.multi_valued {
        return None;
    }
    Some(ResolvedPath::Attribute {
        attribute,
        sub,
        selected,
    })
}
/// How a null value at a User PATCH path applies.
pub(super) fn null_target(path: &str) -> Target {
    if relative(path).eq_ignore_ascii_case("active") {
        return Target::NotNullable;
    }
    match resolve_path(path) {
        // Unsupported paths keep their original operation, which reports the error.
        None => Target::Value,
        // The URN joins its attributes with ":", and the `enterprise` alias with ".".
        Some(ResolvedPath::EnterpriseRoot) => Target::Merge {
            path: path.to_owned(),
            separator: if trim(path).eq_ignore_ascii_case("enterprise") {
                '.'
            } else {
                ':'
            },
        },
        Some(ResolvedPath::Attribute {
            attribute,
            sub,
            selected,
        }) => {
            if attribute.read_only || sub.is_some_and(|sub| sub.read_only) {
                Target::ReadOnly
            } else if sub.is_some() || !attribute.complex || selected {
                // Selected entries handle their own null keys, because a merged
                // value can change what the selector matches.
                Target::Value
            } else if attribute.multi_valued {
                Target::Entries
            } else {
                Target::Merge {
                    path: path.to_owned(),
                    separator: '.',
                }
            }
        }
    }
}
fn canonicalize_path_value(path: &str, value: &Value) -> Result<Value, String> {
    match resolve_path(path) {
        None => Ok(value.clone()),
        Some(ResolvedPath::EnterpriseRoot) => {
            attribute_names::canonicalize(value, attribute_names::enterprise())
        }
        Some(ResolvedPath::Attribute { attribute, sub, .. }) => {
            let attributes = sub.map_or(&attribute.sub_attributes, |sub| &sub.sub_attributes);
            if attributes.is_empty() {
                Ok(value.clone())
            } else {
                attribute_names::canonicalize(value, attributes)
            }
        }
    }
}
/// Rewrite a User PATCH value's keys to the names its target declares.
/// Pathless keys may be aliases or qualified paths, such as `manager` or
/// `name.givenName`, so each entry resolves through its own path.
pub(super) fn canonicalize_value(path: Option<&str>, value: &Value) -> Result<Value, String> {
    if let Some(path) = path {
        return canonicalize_path_value(path, value);
    }
    let resource =
        attribute_names::canonicalize_resource(attribute_names::Resource::User, value)?;
    let Value::Object(entries) = resource else {
        return Ok(resource);
    };
    entries
        .into_iter()
        .map(|(key, entry)| canonicalize_path_value(&key, &entry).map(|entry| (key, entry)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}
/// A null key in a value merged into a selected entry removes that sub-attribute.
fn without_nulls(value: &mut Map<String, Value>) {
    value.retain(|_, item| !matches!(item, Value::Null));
}
#[derive(Clone)]
enum Selector {
    Type(String),
    Primary(bool),
}
fn filtered(path: &str) -> Option<(String, Selector, Option<String>)> {
    let space = r"[\u{0009}-\u{000D}\u{0020}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}]";
    let token = r"[A-Za-z$][A-Za-z0-9_$-]*";
    let type_re=regex::Regex::new(&format!(r#"^({token}){space}*\[{space}*(?i-u:type){space}+(?i-u:eq){space}+"([^"]+)"{space}*\](?:{space}*\.{space}*({token}))?$"#)).ok()?;
    if let Some(values) = type_re.captures(path) {
        return Some((
            values.get(1)?.as_str().into(),
            Selector::Type(trim(values.get(2)?.as_str()).to_lowercase()),
            values.get(3).map(|value| value.as_str().into()),
        ));
    }
    let primary_re=regex::Regex::new(&format!(r#"^({token}){space}*\[{space}*(?i-u:primary){space}+(?i-u:eq){space}+"?((?i-u:true|false))"?{space}*\](?:{space}*\.{space}*({token}))?$"#)).ok()?;
    let values = primary_re.captures(path)?;
    Some((
        values.get(1)?.as_str().into(),
        Selector::Primary(values.get(2)?.as_str().eq_ignore_ascii_case("true")),
        values.get(3).map(|value| value.as_str().into()),
    ))
}
fn canonical(name: &str, enterprise: bool) -> Option<&'static str> {
    let fields = if enterprise {
        &[
            "employeeNumber",
            "costCenter",
            "organization",
            "division",
            "department",
            "manager",
        ][..]
    } else {
        &[
            "title",
            "userType",
            "preferredLanguage",
            "locale",
            "timezone",
            "phoneNumbers",
            "addresses",
            "roles",
            "entitlements",
            "name",
            "emails",
        ][..]
    };
    fields
        .iter()
        .copied()
        .find(|field| field.eq_ignore_ascii_case(name))
}
fn subattribute(root: &str, name: &str) -> Option<&'static str> {
    let names = match root {
        "manager" => &["value", "$ref"][..],
        "addresses" => &[
            "formatted",
            "streetAddress",
            "locality",
            "region",
            "postalCode",
            "country",
            "type",
            "primary",
        ][..],
        "phoneNumbers" => &["value", "type", "primary"][..],
        "roles" | "entitlements" => &["value", "display", "type", "primary"][..],
        _ => &[][..],
    };
    names
        .iter()
        .copied()
        .find(|field| field.eq_ignore_ascii_case(name))
}
fn manager(value: &Value) -> AuthResult<Option<Value>> {
    let value = scalar(value);
    if let Some(value) = value.as_str() {
        return Ok(Some(Value::Object(
            [("value".into(), Value::String(trim(value).into()))]
                .into_iter()
                .collect(),
        )));
    }
    let value = value
        .as_object()
        .ok_or_else(|| invalid("manager must contain value or $ref"))?;
    let mut output = Map::new();
    for key in ["value", "$ref"] {
        if let Some(value) = value.get(key) {
            _ = output.insert(
                key.into(),
                Value::String(string(value, &format!("manager.{key}"))?),
            );
        }
    }
    Ok((!output.is_empty()).then_some(Value::Object(output)))
}
fn enterprise(value: &Value) -> AuthResult<Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{ENTERPRISE_SCHEMA} must be an object")))?;
    let mut output = Map::new();
    for (key, value) in object {
        let Some(canonical) = canonical(key, true) else {
            return Err(unsupported(&format!("{ENTERPRISE_SCHEMA}:{key}")));
        };
        if canonical != key {
            continue;
        }
        if canonical == "manager" {
            if let Some(value) = manager(value)? {
                _ = output.insert(canonical.into(), value);
            }
        } else {
            _ = output.insert(canonical.into(), value.clone());
        }
    }
    Ok(output)
}
fn primary_value(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(primary_value),
        Value::Object(values) => values.get("primary").and_then(Value::as_bool) == Some(true),
        _ => false,
    }
}
fn normalize_primary(values: &mut [Value], preferred: Option<usize>) {
    if let Some(preferred) = preferred {
        for (index, value) in values.iter_mut().enumerate() {
            if index != preferred
                && value.get("primary").and_then(Value::as_bool) == Some(true)
                && let Some(value) = value.as_object_mut()
            {
                _ = value.insert("primary".into(), Value::Bool(false));
            }
        }
    }
}
fn additions(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .map_or_else(|| vec![value.clone()], <[Value]>::to_vec)
}
fn multivalue(
    container: &mut Map<String, Value>,
    root: &str,
    sub: Option<&str>,
    selector: Option<&Selector>,
    op: Kind,
    value: &Value,
    path: &str,
) -> AuthResult<()> {
    let mut current = container
        .get(root)
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    if selector.is_none() && sub.is_none() {
        if op == Kind::Remove {
            _ = container.shift_remove(root);
            return Ok(());
        }
        let added = additions(value);
        let primary = added
            .iter()
            .position(primary_value)
            .map(|index| index + if op == Kind::Add { current.len() } else { 0 });
        if op != Kind::Add {
            current.clear();
        }
        current.extend(added);
        normalize_primary(&mut current, primary);
        _ = container.insert(root.into(), Value::Array(current));
        return Ok(());
    }
    let matches = current
        .iter()
        .map(|item| match selector {
            Some(Selector::Type(kind)) => {
                get_string(item, "type").is_some_and(|value| trim(value).to_lowercase() == *kind)
            }
            Some(Selector::Primary(flag)) => {
                item.get("primary").and_then(Value::as_bool) == Some(*flag)
            }
            None => true,
        })
        .collect::<Vec<_>>();
    let first = matches.iter().position(|value| *value);
    if first.is_none() {
        if op == Kind::Remove {
            return Ok(());
        }
        let mut added = if let Some(sub) = sub {
            vec![Value::Object(
                [(sub.into(), value.clone())].into_iter().collect(),
            )]
        } else {
            // Clearing fields of an entry that does not exist is a no-op, like a remove.
            let added = additions(value)
                .into_iter()
                .filter_map(|mut item| {
                    if let Some(fields) = item.as_object_mut() {
                        let assigned = fields.len();
                        without_nulls(fields);
                        if fields.is_empty() && assigned > 0 {
                            return None;
                        }
                    }
                    Some(item)
                })
                .collect::<Vec<_>>();
            if added.is_empty() {
                return Ok(());
            }
            added
        };
        for item in &mut added {
            if let Some(item) = item.as_object_mut() {
                match selector {
                    Some(Selector::Type(kind)) => {
                        _ = item.insert("type".into(), Value::String(kind.clone()));
                    }
                    Some(Selector::Primary(flag)) => {
                        _ = item.insert("primary".into(), Value::Bool(*flag));
                    }
                    None => {}
                }
            }
        }
        let preferred = if sub.is_some_and(|sub| sub.eq_ignore_ascii_case("primary"))
            && value.as_bool() == Some(true)
        {
            Some(current.len())
        } else {
            added
                .iter()
                .position(primary_value)
                .map(|index| index + current.len())
        };
        current.extend(added);
        normalize_primary(&mut current, preferred);
    } else if let Some(sub) = sub {
        for (item, matches) in current.iter_mut().zip(matches.iter()) {
            if *matches {
                let item = item
                    .as_object_mut()
                    .ok_or_else(|| invalid(format!("{root} must contain objects")))?;
                if op == Kind::Remove {
                    _ = item.shift_remove(sub);
                } else {
                    _ = item.insert(sub.into(), value.clone());
                }
            }
        }
        normalize_primary(
            &mut current,
            if sub.eq_ignore_ascii_case("primary") && value.as_bool() == Some(true)
                || primary_value(value)
            {
                first
            } else {
                None
            },
        );
    } else if op == Kind::Remove {
        current = current
            .into_iter()
            .zip(matches)
            .filter_map(|(item, keep)| (!keep).then_some(item))
            .collect();
    } else {
        let added = additions(value);
        let replacement = if added.len() == 1 {
            added.first().and_then(Value::as_object)
        } else {
            None
        }
        .ok_or_else(|| invalid(format!("User PATCH path {path} requires one complex value")))?;
        for (item, matches) in current.iter_mut().zip(matches.iter()) {
            if *matches {
                let item = item
                    .as_object_mut()
                    .ok_or_else(|| invalid(format!("{root} must contain objects")))?;
                item.extend(replacement.clone());
                without_nulls(item);
            }
        }
        normalize_primary(
            &mut current,
            if replacement.get("primary").and_then(Value::as_bool) == Some(true) {
                first
            } else {
                None
            },
        );
    }
    if current.is_empty() && op == Kind::Remove && sub.is_none() {
        _ = container.shift_remove(root);
    } else {
        _ = container.insert(root.into(), Value::Array(current));
    }
    Ok(())
}
fn declaration(document: &mut Map<String, Value>, declared: bool) {
    let mut schemas = document
        .get("schemas")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    schemas.retain(|value| value.as_str() != Some(ENTERPRISE_SCHEMA));
    if declared {
        schemas.push(Value::String(ENTERPRISE_SCHEMA.into()));
    }
    _ = document.insert("schemas".into(), Value::Array(schemas));
}
fn clean_extension(document: &mut Map<String, Value>) {
    if document
        .get(ENTERPRISE_SCHEMA)
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
    {
        _ = document.shift_remove(ENTERPRISE_SCHEMA);
        declaration(document, false);
    }
}
fn generic(
    document: &mut Map<String, Value>,
    op: Kind,
    path: &str,
    value: &Value,
) -> AuthResult<()> {
    let relative = relative(path);
    let enterprise_path =
        relative.eq_ignore_ascii_case("enterprise") || prefix(&relative, "enterprise.").is_some();
    if relative.eq_ignore_ascii_case("enterprise") {
        if op == Kind::Remove {
            _ = document.shift_remove(ENTERPRISE_SCHEMA);
            declaration(document, false);
            return Ok(());
        }
        let patch = enterprise(value)?;
        let extension = document
            .entry(ENTERPRISE_SCHEMA.into())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| invalid("Enterprise User must be an object"))?;
        for (key, value) in patch {
            if key == "manager" {
                let mut existing = extension
                    .get("manager")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                if let Some(value) = value.as_object() {
                    existing.extend(value.clone());
                }
                _ = extension.insert(key, Value::Object(existing));
            } else {
                _ = extension.insert(key, value);
            }
        }
        declaration(document, true);
        return Ok(());
    }
    let relative = prefix(&relative, "enterprise.").unwrap_or(&relative);
    let filtered = filtered(relative);
    let (root, selector, sub) = if let Some((root, selector, sub)) = filtered {
        (root, Some(selector), sub)
    } else {
        let segments = relative.split('.').collect::<Vec<_>>();
        if segments.len() > 2 || segments.iter().any(|value| value.is_empty()) {
            return Err(unsupported(path));
        }
        (
            segments.first().copied().unwrap_or("").into(),
            None,
            segments.get(1).map(|value| (*value).into()),
        )
    };
    let root = canonical(&root, enterprise_path).ok_or_else(|| unsupported(path))?;
    if matches!(root, "name" | "emails") {
        return Err(unsupported(path));
    }
    let sub = sub
        .as_deref()
        .map(|name| subattribute(root, name).ok_or_else(|| unsupported(path)))
        .transpose()?;
    let multi = matches!(
        root,
        "phoneNumbers" | "addresses" | "roles" | "entitlements"
    );
    if selector.is_some() && !multi {
        return Err(error(
            format!("User PATCH path {path} is not a multi-valued attribute"),
            "invalidPath",
        ));
    }
    if enterprise_path && op != Kind::Remove {
        declaration(document, true);
        _ = document
            .entry(ENTERPRISE_SCHEMA.into())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let container = if enterprise_path {
        let Some(container) = document
            .get_mut(ENTERPRISE_SCHEMA)
            .and_then(Value::as_object_mut)
        else {
            return Ok(());
        };
        container
    } else {
        &mut *document
    };
    if multi {
        multivalue(container, root, sub, selector.as_ref(), op, value, path)?;
    } else if let Some(sub) = sub {
        if op == Kind::Remove {
            if let Some(object) = container.get_mut(root).and_then(Value::as_object_mut) {
                _ = object.shift_remove(sub);
                if object.is_empty() {
                    _ = container.shift_remove(root);
                }
            }
        } else {
            let object = container
                .entry(root.into())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| invalid(format!("{root} must be an object")))?;
            _ = object.insert(sub.into(), value.clone());
        }
    } else if op == Kind::Remove {
        _ = container.shift_remove(root);
    } else if enterprise_path && root == "manager" {
        if value.as_str() == Some("") {
            _ = container.shift_remove(root);
        } else {
            let parsed =
                manager(value)?.ok_or_else(|| invalid("manager must contain value or $ref"))?;
            let object = container
                .entry(root.into())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| invalid("manager must be an object"))?;
            if let Some(values) = parsed.as_object() {
                object.extend(values.clone());
            }
        }
    } else {
        _ = container.insert(root.into(), value.clone());
    }
    clean_extension(document);
    Ok(())
}
// Source clones PATCH records by their own enumerable properties. A trusted
// Date has none; serializing it to an ISO string changes mutation semantics.
fn clone_patch_value(value: &Value) -> Value {
    match value {
        Value::Date(_) => Value::Object(Map::new()),
        Value::Array(values) => Value::Array(values.iter().map(clone_patch_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), clone_patch_value(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}
pub(super) fn apply(
    source: &ScimUserRecord,
    operations: &[Operation],
) -> AuthResult<Option<Profile>> {
    let attributes = user_attributes::read(source).ok_or_else(|| AuthError::Api {
        status: 500,
        code: None,
        message: "Stored SCIM User attribute state is invalid".into(),
    })?;
    let typed_attributes = Value::from(attributes.clone());
    let mut document = typed_attributes.as_object().cloned().unwrap_or_default();
    if let Some(extension) = document.shift_remove("enterprise") {
        _ = document.insert(ENTERPRISE_SCHEMA.into(), extension);
    }
    let mut state = State {
        document,
        name: typed_attributes
            .get("name")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
        emails: typed_attributes
            .get("emails")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default(),
        user_name: source.user_name.clone(),
        display_name: source.display_name.clone(),
        external_id: source.external_id.clone(),
        active: source.active,
    };
    for operation in &super::null_attributes::expand(operations, null_target)? {
        let value = operation
            .value
            .as_ref()
            .map_or(Value::Null, clone_patch_value);
        if let Some(path) = operation
            .path
            .as_deref()
            .map(trim)
            .filter(|path| !path.is_empty())
        {
            state.apply(operation.op, path, &value)?;
        } else {
            if operation.op == Kind::Remove {
                return Err(error(
                    "A remove User PATCH operation requires a path",
                    "noTarget",
                ));
            }
            let values = value
                .as_object()
                .ok_or_else(|| invalid("A pathless User PATCH value must be an object"))?;
            for (key, value) in values {
                state.apply(operation.op, key, value)?;
            }
        }
    }
    _ = state
        .document
        .insert("userName".into(), Value::String(state.user_name));
    _ = state
        .document
        .insert("displayName".into(), Value::String(state.display_name));
    _ = state
        .document
        .insert("active".into(), Value::Bool(state.active));
    _ = state
        .document
        .insert("name".into(), Value::Object(state.name));
    _ = state
        .document
        .insert("emails".into(), Value::Array(state.emails));
    if let Some(external) = state.external_id {
        _ = state
            .document
            .insert("externalId".into(), Value::String(external));
    } else {
        _ = state.document.shift_remove("externalId");
    }
    let document = Value::Object(state.document);
    if let Some(detail) = super::user_input::patch_validation_error(&document) {
        return Err(invalid(detail));
    }
    let profile = user_profile::parse(&document.to_json_value()?)
        .ok_or_else(|| invalid("The patched User resource is invalid"))?;
    let changed = source.user_name != profile.user_name
        || source.primary_email != profile.primary_email
        || source.display_name != profile.display_name
        || source.active != profile.active
        || source.external_id != profile.external_id
        || attributes != profile.attributes;
    Ok(changed.then_some(profile))
}
