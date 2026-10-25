//! RFC 7643 section 2.1 case-insensitive attribute names for SCIM requests.
//!
//! Request keys are rewritten to the names the resource schema declares, so the
//! rest of the plugin can match attributes exactly. Unknown keys are kept.
use super::user_attributes::{ENTERPRISE_SCHEMA, USER_SCHEMA};
use alibi_core::utils::json::JsValue;
use indexmap::IndexMap;
use std::sync::LazyLock;

/// A declared attribute and the schema facts PATCH targets depend on.
pub(super) struct Attribute {
    pub(super) name: String,
    pub(super) complex: bool,
    pub(super) multi_valued: bool,
    pub(super) read_only: bool,
    pub(super) sub_attributes: Vec<Attribute>,
}
struct Schemas {
    user: Vec<Attribute>,
    enterprise: Vec<Attribute>,
    group: Vec<Attribute>,
}
fn attributes(raw: &serde_json::Value) -> Vec<Attribute> {
    raw.as_array()
        .map(|attributes| {
            attributes
                .iter()
                .map(|attribute| Attribute {
                    name: attribute["name"].as_str().unwrap_or_default().to_owned(),
                    complex: attribute["type"] == "complex",
                    multi_valued: attribute["multiValued"] == true,
                    read_only: attribute["mutability"] == "readOnly",
                    sub_attributes: self::attributes(&attribute["subAttributes"]),
                })
                .collect()
        })
        .unwrap_or_default()
}
static SCHEMAS: LazyLock<Schemas> = LazyLock::new(|| {
    let schemas: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("schemas.json")).unwrap_or_default();
    let find = |id: &str| {
        schemas
            .iter()
            .find(|schema| schema["id"] == id)
            .map(|schema| attributes(&schema["attributes"]))
            .unwrap_or_default()
    };
    Schemas {
        user: find(USER_SCHEMA),
        enterprise: find(ENTERPRISE_SCHEMA),
        group: find(GROUP_SCHEMA),
    }
});
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// Attributes RFC 7643 section 3.1 defines on every resource.
const COMMON: [&str; 4] = ["schemas", "id", "externalId", "meta"];

pub(super) fn user() -> &'static [Attribute] {
    &SCHEMAS.user
}
pub(super) fn enterprise() -> &'static [Attribute] {
    &SCHEMAS.enterprise
}
pub(super) fn group_members() -> &'static [Attribute] {
    SCHEMAS
        .group
        .iter()
        .find(|attribute| attribute.name == "members")
        .map_or(&[], |attribute| attribute.sub_attributes.as_slice())
}
pub(super) fn find<'a>(attributes: &'a [Attribute], key: &str) -> Option<&'a Attribute> {
    let key = key.to_lowercase();
    attributes
        .iter()
        .find(|attribute| attribute.name.to_lowercase() == key)
}

/// The resource a request body describes.
#[derive(Clone, Copy)]
pub(super) enum Resource {
    User,
    Group,
}

fn record(
    value: &IndexMap<String, JsValue>,
    resource: Option<Resource>,
    attributes: &[Attribute],
) -> Result<IndexMap<String, JsValue>, String> {
    let mut output = IndexMap::new();
    for (key, entry) in value {
        let extension = matches!(resource, Some(Resource::User))
            .then_some(ENTERPRISE_SCHEMA)
            .filter(|id| id.eq_ignore_ascii_case(key));
        let common = resource
            .and(COMMON.iter().find(|name| name.eq_ignore_ascii_case(key)))
            .copied();
        let attribute = if extension.is_some() || common.is_some() {
            None
        } else {
            find(attributes, key)
        };
        let name = extension
            .or(common)
            .or_else(|| attribute.map(|attribute| attribute.name.as_str()))
            .unwrap_or(key);
        if output.contains_key(name) {
            return Err(format!(
                "{name} appears more than once with different letter case"
            ));
        }
        let entry = if extension.is_some() {
            canonicalize(entry, enterprise())?
        } else if let Some(attribute) = attribute.filter(|value| !value.sub_attributes.is_empty())
        {
            canonicalize(entry, &attribute.sub_attributes)?
        } else {
            entry.clone()
        };
        _ = output.insert(name.to_owned(), entry);
    }
    Ok(output)
}

/// Rewrite the keys of a complex value, or of each complex entry in an array,
/// to the declared sub-attribute names. Nested arrays are kept unchanged.
pub(super) fn canonicalize(value: &JsValue, attributes: &[Attribute]) -> Result<JsValue, String> {
    Ok(match value {
        JsValue::Object(entries) => JsValue::Object(record(entries, None, attributes)?),
        JsValue::Array(entries) => JsValue::Array(
            entries
                .iter()
                .map(|entry| match entry {
                    JsValue::Object(entries) => {
                        record(entries, None, attributes).map(JsValue::Object)
                    }
                    _ => Ok(entry.clone()),
                })
                .collect::<Result<_, _>>()?,
        ),
        _ => value.clone(),
    })
}

/// Rewrite a User or Group resource's attribute keys, including the
/// Enterprise User extension key. Fails when two keys name one attribute.
pub(super) fn canonicalize_resource(
    resource: Resource,
    value: &JsValue,
) -> Result<JsValue, String> {
    let JsValue::Object(entries) = value else {
        return Ok(value.clone());
    };
    let attributes = match resource {
        Resource::User => user(),
        Resource::Group => &SCHEMAS.group,
    };
    record(entries, Some(resource), attributes).map(JsValue::Object)
}

/// Rewrite each PATCH operation value's keys to the names its target declares.
pub(super) fn canonicalize_patch(
    body: &JsValue,
    value: impl Fn(Option<&str>, &JsValue) -> Result<JsValue, String>,
) -> Result<JsValue, String> {
    let JsValue::Object(fields) = body else {
        return Ok(body.clone());
    };
    let Some(JsValue::Array(operations)) = fields.get("Operations") else {
        return Ok(body.clone());
    };
    let mut rewritten = Vec::with_capacity(operations.len());
    for operation in operations {
        let JsValue::Object(entries) = operation else {
            rewritten.push(operation.clone());
            continue;
        };
        let path = match entries.get("path") {
            None => None,
            Some(JsValue::String(path)) => Some(alibi_core::utils::javascript::trim(path)),
            Some(_) => {
                rewritten.push(operation.clone());
                continue;
            }
        };
        let mut entries = entries.clone();
        if let Some(current) = entries.get("value") {
            let canonical = value(path.filter(|path| !path.is_empty()), current)?;
            _ = entries.insert("value".into(), canonical);
        }
        rewritten.push(JsValue::Object(entries));
    }
    let mut fields = fields.clone();
    _ = fields.insert("Operations".into(), JsValue::Array(rewritten));
    Ok(JsValue::Object(fields))
}

/// Rewrite a Group PATCH value; only pathless values and `members` declare keys.
pub(super) fn canonicalize_group_patch_value(
    path: Option<&str>,
    value: &JsValue,
) -> Result<JsValue, String> {
    let Some(path) = path else {
        return canonicalize_resource(Resource::Group, value);
    };
    if strip_group_prefix(path).eq_ignore_ascii_case("members") {
        canonicalize(value, group_members())
    } else {
        Ok(value.clone())
    }
}

/// Strip the core Group schema prefix from a PATCH path.
pub(super) fn strip_group_prefix(path: &str) -> &str {
    let path = alibi_core::utils::javascript::trim(path);
    let prefix = "urn:ietf:params:scim:schemas:core:2.0:Group:";
    path.get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .and_then(|_| path.get(prefix.len()..))
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> JsValue {
        alibi_core::utils::json::from_slice(raw.as_bytes()).unwrap()
    }

    #[test]
    fn rewrites_user_keys_and_rejects_case_variant_duplicates() {
        let canonical = canonicalize_resource(
            Resource::User,
            &parse(
                r#"{"UserName":"a","Emails":[{"Value":"a@example.com"}],"URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER":{"Manager":{"Value":"m"}},"unknown":1}"#,
            ),
        )
        .unwrap();
        assert_eq!(
            canonical,
            parse(
                r#"{"userName":"a","emails":[{"value":"a@example.com"}],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"m"}},"unknown":1}"#,
            )
        );
        assert_eq!(
            canonicalize_resource(Resource::User, &parse(r#"{"active":false,"Active":true}"#)),
            Err("active appears more than once with different letter case".into())
        );
    }
}
