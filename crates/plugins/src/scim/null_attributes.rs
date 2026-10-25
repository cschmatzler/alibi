//! RFC 7643 section 2.5 JSON `null` as an unassigned SCIM attribute.
//!
//! POST and PUT bodies omit null attributes. In PATCH an omitted attribute is
//! left unchanged, so a null value becomes an explicit removal instead.
use alibi_core::{
    AuthError, AuthResult,
    store::{ScimGroupPatchKind as Kind, ScimGroupPatchOperation as Operation},
    utils::{javascript::trim, json::JsValue},
};
use indexmap::IndexMap;

/// Deeper values are left as-is for schema validation to reject.
const MAX_DEPTH: usize = 32;

/// How a PATCH value at a path applies to the stored resource.
pub(super) enum Target {
    /// A complex value merged into the current one; omitted keys are kept.
    /// Sub-attribute paths join the parent path with the separator.
    Merge { path: String, separator: char },
    /// Multi-valued entries that are added or replaced whole.
    Entries,
    /// A read-only attribute the service provider ignores.
    ReadOnly,
    /// An attribute where null is never a valid value.
    NotNullable,
    /// A value the target applies as given; a null value removes the target.
    Value,
}
impl Target {
    fn sub_path(&self, attribute: &str) -> String {
        match self {
            Self::Merge { path, separator } => format!("{path}{separator}{attribute}"),
            _ => attribute.to_owned(),
        }
    }
}

fn strip(value: &JsValue, depth: usize) -> JsValue {
    if depth > MAX_DEPTH {
        return value.clone();
    }
    match value {
        JsValue::Array(entries) => {
            JsValue::Array(entries.iter().map(|entry| strip(entry, depth + 1)).collect())
        }
        JsValue::Object(entries) => {
            let mut output = IndexMap::new();
            for (key, entry) in entries {
                if matches!(entry, JsValue::Null) {
                    continue;
                }
                let stripped = strip(entry, depth + 1);
                // A complex attribute whose sub-attributes were all null is unassigned too.
                if matches!(&stripped, JsValue::Object(fields) if fields.is_empty())
                    && stripped != *entry
                {
                    continue;
                }
                _ = output.insert(key.clone(), stripped);
            }
            JsValue::Object(output)
        }
        _ => value.clone(),
    }
}

/// Omit null attributes from a resource sent with POST or PUT. A root
/// `active: null` is kept so validation still rejects it: an omitted `active`
/// defaults to `true` and would reactivate the User.
pub(super) fn strip_resource(resource: &JsValue) -> JsValue {
    let JsValue::Object(fields) = resource else {
        return resource.clone();
    };
    let mut stripped = strip(resource, 0);
    if matches!(fields.get("active"), Some(JsValue::Null))
        && let JsValue::Object(output) = &mut stripped
    {
        _ = output.insert("active".into(), JsValue::Null);
    }
    stripped
}

/// Microsoft Entra may send a single complex value as a one-element array.
fn single_record(value: &JsValue) -> Option<&IndexMap<String, JsValue>> {
    match value {
        JsValue::Object(fields) => Some(fields),
        JsValue::Array(entries) if entries.len() == 1 => match entries.first() {
            Some(JsValue::Object(fields)) => Some(fields),
            _ => None,
        },
        _ => None,
    }
}

fn removal(path: String) -> Operation {
    Operation {
        op: Kind::Remove,
        path: Some(path),
        value: None,
    }
}

/// The operations a null value at `path` becomes; fails when null is invalid.
fn null_operations(path: String, target: &Target) -> AuthResult<Vec<Operation>> {
    match target {
        Target::ReadOnly => Ok(Vec::new()),
        Target::NotNullable => Err(AuthError::Api {
            status: 400,
            code: Some("invalidValue".into()),
            message: format!("{path} cannot be null"),
        }),
        _ => Ok(vec![removal(path)]),
    }
}

fn split(
    value: &IndexMap<String, JsValue>,
    parent: Option<&Target>,
    resolve: &impl Fn(&str) -> Target,
    removals: &mut Vec<Operation>,
) -> AuthResult<IndexMap<String, JsValue>> {
    let mut kept = IndexMap::new();
    for (attribute, entry) in value {
        if !matches!(
            entry,
            JsValue::Null | JsValue::Object(_) | JsValue::Array(_)
        ) {
            _ = kept.insert(attribute.clone(), entry.clone());
            continue;
        }
        let path = parent.map_or_else(|| attribute.clone(), |parent| parent.sub_path(attribute));
        let target = resolve(&path);
        if matches!(entry, JsValue::Null) {
            removals.extend(null_operations(path, &target)?);
            continue;
        }
        if let Target::Merge { .. } = target
            && let Some(record) = single_record(entry)
        {
            let nested = split(record, Some(&target), resolve, removals)?;
            if !nested.is_empty() || record.is_empty() {
                let nested = JsValue::Object(nested);
                _ = kept.insert(
                    attribute.clone(),
                    if matches!(entry, JsValue::Array(_)) {
                        JsValue::Array(vec![nested])
                    } else {
                        nested
                    },
                );
            }
            continue;
        }
        _ = kept.insert(
            attribute.clone(),
            if matches!(target, Target::Entries) {
                strip(entry, 0)
            } else {
                entry.clone()
            },
        );
    }
    Ok(kept)
}

fn expand_operation(
    operation: &Operation,
    resolve: &impl Fn(&str) -> Target,
) -> AuthResult<Vec<Operation>> {
    if operation.op == Kind::Remove {
        return Ok(vec![operation.clone()]);
    }
    let path = operation
        .path
        .as_deref()
        .map(trim)
        .filter(|path| !path.is_empty());
    let target = path.map(resolve);
    if let (Some(path), Some(target)) = (path, &target)
        && matches!(operation.value, Some(JsValue::Null))
    {
        return null_operations(path.to_owned(), target);
    }
    if matches!(target, Some(Target::Entries)) {
        let mut stripped = operation.clone();
        stripped.value = operation.value.as_ref().map(|value| strip(value, 0));
        return Ok(vec![stripped]);
    }
    let merge = matches!(target, Some(Target::Merge { .. }));
    if path.is_some() && !merge {
        return Ok(vec![operation.clone()]);
    }
    let record = match operation.value.as_ref() {
        Some(value) if merge => single_record(value),
        Some(JsValue::Object(fields)) => Some(fields),
        _ => None,
    };
    let Some(record) = record else {
        return Ok(vec![operation.clone()]);
    };
    let mut removals = Vec::new();
    let value = split(record, target.as_ref(), resolve, &mut removals)?;
    // An operation whose value was empty to begin with still fails or no-ops as before.
    let mut operations = Vec::new();
    if !value.is_empty() || record.is_empty() {
        let mut kept = operation.clone();
        kept.value = Some(if matches!(operation.value, Some(JsValue::Array(_))) {
            JsValue::Array(vec![JsValue::Object(value)])
        } else {
            JsValue::Object(value)
        });
        operations.push(kept);
    }
    operations.extend(removals);
    Ok(operations)
}

/// Rewrite add and replace operations so a null value removes its target.
/// Removals run after the operation's other values, so derived values such as
/// `name.formatted` see the update.
pub(super) fn expand(
    operations: &[Operation],
    resolve: impl Fn(&str) -> Target,
) -> AuthResult<Vec<Operation>> {
    let mut expanded = Vec::with_capacity(operations.len());
    for operation in operations {
        expanded.extend(expand_operation(operation, &resolve)?);
    }
    Ok(expanded)
}

/// Group targets: `members` holds whole entries; `schemas` and `meta` are ignored.
pub(super) fn group_target(path: &str) -> Target {
    match super::attribute_names::strip_group_prefix(path)
        .to_lowercase()
        .as_str()
    {
        "members" => Target::Entries,
        "schemas" | "meta" => Target::ReadOnly,
        _ => Target::Value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> JsValue {
        alibi_core::utils::json::from_slice(raw.as_bytes()).unwrap()
    }

    #[test]
    fn strips_null_attributes_but_keeps_root_active() {
        assert_eq!(
            strip_resource(&parse(
                r#"{"title":null,"name":{"middleName":null},"emails":[{"value":"a","type":null},null],"active":null}"#
            )),
            parse(r#"{"emails":[{"value":"a"},null],"active":null}"#)
        );
    }

    #[test]
    fn expands_pathless_null_values_into_trailing_removals() {
        let operations = expand(
            &[Operation {
                op: Kind::Replace,
                path: None,
                value: Some(parse(
                    r#"{"externalId":null,"schemas":null,"displayName":"Platform","members":[{"value":"u","display":null}]}"#,
                )),
            }],
            group_target,
        )
        .unwrap();
        let kept = Some(parse(
            r#"{"displayName":"Platform","members":[{"value":"u"}]}"#,
        ));
        assert!(matches!(
            operations.as_slice(),
            [operation, removal]
                if operation.value == kept
                    && removal.op == Kind::Remove
                    && removal.path.as_deref() == Some("externalId")
        ));
    }
}
