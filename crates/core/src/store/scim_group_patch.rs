//! Executable Group PATCH plans shared by the durable adapters.
use super::{ReplaceScimGroup, ScimGroupRecord};
use crate::{
    AuthError, AuthResult,
    utils::{javascript::trim, json::JsValue},
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScimGroupPatchKind {
    Add,
    Remove,
    Replace,
}
#[derive(Clone)]
pub struct ScimGroupPatchOperation {
    pub op: ScimGroupPatchKind,
    pub path: Option<String>,
    pub value: Option<JsValue>,
}
#[derive(Clone)]
pub enum ScimGroupPatch {
    Incremental {
        desired: Vec<(String, bool)>,
        validate: Vec<String>,
    },
    Full(Vec<ScimGroupPatchOperation>),
}
fn error(detail: impl Into<String>, kind: &str) -> AuthError {
    AuthError::Api {
        status: 400,
        code: Some(kind.into()),
        message: detail.into(),
    }
}
fn normalized_path(path: &str) -> &str {
    let path = trim(path);
    let prefix = "urn:ietf:params:scim:schemas:core:2.0:Group:";
    path.get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .and_then(|_| path.get(prefix.len()..))
        .unwrap_or(path)
}
fn member_path(path: &str) -> Option<String> {
    let space = r"[\u{0009}-\u{000D}\u{0020}\u{00A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}]";
    let pattern = format!(
        r#"^(?i-u:members){space}*\[{space}*(?i-u:value){space}+(?i-u:eq){space}+("(?:\\.|[^"\\])*"){space}*\]$"#
    );
    let regex = regex::Regex::new(&pattern).ok()?;
    let capture = regex.captures(normalized_path(path))?.get(1)?;
    let value = serde_json::from_str::<String>(capture.as_str()).ok()?;
    (!value.is_empty()).then_some(value)
}
fn members(value: Option<&JsValue>) -> AuthResult<Vec<String>> {
    let Some(JsValue::Array(entries)) = value else {
        return Err(error("members must be an array", "invalidValue"));
    };
    cardinality(entries.len())?;
    let mut ids = Vec::new();
    for entry in entries {
        let Some(JsValue::Object(entry)) = Some(entry) else {
            return Err(error(
                "Group members must reference a SCIM User",
                "invalidValue",
            ));
        };
        let Some(id) = entry
            .get("value")
            .and_then(JsValue::as_str)
            .filter(|value| !trim(value).is_empty())
        else {
            return Err(error(
                "Group members must reference a SCIM User",
                "invalidValue",
            ));
        };
        if entry
            .get("type")
            .and_then(JsValue::as_str)
            .is_some_and(|value| !value.eq_ignore_ascii_case("user"))
        {
            return Err(error(
                "Group members must reference a SCIM User",
                "invalidValue",
            ));
        }
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.into());
        }
    }
    Ok(ids)
}
/// Enforce the reference's direct-member cap after a planned delta.
/// # Errors
/// Returns a SCIM invalidValue error when the cap would be exceeded.
pub fn check_scim_group_cardinality(count: usize) -> AuthResult<()> {
    cardinality(count)
}
fn cardinality(count: usize) -> AuthResult<()> {
    if count > 1000 {
        Err(error(
            "Groups cannot contain more than 1000 direct members",
            "invalidValue",
        ))
    } else {
        Ok(())
    }
}
/// Select the incremental fast path without dropping validation of overwritten adds.
/// # Errors
/// Returns a SCIM error for malformed incremental member values.
pub fn prepare_scim_group_patch(
    operations: Vec<ScimGroupPatchOperation>,
) -> AuthResult<ScimGroupPatch> {
    let mut desired = Vec::<(String, bool)>::new();
    let mut validate = Vec::new();
    for operation in &operations {
        let Some(path) = operation
            .path
            .as_deref()
            .map(trim)
            .filter(|path| !path.is_empty())
        else {
            return Ok(ScimGroupPatch::Full(operations));
        };
        let (ids, wanted) = if normalized_path(path).eq_ignore_ascii_case("members") {
            if operation.op == ScimGroupPatchKind::Replace || operation.value.is_none() {
                return Ok(ScimGroupPatch::Full(operations));
            }
            (
                members(operation.value.as_ref())?,
                operation.op == ScimGroupPatchKind::Add,
            )
        } else if operation.op == ScimGroupPatchKind::Remove {
            let Some(id) = member_path(path) else {
                return Ok(ScimGroupPatch::Full(operations));
            };
            (vec![id], false)
        } else {
            return Ok(ScimGroupPatch::Full(operations));
        };
        for id in ids {
            if wanted && !validate.contains(&id) {
                validate.push(id.clone());
            }
            if let Some((_, value)) = desired.iter_mut().find(|(existing, _)| *existing == id) {
                *value = wanted;
            } else {
                desired.push((id, wanted));
            }
        }
    }
    Ok(ScimGroupPatch::Incremental { desired, validate })
}
fn scalar(value: Option<&JsValue>, attribute: &str) -> AuthResult<String> {
    let value = match value {
        Some(JsValue::Array(values)) if values.len() == 1 => values.first(),
        other => other,
    };
    value
        .and_then(JsValue::as_str)
        .map(trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            error(
                format!("{attribute} must be a non-empty string"),
                "invalidValue",
            )
        })
}
fn attribute(
    op: ScimGroupPatchKind,
    path: &str,
    value: Option<&JsValue>,
    name: &mut String,
    external: &mut Option<String>,
) -> AuthResult<()> {
    let normalized = normalized_path(path).to_lowercase();
    if matches!(normalized.as_str(), "id" | "schemas" | "meta") || normalized.starts_with("meta.") {
        return Err(error(format!("{path} is read-only"), "mutability"));
    }
    match normalized.as_str() {
        "displayname" => {
            if op == ScimGroupPatchKind::Remove {
                return Err(error(
                    "displayName is required and cannot be removed",
                    "mutability",
                ));
            }
            *name = scalar(value, "displayName")?;
        }
        "externalid" => {
            *external = if op == ScimGroupPatchKind::Remove {
                None
            } else {
                Some(scalar(value, "externalId")?)
            }
        }
        _ => return Err(error("Unsupported Group PATCH path", "invalidPath")),
    }
    Ok(())
}
fn scoped_key(parts: &[&str]) -> AuthResult<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(parts)?)))
}
/// Apply a full plan to the Group snapshot read under its mutation fence.
/// # Errors
/// Returns the reference's mutability, noTarget, invalidPath, and invalidValue errors.
pub fn apply_scim_group_patch(
    group: &ScimGroupRecord,
    current: &[String],
    operations: &[ScimGroupPatchOperation],
) -> AuthResult<ReplaceScimGroup> {
    let mut ids = current.iter().fold(Vec::new(), |mut ids, id| {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
        ids
    });
    let mut name = group.display_name.clone();
    let mut external = group.external_id.clone();
    for operation in operations {
        let path = operation
            .path
            .as_deref()
            .map(trim)
            .filter(|path| !path.is_empty());
        let Some(path) = path else {
            if operation.op == ScimGroupPatchKind::Remove {
                return Err(error(
                    "A pathless remove operation has no target",
                    "noTarget",
                ));
            }
            // The reference treats Date as a record, then iterates its own
            // enumerable properties. A trusted Date has none.
            if matches!(operation.value, Some(JsValue::Date(_))) {
                continue;
            }
            let Some(JsValue::Object(values)) = operation.value.as_ref() else {
                return Err(error(
                    "A pathless Group PATCH value must be an object",
                    "invalidValue",
                ));
            };
            for (key, value) in values {
                match key.to_lowercase().as_str() {
                    "id" => {
                        if value.as_str() != Some(group.id.as_str()) {
                            return Err(error("A Group PATCH cannot change id", "mutability"));
                        }
                    }
                    "schemas" | "meta" => {}
                    "members" => {
                        let added = members(Some(value))?;
                        if operation.op == ScimGroupPatchKind::Replace {
                            ids.clear();
                        }
                        for id in added {
                            if !ids.contains(&id) {
                                ids.push(id);
                            }
                        }
                    }
                    _ => attribute(operation.op, key, Some(value), &mut name, &mut external)?,
                }
            }
            continue;
        };
        if normalized_path(path).eq_ignore_ascii_case("members") {
            if operation.op == ScimGroupPatchKind::Remove && operation.value.is_none() {
                ids.clear();
                continue;
            }
            let requested = members(operation.value.as_ref())?;
            if operation.op == ScimGroupPatchKind::Replace {
                ids.clear();
            }
            for id in requested {
                if operation.op == ScimGroupPatchKind::Remove {
                    ids.retain(|existing| *existing != id);
                } else if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            continue;
        }
        if operation.op == ScimGroupPatchKind::Remove
            && let Some(id) = member_path(path)
        {
            ids.retain(|existing| *existing != id);
            continue;
        }
        attribute(
            operation.op,
            path,
            operation.value.as_ref(),
            &mut name,
            &mut external,
        )?;
    }
    cardinality(ids.len())?;
    Ok(ReplaceScimGroup {
        connection_id: group.connection_id.clone(),
        provisioning_domain_id: group.provisioning_domain_id.clone(),
        display_name_key: scoped_key(&[
            "scim-group-display-name",
            &group.connection_id,
            &name.to_lowercase(),
        ])?,
        external_id_key: external
            .as_ref()
            .filter(|value| !value.is_empty())
            .map(|value| scoped_key(&["scim-group-external-id", &group.connection_id, value]))
            .transpose()?,
        display_name: name,
        external_id: external,
        member_ids: ids,
    })
}
