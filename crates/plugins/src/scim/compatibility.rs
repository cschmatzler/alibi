//! Input-only normalization for the classic Entra Group marker.
use alibi_core::HttpMethod;
use alibi_core::utils::json::JsValue;
const LEGACY_GROUP: &str =
    "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";

pub(super) fn normalize_group(
    path: &str,
    method: &HttpMethod,
    body: &mut JsValue,
    enabled: bool,
) -> Result<bool, &'static str> {
    let Some((_, suffix)) = path.rsplit_once("/scim/v2/Groups") else {
        return Ok(false);
    };
    let create = method == &HttpMethod::Post && suffix.is_empty();
    let update = matches!(method, HttpMethod::Put | HttpMethod::Patch)
        && suffix
            .strip_prefix('/')
            .is_some_and(|id| !id.is_empty() && !id.contains('/'));
    if !create && !update {
        return Ok(false);
    }
    let JsValue::Object(fields) = body else {
        return Ok(false);
    };
    if fields.contains_key(LEGACY_GROUP) {
        return Err("The Microsoft Entra Group compatibility schema cannot contain attributes");
    }
    if !create || !enabled {
        return Ok(false);
    }
    let Some(JsValue::Array(schemas)) = fields.get_mut("schemas") else {
        return Ok(false);
    };
    let count = schemas
        .iter()
        .filter(|schema| schema.as_str() == Some(LEGACY_GROUP))
        .count();
    if count == 0 {
        return Ok(false);
    }
    if count != 1 {
        return Err("The Microsoft Entra Group compatibility schema must not be duplicated");
    }
    schemas.retain(|schema| schema.as_str() != Some(LEGACY_GROUP));
    Ok(true)
}
