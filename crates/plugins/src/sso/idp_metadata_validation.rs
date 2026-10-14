//! Identity-provider metadata admission, including typed service descriptors.
use super::{AuthError, AuthResult, JsValue};
use crate::authentication_helpers::{JsonField, JsonFieldKind, json_type};
const ROOT: &str = "body.samlConfig.idpMetadata";
pub(super) fn validate(input: Option<&JsValue>, partial: bool) -> AuthResult<JsValue> {
    parse(input, partial).map_err(|error| {
        let refinement = matches!(&error, AuthError::Api {message,..} if message.ends_with("Invalid URL") || message.contains("Too small:"));
        if partial || refinement { error } else {
            crate::endpoint::validation(format!("[{ROOT}] idpMetadata.entityID is required when IdP metadata XML is not provided"))
        }
    })
}
fn parse(input: Option<&JsValue>, partial: bool) -> AuthResult<JsValue> {
    let parsed = crate::endpoint::validate_fields(
        input,
        ROOT,
        &[
            JsonField::string("privateKey", false),
            JsonField::string("privateKeyPass", false),
            JsonField {
                name: "isAssertionEncrypted",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
            JsonField::string("encPrivateKey", false),
            JsonField::string("encPrivateKeyPass", false),
            JsonField::string("metadata", false),
            JsonField::string("entityID", false),
        ],
    )?;
    let input = input
        .and_then(JsValue::as_object)
        .ok_or_else(|| crate::endpoint::validation("Invalid IdP metadata"))?;
    let mut parsed_fields = parsed
        .as_object()
        .cloned()
        .ok_or_else(|| crate::endpoint::validation("Invalid IdP metadata"))?;
    if let Some(cert) = input.get("cert") {
        match cert {
            JsValue::String(_) => {}
            JsValue::Array(values) if values.is_empty() => {
                return Err(crate::endpoint::validation(format!(
                    "[{ROOT}.cert] Too small: expected array to have >=1 items"
                )));
            }
            JsValue::Array(values) if values.iter().all(|value| value.as_str().is_some()) => {}
            _ => {
                return Err(crate::endpoint::validation(format!(
                    "[{ROOT}.cert] Invalid input"
                )));
            }
        }
        _ = parsed_fields.insert("cert".into(), cert.clone());
    }
    let mut urls = Vec::new();
    for name in ["singleSignOnService", "singleLogoutService"] {
        if let Some(value) = input.get(name) {
            let values = value.as_array().ok_or_else(|| {
                crate::endpoint::validation(format!(
                    "[{ROOT}.{name}] Invalid input: expected array, received {}",
                    json_type(Some(value))
                ))
            })?;
            let mut services = Vec::new();
            for (index, value) in values.iter().enumerate() {
                let service = crate::endpoint::validate_fields(
                    Some(value),
                    &format!("{ROOT}.{name}.{index}"),
                    &[
                        JsonField::string("Binding", true),
                        JsonField::string("Location", true),
                    ],
                )?;
                if service
                    .get("Location")
                    .and_then(JsValue::as_str)
                    .is_some_and(|location| url::Url::parse(location).is_err())
                {
                    urls.push(format!("[{ROOT}.{name}.{index}.Location] Invalid URL"));
                }
                services.push(service);
            }
            _ = parsed_fields.insert(name.into(), JsValue::Array(services));
        }
    }
    let xml = input.get("metadata").and_then(JsValue::as_str);
    if xml == Some("") {
        return Err(crate::endpoint::validation(format!(
            "[{ROOT}.metadata] Too small: expected string to have >=1 characters"
        )));
    }
    let entity = input.get("entityID").and_then(JsValue::as_str);
    if (partial || xml.is_none()) && entity == Some("") {
        return Err(crate::endpoint::validation(format!(
            "[{ROOT}.entityID] Too small: expected string to have >=1 characters"
        )));
    }
    if !partial && xml.is_none() && entity.is_none() {
        return Err(crate::endpoint::validation("Missing IdP authority"));
    }
    if !urls.is_empty() {
        return Err(crate::endpoint::validation(urls.join("; ")));
    }
    Ok(JsValue::Object(parsed_fields))
}
