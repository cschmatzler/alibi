//! Manual SAML registration schema and authority admission.
use super::{AuthError, AuthResult, JsValue, Value, api, json};
use crate::authentication_helpers::{JsonField, JsonFieldKind};
const STRINGS: &[&str] = &[
    "entryPoint",
    "audience",
    "callbackUrl",
    "idpInitiatedCallbackUrl",
    "signatureAlgorithm",
    "digestAlgorithm",
    "identifierFormat",
    "privateKey",
    "idpInitiatedCallbackUrl",
];
pub(super) fn validate(input: &JsValue) -> AuthResult<JsValue> {
    validate_config(input, false)
}
pub(super) fn validate_update(input: &JsValue) -> AuthResult<JsValue> {
    validate_config(input, true)
}
fn validate_config(input: &JsValue, partial: bool) -> AuthResult<JsValue> {
    let mut fields = STRINGS
        .iter()
        .filter(|name| {
            !(partial
                && **name == "idpInitiatedCallbackUrl"
                && input.get(name).is_some_and(JsValue::is_null))
        })
        .map(|name| JsonField::string(name, !partial && *name == "entryPoint"))
        .collect::<Vec<_>>();
    fields.extend([
        JsonField {
            name: "wantAssertionsSigned",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
        JsonField {
            name: "authnRequestsSigned",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ]);
    let mut parsed = crate::endpoint::validate_fields(Some(input), "body.samlConfig", &fields)?;
    if let Some(mapping) = input.get("mapping") {
        let mapping = super::mapping_schema::saml(mapping)?;
        if let JsValue::Object(fields) = &mut parsed {
            _ = fields.insert("mapping".into(), mapping);
        }
    }
    let mut value = parsed.to_json_value()?;
    if value
        .get("entryPoint")
        .and_then(Value::as_str)
        .is_some_and(|url| url::Url::parse(url).is_err())
    {
        return Err(crate::endpoint::validation(
            "[body.samlConfig.entryPoint] Invalid URL",
        ));
    }
    if value
        .get("callbackUrl")
        .and_then(Value::as_str)
        .is_some_and(|url| url.contains('#'))
    {
        return Err(crate::endpoint::validation(
            "callbackUrl must not contain a fragment",
        ));
    }
    if let Some(metadata) = input.get("spMetadata") {
        let metadata = crate::endpoint::validate_fields(
            Some(metadata),
            "body.samlConfig.spMetadata",
            &[
                JsonField::string("metadata", false),
                JsonField::string("entityID", false),
                JsonField::string("binding", false),
                JsonField::string("privateKey", false),
                JsonField::string("privateKeyPass", false),
                JsonField {
                    name: "isAssertionEncrypted",
                    kind: JsonFieldKind::Boolean,
                    required: false,
                },
                JsonField::string("encPrivateKey", false),
                JsonField::string("encPrivateKeyPass", false),
            ],
        )?;
        _ = value
            .as_object_mut()
            .ok_or_else(|| crate::endpoint::validation("Invalid SAML configuration"))?
            .insert("spMetadata".into(), metadata.to_json_value()?);
    }
    if let Some(cert) = input.get("cert") {
        let cert = cert.to_json_value()?;
        certificate_shape(&cert)?;
        _ = value
            .as_object_mut()
            .ok_or_else(|| crate::endpoint::validation("Invalid SAML configuration"))?
            .insert("cert".into(), cert);
    }
    if partial
        && input
            .get("idpInitiatedCallbackUrl")
            .is_some_and(JsValue::is_null)
    {
        let object = value
            .as_object_mut()
            .ok_or_else(|| crate::endpoint::validation("Invalid SAML configuration"))?;
        _ = object.insert("idpInitiatedCallbackUrl".into(), Value::Null);
    }
    if !partial || input.get("idpMetadata").is_some() {
        let idp = super::idp_metadata_validation::validate(input.get("idpMetadata"), partial)?;
        _ = value
            .as_object_mut()
            .ok_or_else(|| crate::endpoint::validation("Invalid SAML configuration"))?
            .insert("idpMetadata".into(), idp.to_json_value()?);
    }
    Ok(alibi_core::utils::json::parse_value(
        &serde_json::to_string(&value)?,
    )?)
}
fn certificate_shape(value: &Value) -> AuthResult<()> {
    if value.is_string()
        || value
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string))
    {
        Ok(())
    } else {
        Err(crate::endpoint::validation(
            "Invalid SAML signing certificate",
        ))
    }
}
pub(super) fn prepare(
    config: &Value,
    issuer: &str,
    max_metadata_size: usize,
) -> AuthResult<String> {
    let idp = config
        .get("idpMetadata")
        .ok_or_else(|| api(400, "Invalid SAML configuration"))?;
    let xml = idp
        .get("metadata")
        .and_then(Value::as_str)
        .filter(|xml| !xml.is_empty());
    if xml.is_none() && config.get("cert").is_none() && idp.get("cert").is_none() {
        return Err(AuthError::Api{status:400,code:Some("CERT_SOURCE_MISSING".into()),message:"samlConfig requires either a signing certificate (cert or idpMetadata.cert) or an idpMetadata.metadata XML document.".into()});
    }
    for (kind, metadata) in [("IdP", xml), ("SP", super::sp_metadata_xml::xml(config))] {
        if metadata.is_some_and(|xml| xml.len() > max_metadata_size) {
            return Err(api(
                400,
                &format!(
                    "{kind} metadata exceeds maximum allowed size ({max_metadata_size} bytes)"
                ),
            ));
        }
    }
    _ = super::sp_metadata_xml::from_config(config)?;
    let mut output = config
        .as_object()
        .cloned()
        .ok_or_else(|| api(400, "Invalid SAML configuration"))?;
    _ = output.insert("issuer".into(), json!(issuer));
    serde_json::to_string(&output).map_err(Into::into)
}
