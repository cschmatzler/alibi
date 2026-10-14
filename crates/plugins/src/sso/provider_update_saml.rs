//! Manual SAML configuration merge and effective authentication authority.
use super::{AuthResult, SsoProvider, Value, api, json};
pub(super) fn prepare(
    existing: &SsoProvider,
    updates: &Value,
    issuer: Option<&str>,
    max_metadata_size: usize,
) -> AuthResult<(String, bool)> {
    let current: Value = existing
        .saml_config
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .filter(|value: &Value| value.is_object())
        .ok_or_else(|| {
            api(
                400,
                "Cannot update SAML config for a provider that doesn't have SAML configured",
            )
        })?;
    let issuer = issuer
        .or_else(|| {
            current
                .get("issuer")
                .and_then(Value::as_str)
                .filter(|issuer| !issuer.is_empty())
        })
        .unwrap_or(&existing.issuer);
    let mut merged = current
        .as_object()
        .cloned()
        .ok_or_else(|| api(400, "Invalid SAML configuration"))?;
    for (name, value) in updates
        .as_object()
        .ok_or_else(|| api(400, "Invalid SAML configuration"))?
    {
        if name == "idpInitiatedCallbackUrl" && value.is_null() {
            _ = merged.remove(name);
        } else if matches!(name.as_str(), "idpMetadata" | "spMetadata") {
            let mut metadata = current
                .get(name)
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if let Some(fields) = value.as_object() {
                metadata.extend(
                    fields
                        .iter()
                        .map(|(name, value)| (name.clone(), value.clone())),
                );
            }
            _ = merged.insert(name.clone(), Value::Object(metadata));
        } else {
            _ = merged.insert(name.clone(), value.clone());
        }
    }
    _ = merged.insert("issuer".into(), json!(issuer));
    let updated = Value::Object(merged);
    let raw = super::registration_saml::prepare(&updated, issuer, max_metadata_size)?;
    if updated
        .get("idpMetadata")
        .and_then(|metadata| metadata.get("entityID"))
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(api(
            400,
            "SAML manual IdP configuration requires idpMetadata.entityID; issuer identifies the service provider and cannot identify the IdP",
        ));
    }
    Ok((raw, identity(&current) != identity(&updated)))
}
fn identity(config: &Value) -> Value {
    let certs = config
        .get("idpMetadata")
        .and_then(|idp| idp.get("cert"))
        .filter(|cert| !cert.is_null())
        .or_else(|| config.get("cert"));
    let mut anchors = certs.map_or_else(Vec::new, |certs| {
        certs
            .as_array()
            .map_or_else(|| vec![certs], |certs| certs.iter().collect())
            .into_iter()
            .filter_map(Value::as_str)
            .map(|cert| {
                cert.lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with("-----"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect::<Vec<_>>()
    });
    anchors.sort();
    let sp = config.get("spMetadata");
    let metadata = super::sp_metadata_xml::from_config(config).ok().flatten();
    json!({"audience":config.get("audience"), "callbackUrl":config.get("callbackUrl"),
        "idpEntityId":config.get("idpMetadata").and_then(|idp|idp.get("entityID")),
        "idpRedirectService":super::idp_services::identity(config,"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
        "idpPostService":super::idp_services::identity(config,"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        "spEntityId":metadata.as_ref().map(|sp|json!(sp.entity_id)).or_else(||sp.and_then(|sp|sp.get("entityID")).or_else(||config.get("issuer")).cloned()),
        "spNameIDFormat":metadata.as_ref().and_then(|sp|sp.name_id_formats.first().map(|name|json!(name))).or_else(||config.get("identifierFormat").cloned()),
        "spPostServices":metadata.as_ref().map_or_else(||config.get("callbackUrl").and_then(Value::as_str).map(|url|vec![url.to_owned()]).unwrap_or_default(), |sp|sp.post_services.clone()),
        "wantAssertionsSigned":metadata.as_ref().map_or_else(||config.get("wantAssertionsSigned")==Some(&json!(true)),|sp|sp.want_assertions_signed),
        "trustAnchors":anchors})
}
