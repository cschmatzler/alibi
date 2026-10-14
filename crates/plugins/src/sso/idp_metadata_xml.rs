//! Resolve stored `IdP` XML authority without rewriting durable provider state.
use super::{AuthError, AuthResult, Value, json};
use bergshamra::xml::{Document, NodeId};
pub(super) fn effective(config: &Value) -> AuthResult<Value> {
    let Some(xml) = config
        .get("idpMetadata")
        .and_then(|idp| idp.get("metadata"))
        .and_then(Value::as_str)
        .filter(|xml| !xml.is_empty())
    else {
        return Ok(config.clone());
    };
    let invalid = || AuthError::internal("Invalid SAML IdP metadata");
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(invalid());
    }
    let doc = bergshamra::xml::uppsala::parse(xml).map_err(|_| invalid())?;
    let root = doc.document_element().ok_or_else(invalid)?;
    let mut entities = doc
        .descendants(root)
        .into_iter()
        .filter(|node| named(&doc, *node, "EntityDescriptor"))
        .collect::<Vec<_>>();
    if named(&doc, root, "EntityDescriptor") && !entities.contains(&root) {
        entities.insert(0, root);
    }
    if entities.len() != 1 {
        return Err(invalid());
    }
    let entity = entities.first().copied().ok_or_else(invalid)?;
    let issuer = doc
        .get_attribute(entity, "entityID")
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let descriptors = doc
        .children(entity)
        .into_iter()
        .filter(|node| named(&doc, *node, "IDPSSODescriptor"))
        .collect::<Vec<_>>();
    if descriptors.is_empty() {
        return Err(invalid());
    }
    let mut sso = Vec::new();
    let mut slo = Vec::new();
    let mut all_certificates = Vec::new();
    let mut signing = Vec::new();
    for descriptor in descriptors {
        for child in doc.children(descriptor) {
            if (named(&doc, child, "SingleSignOnService")
                || named(&doc, child, "SingleLogoutService"))
                && let (Some(binding), Some(location)) = (
                    doc.get_attribute(child, "Binding"),
                    doc.get_attribute(child, "Location"),
                )
            {
                let service = json!({"Binding":binding,"Location":location});
                if named(&doc, child, "SingleSignOnService") {
                    sso.push(service);
                } else {
                    slo.push(service);
                }
            }
            if named(&doc, child, "KeyDescriptor") {
                for certificate in doc
                    .descendants(child)
                    .into_iter()
                    .filter(|node| named(&doc, *node, "X509Certificate"))
                {
                    let body = doc
                        .text_content_deep(certificate)
                        .split_whitespace()
                        .collect::<String>();
                    let lines = body
                        .as_bytes()
                        .chunks(64)
                        .map(|chunk| String::from_utf8_lossy(chunk))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let pem = format!(
                        "-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"
                    );
                    all_certificates.push(pem.clone());
                    if doc.get_attribute(child, "use") == Some("signing") {
                        signing.push(pem);
                    }
                }
            }
        }
    }
    if all_certificates.len() == 1 {
        signing = all_certificates;
    }
    let mut output = config.clone();
    let idp = output
        .get_mut("idpMetadata")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)?;
    _ = idp.insert("entityID".into(), json!(issuer));
    _ = idp.insert("cert".into(), json!(signing));
    _ = idp.insert("singleSignOnService".into(), json!(sso));
    _ = idp.insert("singleLogoutService".into(), json!(slo));
    Ok(output)
}
fn named(doc: &Document<'_>, node: NodeId, name: &str) -> bool {
    doc.element(node)
        .is_some_and(|element| element.name.local_name == name)
}
