//! Effective identity and signature policy from custom service-provider XML.
use super::{AuthError, AuthResult, Value};
use bergshamra::xml::{Document, NodeId};
const NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub(super) struct Metadata {
    pub(super) entity_id: String,
    pub(super) name_id_formats: Vec<String>,
    pub(super) post_services: Vec<String>,
    pub(super) want_assertions_signed: bool,
    pub(super) authn_requests_signed: bool,
}
pub(super) fn xml(config: &Value) -> Option<&str> {
    config
        .get("spMetadata")
        .and_then(|sp| sp.get("metadata"))
        .and_then(Value::as_str)
        .filter(|xml| !xml.is_empty())
}
pub(super) fn from_config(config: &Value) -> AuthResult<Option<Metadata>> {
    let Some(xml) = xml(config) else {
        return Ok(None);
    };
    let metadata = parse(xml).map_err(|()| {
        error(
            "SAML_INVALID_SP_METADATA",
            "Invalid SAML service provider metadata",
        )
    })?;
    if config.get("wantAssertionsSigned").and_then(Value::as_bool) == Some(true)
        && !metadata.want_assertions_signed
    {
        return Err(error(
            "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH",
            "SAML service provider metadata must require signed assertions",
        ));
    }
    Ok(Some(metadata))
}
fn error(code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status: 400,
        code: Some(code.into()),
        message: message.into(),
    }
}
fn children(doc: &Document<'_>, node: NodeId, name: &str) -> Vec<NodeId> {
    doc.children(node)
        .into_iter()
        .filter(|node| {
            doc.element(*node)
                .is_some_and(|e| e.name.matches(Some(NS), name))
        })
        .collect()
}
fn boolean(value: Option<&str>) -> Result<bool, ()> {
    match value.map(str::trim) {
        None | Some("false" | "0") => Ok(false),
        Some("true" | "1") => Ok(true),
        _ => Err(()),
    }
}
fn parse(xml: &str) -> Result<Metadata, ()> {
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(());
    }
    let doc = bergshamra::xml::uppsala::parse(xml).map_err(|_| ())?;
    let root = doc.document_element().ok_or(())?;
    if !doc
        .element(root)
        .is_some_and(|e| e.name.matches(Some(NS), "EntityDescriptor"))
    {
        return Err(());
    }
    let entity_id = doc
        .get_attribute(root, "entityID")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(())?
        .to_owned();
    let descriptors = children(&doc, root, "SPSSODescriptor");
    if descriptors.is_empty() {
        return Err(());
    }
    for node in doc.descendants(root) {
        let Some(element) = doc.element(node) else {
            continue;
        };
        match element.name.local_name.as_ref() {
            "EntityDescriptor" if node != root => return Err(()),
            "SPSSODescriptor" if !descriptors.contains(&node) => return Err(()),
            "AssertionConsumerService" | "NameIDFormat"
                if (element.name.namespace_uri.as_deref() != Some(NS)
                    || !doc
                        .parent(node)
                        .is_some_and(|parent| descriptors.contains(&parent))) =>
            {
                return Err(());
            }
            _ => {}
        }
    }
    let mut output = Metadata {
        entity_id,
        name_id_formats: Vec::new(),
        post_services: Vec::new(),
        want_assertions_signed: false,
        authn_requests_signed: false,
    };
    for descriptor in descriptors {
        output.want_assertions_signed |=
            boolean(doc.get_attribute(descriptor, "WantAssertionsSigned"))?;
        output.authn_requests_signed |=
            doc.get_attribute(descriptor, "AuthnRequestsSigned") == Some("true");
        for node in children(&doc, descriptor, "NameIDFormat") {
            let value = doc.text_content_deep(node).trim().to_owned();
            if !value.is_empty() && !output.name_id_formats.contains(&value) {
                output.name_id_formats.push(value);
            }
        }
        for node in children(&doc, descriptor, "AssertionConsumerService") {
            if doc.get_attribute(node, "Binding") != Some(POST) {
                continue;
            }
            let location = doc
                .get_attribute(node, "Location")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or(())?;
            let url = url::Url::parse(location).map_err(|_| ())?;
            if !matches!(url.scheme(), "http" | "https") || location.contains('#') {
                return Err(());
            }
            if !output.post_services.iter().any(|value| value == location) {
                output.post_services.push(location.into());
            }
        }
    }
    if output.post_services.is_empty() {
        return Err(());
    }
    Ok(output)
}
