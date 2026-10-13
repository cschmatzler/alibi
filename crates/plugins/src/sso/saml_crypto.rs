//! Validate signature coverage before consuming SAML identity claims.
use super::{Value, json};
use bergshamra::xml::{Document, NodeId};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(super) struct SamlIdentity {
    pub id: String,
    pub email: String,
    pub name: String,
    pub attributes: Value,
    pub assertion_id: Option<String>,
    pub issuer: String,
    pub in_response_to: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_index: Option<String>,
}
pub(super) struct Failure {
    pub code: &'static str,
    pub message: &'static str,
}
fn invalid() -> Failure {
    Failure {
        code: "saml_error",
        message: "Invalid SAML response",
    }
}
fn binding(message: &'static str) -> Failure {
    Failure {
        code: "invalid_saml_response",
        message,
    }
}
fn children(doc: &Document<'_>, parent: NodeId, namespace: &str, name: &str) -> Vec<NodeId> {
    doc.children(parent)
        .into_iter()
        .filter(|id| {
            doc.element(*id)
                .is_some_and(|element| element.name.matches(Some(namespace), name))
        })
        .collect()
}
fn child(doc: &Document<'_>, parent: NodeId, namespace: &str, name: &str) -> Option<NodeId> {
    children(doc, parent, namespace, name).into_iter().next()
}
fn attribute<'a>(doc: &'a Document<'_>, node: NodeId, name: &str) -> Option<&'a str> {
    doc.get_attribute(node, name)
}
fn text(doc: &Document<'_>, node: NodeId) -> String {
    doc.text_content_deep(node)
}
pub(super) fn verify(
    xml: &str,
    config: &Value,
    recipient: &str,
    clock_skew: chrono::Duration,
    require_timestamps: bool,
) -> Result<SamlIdentity, Failure> {
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(invalid());
    }
    let doc = bergshamra::xml::uppsala::parse(xml).map_err(|_| invalid())?;
    let root = doc.document_element().ok_or_else(invalid)?;
    if !doc
        .element(root)
        .is_some_and(|element| element.name.matches(Some(PROTOCOL), "Response"))
    {
        return Err(invalid());
    }
    let assertions = doc
        .descendants(root)
        .into_iter()
        .filter(|id| {
            doc.element(*id)
                .is_some_and(|element| element.name.matches(Some(ASSERTION), "Assertion"))
        })
        .collect::<Vec<_>>();
    if assertions.len() != 1 || doc.parent(*assertions.first().ok_or_else(invalid)?) != Some(root) {
        return Err(invalid());
    }
    let assertion = *assertions.first().ok_or_else(invalid)?;
    let status = child(&doc, root, PROTOCOL, "Status")
        .and_then(|node| child(&doc, node, PROTOCOL, "StatusCode"))
        .and_then(|node| attribute(&doc, node, "Value"));
    if status != Some("urn:oasis:names:tc:SAML:2.0:status:Success") {
        return Err(invalid());
    }
    let certificates = config
        .get("idpMetadata")
        .and_then(|metadata| metadata.get("cert"))
        .or_else(|| config.get("cert"))
        .ok_or_else(invalid)?;
    let certificates = if let Some(certificate) = certificates.as_str() {
        vec![certificate]
    } else {
        certificates
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .filter_map(Value::as_str)
            .collect()
    };
    // Same-document, whole-node references prevent file/network resolution and filtered-claim signatures.
    for node in doc.descendants(root) {
        if doc
            .element(node)
            .is_some_and(|element| element.name.matches(Some(DSIG), "Reference"))
        {
            if !attribute(&doc, node, "URI").is_some_and(|uri| uri.starts_with('#')) {
                return Err(invalid());
            }
            for transform in child(&doc, node, DSIG, "Transforms")
                .map_or_else(Vec::new, |transforms| {
                    children(&doc, transforms, DSIG, "Transform")
                })
            {
                if !attribute(&doc, transform, "Algorithm").is_some_and(|algorithm| {
                    matches!(
                        algorithm,
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                            | "http://www.w3.org/2001/10/xml-exc-c14n#"
                            | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
                            | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                            | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
                            | "http://www.w3.org/2006/12/xml-c14n11"
                            | "http://www.w3.org/2006/12/xml-c14n11#WithComments"
                    )
                }) {
                    return Err(invalid());
                }
            }
        }
    }
    let mut verified = HashSet::new();
    let mut assertion_signed = false;
    let mut response_signed = false;
    for certificate in certificates {
        let key = bergshamra::keys::loader::load_x509_cert_pem(certificate.as_bytes())
            .map_err(|_| invalid())?;
        let mut keys = bergshamra::KeysManager::new();
        keys.add_key(key);
        let context = bergshamra::DsigContext::new(keys);
        let results =
            bergshamra::dsig::verify::verify_all_document_with_source(&context, &doc, Some(xml))
                .map_err(|_| invalid())?;
        for result in results {
            if result.all_reference_digests_verified()
                && let bergshamra::VerifyResult::Valid {
                    signature_node,
                    references,
                    ..
                } = result
            {
                let parent = doc.parent(signature_node);
                let covers_assertion = references.iter().any(|reference| {
                    reference.resolved_node == Some(assertion) && reference.digest_verified
                });
                let covers_response = references.iter().any(|reference| {
                    reference.resolved_node == Some(root) && reference.digest_verified
                });
                if parent == Some(assertion) && covers_assertion {
                    assertion_signed = true;
                    _ = verified.insert(signature_node);
                }
                if parent == Some(root) && covers_response {
                    response_signed = true;
                    _ = verified.insert(signature_node);
                }
            }
        }
    }
    let signatures = doc
        .descendants(root)
        .into_iter()
        .filter(|id| {
            doc.element(*id)
                .is_some_and(|element| element.name.matches(Some(DSIG), "Signature"))
        })
        .count();
    if verified.len() != signatures
        || (!assertion_signed && !response_signed)
        || config.get("wantAssertionsSigned") == Some(&json!(true)) && !assertion_signed
    {
        return Err(invalid());
    }
    let issuer = config
        .get("idpMetadata")
        .and_then(|metadata| metadata.get("entityID"))
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if child(&doc, root, ASSERTION, "Issuer")
        .map(|node| text(&doc, node))
        .as_deref()
        != Some(issuer)
        || child(&doc, assertion, ASSERTION, "Issuer")
            .map(|node| text(&doc, node))
            .as_deref()
            != Some(issuer)
    {
        return Err(invalid());
    }
    let conditions = child(&doc, assertion, ASSERTION, "Conditions");
    let now = Utc::now();
    let mut expires_at = None;
    if require_timestamps
        && conditions.is_none_or(|node| {
            attribute(&doc, node, "NotBefore").is_none()
                && attribute(&doc, node, "NotOnOrAfter").is_none()
        })
    {
        return Err(Failure {
            code: "saml_error",
            message: "SAML assertion missing required timestamp conditions",
        });
    }
    if let Some(conditions) = conditions {
        for field in ["NotBefore", "NotOnOrAfter"] {
            if let Some(raw) = attribute(&doc, conditions, field) {
                let time = DateTime::parse_from_rfc3339(raw)
                    .map_err(|_| Failure {
                        code: "saml_error",
                        message: if field == "NotBefore" {
                            "SAML assertion has invalid NotBefore timestamp"
                        } else {
                            "SAML assertion has invalid NotOnOrAfter timestamp"
                        },
                    })?
                    .with_timezone(&Utc);
                if field == "NotBefore" && now < time - clock_skew {
                    return Err(Failure {
                        code: "saml_error",
                        message: "SAML assertion is not yet valid",
                    });
                }
                if field == "NotOnOrAfter" {
                    expires_at = Some(time);
                    if now > time + clock_skew {
                        return Err(Failure {
                            code: "saml_error",
                            message: "SAML assertion has expired",
                        });
                    }
                }
            }
        }
    }
    let entity = config
        .get("spMetadata")
        .and_then(|metadata| metadata.get("entityID"))
        .and_then(Value::as_str)
        .filter(|entity| !entity.is_empty())
        .or_else(|| config.get("issuer").and_then(Value::as_str))
        .ok_or_else(invalid)?;
    let expected = [Some(entity), config.get("audience").and_then(Value::as_str)];
    let audiences = conditions.map_or_else(Vec::new, |node| {
        children(&doc, node, ASSERTION, "AudienceRestriction")
    });
    if audiences.is_empty() {
        return Err(binding("SAML assertion is missing an AudienceRestriction"));
    }
    for group in audiences {
        let audiences = children(&doc, group, ASSERTION, "Audience");
        if audiences.is_empty() {
            return Err(binding("SAML assertion is missing an AudienceRestriction"));
        }
        if !audiences.iter().any(|node| {
            expected
                .into_iter()
                .flatten()
                .any(|audience| text(&doc, *node) == audience)
        }) {
            return Err(binding(
                "SAML assertion audience does not match this Service Provider",
            ));
        }
    }
    let subject = child(&doc, assertion, ASSERTION, "Subject").ok_or_else(invalid)?;
    let confirmations = children(&doc, subject, ASSERTION, "SubjectConfirmation")
        .into_iter()
        .filter(|node| {
            attribute(&doc, *node, "Method") == Some("urn:oasis:names:tc:SAML:2.0:cm:bearer")
        })
        .filter_map(|node| child(&doc, node, ASSERTION, "SubjectConfirmationData"))
        .collect::<Vec<_>>();
    if confirmations.is_empty() {
        return Err(binding(
            "SAML assertion is missing bearer SubjectConfirmationData",
        ));
    }
    if !confirmations
        .iter()
        .any(|node| attribute(&doc, *node, "Recipient") == Some(recipient))
    {
        return Err(binding(
            "SAML bearer SubjectConfirmationData Recipient does not match this Service Provider",
        ));
    }
    if attribute(&doc, root, "Destination")
        .is_some_and(|destination| !destination.is_empty() && destination != recipient)
    {
        return Err(binding(
            "SAML response Destination does not match this Service Provider",
        ));
    }
    let response_to = attribute(&doc, root, "InResponseTo");
    if response_to.is_some_and(|response_to| {
        confirmations.iter().any(|node| {
            attribute(&doc, *node, "InResponseTo")
                .is_some_and(|confirmation| confirmation != response_to)
        })
    }) {
        return Err(invalid());
    }
    let id = child(&doc, subject, ASSERTION, "NameID")
        .map(|node| text(&doc, node))
        .filter(|id| !id.is_empty())
        .ok_or_else(invalid)?;
    let mut attributes = HashMap::<String, Vec<String>>::new();
    for statement in children(&doc, assertion, ASSERTION, "AttributeStatement") {
        for node in children(&doc, statement, ASSERTION, "Attribute") {
            if let Some(name) = attribute(&doc, node, "Name") {
                _ = attributes.insert(
                    name.into(),
                    children(&doc, node, ASSERTION, "AttributeValue")
                        .into_iter()
                        .map(|node| text(&doc, node))
                        .collect(),
                );
            }
        }
    }
    let mapped = |name: &str, default: &str| {
        config
            .get("mapping")
            .and_then(|mapping| mapping.get(name))
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let value = |name: &str, default: &str| {
        attributes
            .get(&mapped(name, default))
            .and_then(|values| values.first())
            .cloned()
    };
    let email = value("email", "email")
        .filter(|email| !email.is_empty())
        .unwrap_or_else(|| id.clone())
        .to_lowercase();
    let full_name = [
        value("firstName", "givenName"),
        value("lastName", "surname"),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.is_empty())
    .collect::<Vec<_>>()
    .join(" ");
    let name = if full_name.is_empty() {
        value("name", "displayName")
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone())
    } else {
        full_name
    };
    let attributes = Value::Object(
        attributes
            .into_iter()
            .map(|(name, values)| {
                let value = if values.len() == 1 {
                    values.first().map_or(Value::Null, |value| json!(value))
                } else {
                    json!(values)
                };
                (name, value)
            })
            .collect(),
    );
    Ok(SamlIdentity {
        id,
        email,
        name,
        attributes,
        assertion_id: attribute(&doc, assertion, "ID").map(str::to_owned),
        issuer: issuer.into(),
        in_response_to: response_to.map(str::to_owned),
        expires_at,
        session_index: child(&doc, assertion, ASSERTION, "AuthnStatement")
            .and_then(|statement| attribute(&doc, statement, "SessionIndex"))
            .map(str::to_owned),
    })
}
