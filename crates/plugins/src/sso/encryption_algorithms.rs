//! Application policies for SAML assertion key transport and data encryption.
use super::SsoDeprecatedAlgorithmBehavior;
#[derive(Clone, Debug, Default)]
pub struct SsoSamlEncryptionPolicy {
    pub on_deprecated: SsoDeprecatedAlgorithmBehavior,
    pub allowed_key_encryption_algorithms: Option<Vec<String>>,
    pub allowed_data_encryption_algorithms: Option<Vec<String>>,
}

use super::saml_crypto::Failure;
use bergshamra::xml::{Document, NodeId};
const XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";
fn algorithm(doc: &Document<'_>, root: NodeId, parent: &str) -> Option<String> {
    let parent = doc.descendants(root).into_iter().find(|node| {
        doc.element(*node)
            .is_some_and(|element| element.name.matches(Some(XMLENC), parent))
    })?;
    let method = doc.children(parent).into_iter().find(|node| {
        doc.element(*node)
            .is_some_and(|element| element.name.matches(Some(XMLENC), "EncryptionMethod"))
    })?;
    doc.get_attribute(method, "Algorithm")
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
pub(super) fn validate(xml: &str, policy: &SsoSamlEncryptionPolicy) -> Result<(), Failure> {
    let Ok(doc) = bergshamra::xml::uppsala::parse(xml) else {
        return Ok(());
    };
    let Some(root) = doc.document_element() else {
        return Ok(());
    };
    for (value, label, allowed, deprecated, recommendation) in [
        (
            algorithm(&doc, root, "EncryptedKey"),
            "key",
            &policy.allowed_key_encryption_algorithms,
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
            "RSA-OAEP",
        ),
        (
            algorithm(&doc, root, "EncryptedData"),
            "data",
            &policy.allowed_data_encryption_algorithms,
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
            "AES-GCM",
        ),
    ] {
        let Some(value) = value else { continue };
        if let Some(allowed) = allowed {
            if !allowed.contains(&value) {
                return Err(Failure {
                    code: "saml_algorithm_not_allowed",
                    message: format!(
                        "SAML {label} encryption algorithm not in allow-list: {value}"
                    ),
                });
            }
        } else if value == deprecated {
            let message = format!(
                "SAML response uses deprecated {label} encryption algorithm: {value}. Please configure your IdP to use {recommendation}."
            );
            match policy.on_deprecated {
                SsoDeprecatedAlgorithmBehavior::Reject => {
                    return Err(Failure {
                        code: "saml_deprecated_algorithm",
                        message,
                    });
                }
                SsoDeprecatedAlgorithmBehavior::Warn => tracing::warn!("{message}"),
                SsoDeprecatedAlgorithmBehavior::Allow => {}
            }
        }
    }
    Ok(())
}
