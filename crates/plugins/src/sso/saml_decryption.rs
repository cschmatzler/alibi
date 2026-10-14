//! Decrypt an assertion envelope before validating its signed identity claims.
use super::{AuthError, AuthResult, Value};
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ENCRYPTION: &str = "http://www.w3.org/2001/04/xmlenc#";
fn invalid() -> AuthError {
    AuthError::internal("Invalid encrypted SAML assertion")
}
pub(super) fn decrypt(xml: &str, config: &Value) -> AuthResult<String> {
    let doc = bergshamra::xml::uppsala::parse(xml).map_err(|_| invalid())?;
    let root = doc.document_element().ok_or_else(invalid)?;
    if !doc
        .element(root)
        .is_some_and(|element| element.name.matches(Some(PROTOCOL), "Response"))
    {
        return Err(invalid());
    }
    let envelopes: Vec<_> = doc
        .children(root)
        .into_iter()
        .filter(|node| {
            doc.element(*node)
                .is_some_and(|element| element.name.matches(Some(ASSERTION), "EncryptedAssertion"))
        })
        .collect();
    let data: Vec<_> = doc
        .descendants(root)
        .into_iter()
        .filter(|node| {
            doc.element(*node)
                .is_some_and(|element| element.name.matches(Some(ENCRYPTION), "EncryptedData"))
        })
        .collect();
    if envelopes.len() != 1
        || data.len() != 1
        || doc.parent(*data.first().ok_or_else(invalid)?) != envelopes.first().copied()
    {
        return Err(invalid());
    }
    let metadata = config.get("spMetadata").ok_or_else(invalid)?;
    let private = metadata
        .get("encPrivateKey")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .ok_or_else(invalid)?;
    let private = private
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    let passphrase = metadata.get("encPrivateKeyPass").and_then(Value::as_str);
    let key = bergshamra::keys::loader::load_pem_auto(private.as_bytes(), passphrase)
        .map_err(|_| invalid())?;
    let mut keys = bergshamra::KeysManager::new();
    keys.add_key(key);
    let mut context = bergshamra::EncContext::new(keys);
    context.disable_cipher_reference = true;
    let decrypted = bergshamra::decrypt(&context, xml).map_err(|_| invalid())?;
    if decrypted.contains("<!DOCTYPE") || decrypted.contains("<!ENTITY") {
        return Err(invalid());
    }
    let doc = bergshamra::xml::uppsala::parse(&decrypted).map_err(|_| invalid())?;
    let root = doc.document_element().ok_or_else(invalid)?;
    let envelope = doc
        .children(root)
        .into_iter()
        .find(|node| {
            doc.element(*node)
                .is_some_and(|element| element.name.matches(Some(ASSERTION), "EncryptedAssertion"))
        })
        .ok_or_else(invalid)?;
    let assertions: Vec<_> = doc
        .children(envelope)
        .into_iter()
        .filter(|node| {
            doc.element(*node)
                .is_some_and(|element| element.name.matches(Some(ASSERTION), "Assertion"))
        })
        .collect();
    if assertions.len() != 1 {
        return Err(invalid());
    }
    let assertion_range = doc
        .node_range(*assertions.first().ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let envelope_range = doc.node_range(envelope).ok_or_else(invalid)?;
    let assertion = decrypted
        .get(assertion_range)
        .ok_or_else(invalid)?
        .to_owned();
    let mut output = decrypted;
    output.replace_range(envelope_range, &assertion);
    Ok(output)
}
