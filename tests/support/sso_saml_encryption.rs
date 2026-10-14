//! Independent IdP envelope construction over a genuinely signed assertion.
use base64::Engine as _;
pub(crate) fn encrypt_grant(
    grant: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    use bergshamra::crypto::AlgorithmRegistry;
    use rsa::rand_core::{OsRng, RngCore};
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(grant["SAMLResponse"].as_str().unwrap())?,
    )?;
    let doc = bergshamra::xml::uppsala::parse(&xml)?;
    let root = doc.document_element().ok_or("Response missing")?;
    let assertion = doc
        .children(root)
        .into_iter()
        .find(|id| {
            doc.element(*id).is_some_and(|element| {
                element
                    .name
                    .matches(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Assertion")
            })
        })
        .ok_or("Assertion missing")?;
    let range = doc.node_range(assertion).ok_or("Assertion range missing")?;
    let mut plaintext = xml[range.clone()].to_owned();
    if !plaintext.split('>').next().unwrap().contains("xmlns:saml=") {
        plaintext = plaintext.replacen(
            "<saml:Assertion ",
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
            1,
        );
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let cipher = AlgorithmRegistry::cipher("http://www.w3.org/2009/xmlenc11#aes256-gcm")?
        .encrypt(&secret, plaintext.as_bytes())?;
    let recipient = bergshamra::keys::loader::load_x509_cert_pem(include_bytes!(
        "../compat/fixtures/salesforce-transport/leaf.pem"
    ))?;
    let wrapped =
        AlgorithmRegistry::key_transport("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")?
            .encrypt(
                &recipient
                    .software_key()?
                    .ok_or("Recipient software key missing")?,
                &secret,
            )?;
    let envelope = format!(
        r#"<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#,
        base64::engine::general_purpose::STANDARD.encode(wrapped),
        base64::engine::general_purpose::STANDARD.encode(cipher)
    );
    let mut encrypted = xml;
    encrypted.replace_range(range, &envelope);
    let mut output = grant.clone();
    output["SAMLResponse"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(encrypted));
    Ok(output)
}
