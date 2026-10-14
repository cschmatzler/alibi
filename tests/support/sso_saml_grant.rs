//! Independent IdP signer grants a real assertion for an issued redirect request.
use base64::Engine as _;
use std::io::Read as _;
pub(super) fn grant(
    authorization: &str,
    email: &str,
    wrong_key: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    grant_with_verified(authorization, email, wrong_key, None)
}
pub(super) fn grant_with_verified(
    authorization: &str,
    email: &str,
    wrong_key: bool,
    verified: Option<&[&str]>,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    grant_with_correlation(authorization, email, wrong_key, verified, true)
}
pub(super) fn unsolicited_grant(
    authorization: &str,
    email: &str,
    wrong_key: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    grant_with_correlation(authorization, email, wrong_key, None, false)
}
fn grant_with_correlation(
    authorization: &str,
    email: &str,
    wrong_key: bool,
    verified: Option<&[&str]>,
    correlated: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(authorization)?;
    let query = url
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    let bytes = base64::engine::general_purpose::STANDARD.decode(&query["SAMLRequest"])?;
    let mut request = String::new();
    _ = flate2::read::DeflateDecoder::new(bytes.as_slice()).read_to_string(&mut request)?;
    let doc = bergshamra::xml::uppsala::parse(&request)?;
    let root = doc.document_element().ok_or("AuthnRequest missing")?;
    let request_id = doc.get_attribute(root, "ID").ok_or("request ID missing")?;
    let recipient = doc
        .get_attribute(root, "AssertionConsumerServiceURL")
        .ok_or("ACS missing")?;
    let issuer = doc
        .children(root)
        .into_iter()
        .find(|id| {
            doc.element(*id).is_some_and(|element| {
                element
                    .name
                    .matches(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Issuer")
            })
        })
        .and_then(|id| doc.element_text(id))
        .ok_or("SP issuer missing")?;
    let assertion_id = format!("_{}", uuid::Uuid::new_v4());
    let response_id = format!("_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let instant = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let before =
        (now - chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expires =
        (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let escaped = |value: &str| quick_xml::escape::escape(value).into_owned();
    let request_id = escaped(request_id);
    let recipient = escaped(recipient);
    let issuer = escaped(issuer);
    let email = escaped(email);
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"##
    );
    let verification = verified.map_or_else(String::new, |values| {
        let values = values
            .iter()
            .map(|value| {
                format!(
                    "<saml:AttributeValue>{}</saml:AttributeValue>",
                    escaped(value)
                )
            })
            .collect::<String>();
        format!(r#"<saml:Attribute Name="verified-mailbox">{values}</saml:Attribute>"#)
    });
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{response_id}" Version="2.0" IssueInstant="{instant}" Destination="{recipient}" InResponseTo="{request_id}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{instant}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer>{signature}<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{recipient}" NotOnOrAfter="{expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{expires}"><saml:AudienceRestriction><saml:Audience>{issuer}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{instant}" SessionIndex="session-index"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue>SSO employee</saml:AttributeValue></saml:Attribute>{verification}</saml:AttributeStatement></saml:Assertion></samlp:Response>"#
    );
    let xml = if correlated {
        xml
    } else {
        xml.replace(&format!(" InResponseTo=\"{request_id}\""), "")
    };
    let signed = sign_xml(&xml, wrong_key)?;
    Ok(
        serde_json::json!({"SAMLResponse":base64::engine::general_purpose::STANDARD.encode(signed),"RelayState":query["RelayState"],"assertionId":assertion_id,"requestId":request_id}),
    )
}

fn sign_xml(
    xml: &str,
    wrong_key: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let private = if wrong_key {
        include_bytes!("../fixtures/one-tap/wrong-private-key.pem").as_slice()
    } else {
        include_bytes!("../compat/fixtures/salesforce-transport/key.pem").as_slice()
    };
    let key = bergshamra::keys::loader::load_rsa_private_pem(private)?;
    let mut keys = bergshamra::KeysManager::new();
    keys.add_key(key);
    Ok(bergshamra::sign(&bergshamra::DsigContext::new(keys), xml)?)
}
pub(super) fn signed_logout(
    xml: &str,
    wrong_key: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let doc = bergshamra::xml::uppsala::parse(xml)?;
    let root = doc.document_element().ok_or("Logout root missing")?;
    let id = quick_xml::escape::escape(doc.get_attribute(root, "ID").ok_or("Logout ID missing")?);
    let signature = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/></ds:Signature>"##
    );
    let xml = xml.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
    Ok(base64::engine::general_purpose::STANDARD.encode(sign_xml(&xml, wrong_key)?))
}
