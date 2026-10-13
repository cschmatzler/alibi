//! Actual redirect-binding requests carry durable provider-bound relay and request proofs.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::SsoPlugin;
use alibi::{AuthVerification, store::VerificationStore};
use base64::Engine as _;
use std::io::Read as _;
backend_tests!(sso_saml_sign_in_issues_bound_redirect_request_and_rsa_signature);
async fn sso_saml_sign_in_issues_bound_redirect_request_and_rsa_signature<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "saml-sign-in-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let private = include_str!("../../../compat/fixtures/salesforce-transport/key.pem");
    for signed in [false, true] {
        let provider_id = if signed {
            "signed-saml-provider"
        } else {
            "unsigned-saml-provider"
        };
        let config = json!({"entryPoint":"https://idp.example.test/sso","cert":cert,"privateKey":private,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"authnRequestsSigned":signed,"wantAssertionsSigned":true});
        let registered=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider_id,"issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":config}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
        assert_eq!(registered.status, 200);
        let input = json!({"providerId":provider_id,"providerType":"saml","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")});
        let before = chrono::Utc::now();
        let response = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::sign_in_sso_endpoint(&input)?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        let after = chrono::Utc::now();
        assert_eq!(response.status, 200);
        assert_eq!(body(&response)["redirect"], true);
        let url = url::Url::parse(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://idp.example.test"
        );
        assert_eq!(url.path(), "/sso");
        let query = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        let relay = &query["RelayState"];
        assert_eq!(relay.len(), 32);
        let bytes = base64::engine::general_purpose::STANDARD.decode(&query["SAMLRequest"])?;
        let mut xml = String::new();
        _ = flate2::read::DeflateDecoder::new(bytes.as_slice()).read_to_string(&mut xml)?;
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut attrs = std::collections::HashMap::new();
        let mut issuer = String::new();
        let mut name_policy = std::collections::HashMap::new();
        loop {
            match reader.read_event()? {
                quick_xml::events::Event::Start(event)
                    if event.local_name().as_ref() == b"AuthnRequest" =>
                {
                    for attribute in event.attributes() {
                        let attribute = attribute?;
                        _ = attrs.insert(
                            String::from_utf8(attribute.key.as_ref().to_vec())?,
                            attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        );
                    }
                }
                quick_xml::events::Event::Empty(event)
                    if event.local_name().as_ref() == b"NameIDPolicy" =>
                {
                    for attribute in event.attributes() {
                        let attribute = attribute?;
                        _ = name_policy.insert(
                            String::from_utf8(attribute.key.as_ref().to_vec())?,
                            attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        );
                    }
                }
                quick_xml::events::Event::Text(event) => {
                    issuer = event
                        .xml_content(quick_xml::XmlVersion::Implicit1_0)?
                        .into_owned()
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
        assert_eq!(attrs["Version"], "2.0");
        assert_eq!(attrs["xmlns:samlp"], "urn:oasis:names:tc:SAML:2.0:protocol");
        assert_eq!(attrs["xmlns:saml"], "urn:oasis:names:tc:SAML:2.0:assertion");
        assert_eq!(
            name_policy["Format"],
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        assert_eq!(name_policy["AllowCreate"], "true");
        assert_eq!(attrs["Destination"], "https://idp.example.test/sso");
        assert_eq!(
            attrs["ProtocolBinding"],
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
        assert_eq!(
            attrs["AssertionConsumerServiceURL"],
            format!("{ORIGIN}/api/auth/sso/saml2/sp/acs/{provider_id}")
        );
        assert_eq!(issuer, "https://sp.example.test/entity");
        assert!(attrs["ID"].starts_with('_'));
        _ = uuid::Uuid::parse_str(&attrs["ID"][1..])?;
        let instant = chrono::DateTime::parse_from_rfc3339(&attrs["IssueInstant"])?;
        assert!(
            instant.timestamp_millis() >= before.timestamp_millis()
                && instant.timestamp_millis() <= after.timestamp_millis()
        );
        let relay_row = store
            .get_latest_verification_by_identifier(&format!("auth-state:{relay}"))
            .await?
            .ok_or("relay proof missing")?;
        let payload: Value = serde_json::from_str(relay_row.value())?;
        assert_eq!(payload["oauthState"], *relay);
        assert_eq!(payload["callbackURL"], format!("{ORIGIN}/complete"));
        assert_eq!(payload["errorURL"], format!("{ORIGIN}/failed"));
        assert_eq!(payload["codeVerifier"].as_str().unwrap().len(), 128);
        assert!(
            relay_row.expires_at().timestamp_millis() >= before.timestamp_millis() + 600000
                && relay_row.expires_at().timestamp_millis() <= after.timestamp_millis() + 600000
        );
        let reference = &payload["serverContext"]["ssoProviderReference"];
        assert_eq!(reference["providerId"], provider_id);
        assert_eq!(reference["source"]["type"], "persisted");
        assert_eq!(reference["source"]["recordId"], body(&registered)["id"]);
        use sha2::Digest as _;
        let canonical = format!(
            r#"{{"domain":"company.test","issuer":"https://sp.example.test/entity","organizationId":null,"samlConfig":{{"authnRequestsSigned":{},"cert":{},"entryPoint":"https://idp.example.test/sso","idpMetadata":{{"entityID":"https://idp.example.test/entity"}},"issuer":"https://sp.example.test/entity","wantAssertionsSigned":true}}}}"#,
            signed,
            serde_json::to_string(cert)?
        );
        assert_eq!(
            reference["authenticationConfigurationFingerprint"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(canonical.as_bytes()))
        );
        let request_row = store
            .get_latest_verification_by_identifier(&format!("saml-authn-request:{}", attrs["ID"]))
            .await?
            .ok_or("request proof missing")?;
        let proof: Value = serde_json::from_str(request_row.value())?;
        assert_eq!(proof["id"], attrs["ID"]);
        assert_eq!(proof["providerId"], provider_id);
        assert_eq!(proof["providerReference"], *reference);
        assert_eq!(
            request_row.expires_at().timestamp_millis(),
            proof["expiresAt"].as_i64().unwrap()
        );
        assert!(
            proof["createdAt"].as_i64().unwrap() >= before.timestamp_millis()
                && proof["createdAt"].as_i64().unwrap() <= after.timestamp_millis()
        );
        let ttl = proof["expiresAt"].as_i64().unwrap() - proof["createdAt"].as_i64().unwrap();
        assert!((300000..=300200).contains(&ttl));
        let cookie = response
            .headers
            .get_all("set-cookie")
            .find(|cookie| cookie.starts_with("better-auth.relay_state="))
            .ok_or("relay cookie missing")?;
        assert!(cookie.contains("Max-Age=300"));
        let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
        let decoded = url::form_urlencoded::parse(format!("value={value}").as_bytes())
            .next()
            .unwrap()
            .1
            .into_owned();
        let (cookie_state, signature) = decoded.rsplit_once('.').unwrap();
        assert_eq!(cookie_state, relay);
        use hkdf::hmac::{Hmac, KeyInit, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes())?;
        mac.update(relay.as_bytes());
        mac.verify_slice(&base64::engine::general_purpose::STANDARD.decode(signature)?)?;
        if signed {
            assert_eq!(
                query["SigAlg"],
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            );
            let message = ["SAMLRequest", "RelayState", "SigAlg"]
                .into_iter()
                .map(|name| {
                    let prefix = format!("{name}=");
                    let pairs = url
                        .query()
                        .unwrap()
                        .split('&')
                        .filter(|pair| pair.starts_with(&prefix))
                        .collect::<Vec<_>>();
                    assert_eq!(pairs.len(), 1);
                    pairs[0]
                })
                .collect::<Vec<_>>()
                .join("&");
            use rsa::{pkcs8::DecodePrivateKey as _, signature::Verifier as _};
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(private)?;
            let signature =
                base64::engine::general_purpose::STANDARD.decode(&query["Signature"])?;
            rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key.to_public_key()).verify(
                message.as_bytes(),
                &rsa::pkcs1v15::Signature::try_from(signature.as_slice())?,
            )?;
        } else {
            assert!(!query.contains_key("SigAlg"));
            assert!(!query.contains_key("Signature"));
        }
        let mut invalid = input.clone();
        invalid["additionalParams"] = json!({"prompt":"login"});
        let rejected = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::sign_in_sso_endpoint(&invalid)?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400);
        assert_eq!(
            rejected.error.error_payload().2,
            "additionalParams is not supported for SAML providers; the SAML AuthnRequest is signed and cannot carry caller-supplied query parameters."
        );
    }
    B::close(connection).await
}
