//! A real IdP signature redeems issued SAML state and creates a usable session.
use super::saml_idp as idp;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::{
    AuthAccount, AuthVerification,
    store::{AccountStore, SsoProviderStore, VerificationStore},
};
backend_tests!(
    sso_saml_acs_validates_signed_grant_and_rejects_wrong_key_and_replay,
    sso_trusted_saml_verification_requires_mapping_and_exact_first_true_attribute,
    sso_saml_acs_uses_xml_idp_authority_and_signing_certificate,
    sso_saml_encrypted_assertions_require_trusted_signatures_and_prevent_replay,
    sso_saml_encrypted_assertions_import_password_protected_decryption_keys,
    sso_saml_encrypted_assertions_reject_missing_decryption_key,
    sso_saml_encrypted_assertions_reject_wrong_decryption_key,
    sso_saml_encrypted_assertions_reject_wrong_passphrase,
    sso_saml_encrypted_assertions_reject_missing_passphrase,
    sso_saml_encrypted_assertions_accept_ciphertext_response_signatures,
    sso_saml_encrypted_assertions_accept_outer_only_signatures,
    sso_saml_encrypted_assertions_accept_aes128_gcm,
    sso_saml_encrypted_assertions_accept_aes128_cbc,
    sso_saml_encrypted_assertions_accept_aes256_cbc,
    sso_saml_encrypted_assertions_reject_damaged_ciphertext,
    sso_saml_encryption_policy_key_denied,
    sso_saml_encryption_policy_data_denied,
    sso_saml_encryption_policy_key_allowed,
    sso_saml_encryption_policy_data_allowed,
    sso_saml_encryption_policy_key_empty,
    sso_saml_encryption_policy_data_empty,
    sso_saml_encryption_policy_outer_key_denied,
    sso_saml_deprecated_data_cipher_reject,
    sso_saml_deprecated_data_cipher_allow,
    sso_saml_deprecated_data_cipher_warn,
    sso_saml_deprecated_data_cipher_override,
    sso_saml_legacy_cipher_support_rejects_unsupported_signature_algorithms
);
async fn sso_saml_acs_validates_signed_grant_and_rejects_wrong_key_and_replay<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::Manual).await
}
async fn sso_saml_acs_uses_xml_idp_authority_and_signing_certificate<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::IdpXml).await
}
async fn sso_saml_encrypted_assertions_require_trusted_signatures_and_prevent_replay<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::Encrypted).await
}
async fn sso_saml_encrypted_assertions_import_password_protected_decryption_keys<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::EncryptedKey).await
}
async fn sso_saml_encrypted_assertions_reject_missing_decryption_key<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::MissingKey).await
}
async fn sso_saml_encrypted_assertions_reject_wrong_decryption_key<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::WrongKey).await
}
async fn sso_saml_encrypted_assertions_reject_wrong_passphrase<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::WrongPass).await
}
async fn sso_saml_encrypted_assertions_reject_missing_passphrase<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::MissingPass).await
}
async fn sso_saml_encrypted_assertions_accept_ciphertext_response_signatures<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::EncryptedResponse).await
}
async fn sso_saml_encrypted_assertions_accept_outer_only_signatures<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::OuterOnly).await
}
async fn sso_saml_encrypted_assertions_accept_aes128_gcm<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::Aes128Gcm).await
}
async fn sso_saml_encrypted_assertions_accept_aes128_cbc<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::Aes128Cbc).await
}
async fn sso_saml_encrypted_assertions_accept_aes256_cbc<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::Aes256Cbc).await
}
async fn sso_saml_encrypted_assertions_reject_damaged_ciphertext<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::Tampered).await
}
async fn sso_saml_encryption_policy_key_denied<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::EncryptionPolicy("encrypted-policy-key-denied")).await
}
async fn sso_saml_encryption_policy_data_denied<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-policy-data-denied"),
    )
    .await
}
async fn sso_saml_encryption_policy_key_allowed<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-policy-key-allowed"),
    )
    .await
}
async fn sso_saml_encryption_policy_data_allowed<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-policy-data-allowed"),
    )
    .await
}
async fn sso_saml_encryption_policy_key_empty<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::EncryptionPolicy("encrypted-policy-key-empty")).await
}
async fn sso_saml_encryption_policy_data_empty<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(db, AcsCase::EncryptionPolicy("encrypted-policy-data-empty")).await
}
async fn sso_saml_encryption_policy_outer_key_denied<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-policy-outer-key-denied"),
    )
    .await
}
async fn sso_saml_deprecated_data_cipher_reject<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-deprecated-data-reject"),
    )
    .await
}
async fn sso_saml_deprecated_data_cipher_allow<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-deprecated-data-allow"),
    )
    .await
}
async fn sso_saml_deprecated_data_cipher_warn<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-deprecated-data-warn"),
    )
    .await
}
async fn sso_saml_deprecated_data_cipher_override<B: Backend>(db: Db) -> TestResult {
    acs_flow::<B>(
        db,
        AcsCase::EncryptionPolicy("encrypted-deprecated-data-override"),
    )
    .await
}
async fn sso_saml_legacy_cipher_support_rejects_unsupported_signature_algorithms<B: Backend>(
    db: Db,
) -> TestResult {
    acs_flow::<B>(db, AcsCase::UnsupportedLegacySignature).await
}
#[derive(Clone, Copy)]
enum AcsCase {
    EncryptionPolicy(&'static str),
    UnsupportedLegacySignature,
    Manual,
    IdpXml,
    Encrypted,
    EncryptedKey,
    EncryptedResponse,
    OuterOnly,
    Aes128Gcm,
    Aes128Cbc,
    Aes256Cbc,
    Tampered,
    MissingKey,
    WrongKey,
    WrongPass,
    MissingPass,
}
async fn acs_flow<B: Backend>(db: Db, case: AcsCase) -> TestResult {
    let xml_metadata = matches!(case, AcsCase::IdpXml);
    let key_failure = matches!(
        case,
        AcsCase::MissingKey | AcsCase::WrongKey | AcsCase::WrongPass | AcsCase::MissingPass
    );
    let signature_denied = matches!(case, AcsCase::UnsupportedLegacySignature);
    let encrypted = !matches!(
        case,
        AcsCase::Manual | AcsCase::IdpXml | AcsCase::UnsupportedLegacySignature
    );

    let policy_mode = if let AcsCase::EncryptionPolicy(mode) = case {
        mode
    } else {
        "default"
    };
    let deprecated = policy_mode.contains("deprecated-data-");
    let deprecated_rejected = policy_mode.ends_with("deprecated-data-reject");
    let policy_denied = matches!(case,AcsCase::EncryptionPolicy(mode) if !mode.contains("allowed") && !mode.contains("outer") && !deprecated)
        || deprecated_rejected;
    let policy_key = policy_mode.contains("policy-key");
    let outer_policy = policy_mode.contains("policy-outer");
    let provider_id = if signature_denied {
        "unsupported-legacy-signature-provider"
    } else if let AcsCase::EncryptionPolicy(mode) = case {
        mode
    } else if matches!(case, AcsCase::Tampered) {
        "encrypted-tampered-acs-provider"
    } else if matches!(
        case,
        AcsCase::Aes128Gcm | AcsCase::Aes128Cbc | AcsCase::Aes256Cbc
    ) {
        match case {
            AcsCase::Aes128Gcm => "encrypted-aes-128-gcm-acs-provider",
            AcsCase::Aes128Cbc => "encrypted-aes-128-cbc-acs-provider",
            _ => "encrypted-aes-256-cbc-acs-provider",
        }
    } else if matches!(case, AcsCase::OuterOnly) {
        "encrypted-outer-only-acs-provider"
    } else if matches!(case, AcsCase::EncryptedResponse) {
        "encrypted-response-acs-provider"
    } else if key_failure {
        match case {
            AcsCase::MissingKey => "encrypted-missing-key-acs-provider",
            AcsCase::WrongKey => "encrypted-wrong-key-acs-provider",
            AcsCase::WrongPass => "encrypted-wrong-pass-acs-provider",
            _ => "encrypted-missing-pass-acs-provider",
        }
    } else if matches!(case, AcsCase::EncryptedKey) {
        "encrypted-key-acs-provider"
    } else if encrypted {
        "encrypted-acs-provider"
    } else if xml_metadata {
        "xml-acs-provider"
    } else {
        "acs-provider"
    };
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(alibi::plugins::SsoConfig {
            saml_encryption_policy: super::sso_encryption_policy::policy(policy_mode),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "saml-acs-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let mut input = json!({"providerId":provider_id,"issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"callbackUrl":format!("{ORIGIN}/complete")}});
    if matches!(case, AcsCase::OuterOnly) {
        input["samlConfig"]["wantAssertionsSigned"] = json!(false);
    }
    if encrypted {
        input["samlConfig"]["idpMetadata"]["isAssertionEncrypted"] = json!(true);
        input["samlConfig"]["spMetadata"] = if matches!(case, AcsCase::EncryptedKey) {
            json!({"isAssertionEncrypted":true,"encPrivateKey":include_str!("../../../compat/fixtures/salesforce-transport/encrypted-key.pem"),"encPrivateKeyPass":"sso-test-passphrase"})
        } else {
            json!({"isAssertionEncrypted":true,"encPrivateKey":include_str!("../../../compat/fixtures/salesforce-transport/key.pem")})
        };
    }
    if key_failure {
        input["samlConfig"]["spMetadata"] = match case {
            AcsCase::MissingKey => json!({"isAssertionEncrypted":true}),
            AcsCase::WrongKey => {
                json!({"isAssertionEncrypted":true,"encPrivateKey":include_str!("../../../compat/fixtures/passkey-attestation/ca-key.pem")})
            }
            AcsCase::WrongPass => {
                json!({"isAssertionEncrypted":true,"encPrivateKey":include_str!("../../../compat/fixtures/salesforce-transport/encrypted-key.pem"),"encPrivateKeyPass":"incorrect-passphrase"})
            }
            _ => {
                json!({"isAssertionEncrypted":true,"encPrivateKey":include_str!("../../../compat/fixtures/salesforce-transport/encrypted-key.pem")})
            }
        };
    }
    if xml_metadata {
        let certificate = cert
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let metadata = format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.test/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/from-xml"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        );
        input["samlConfig"]["entryPoint"] = json!("https://unused.example.test/entrypoint");
        _ = input["samlConfig"].as_object_mut().unwrap().remove("cert");
        input["samlConfig"]["idpMetadata"] =
            json!({"entityID":"https://unused.example.test/entity","metadata":metadata});
    }
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    for (http, wrong_key) in [(false, false), (true, false), (false, true), (true, true)] {
        let email = if wrong_key {
            "wrong-key-user@example.test"
        } else {
            "saml-employee@example.test"
        };
        let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider_id,"providerType":"saml","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(started.status, 200);
        let authorization = url::Url::parse(body(&started)["url"].as_str().unwrap())?;
        assert_eq!(
            authorization.origin().ascii_serialization(),
            "https://idp.example.test"
        );
        assert_eq!(
            authorization.path(),
            if xml_metadata { "/from-xml" } else { "/sso" }
        );
        let grant = if signature_denied {
            idp::unsupported_signature_grant(
                body(&started)["url"].as_str().unwrap(),
                email,
                wrong_key,
            )?
        } else {
            idp::grant(body(&started)["url"].as_str().unwrap(), email, wrong_key)?
        };
        let grant = if encrypted {
            super::sso_saml_encryption::encrypt_grant_with_unsigned_assertion(
                &grant,
                matches!(case, AcsCase::OuterOnly),
                match case {
                    AcsCase::EncryptionPolicy(mode) if mode.contains("deprecated-data-") => {
                        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
                    }
                    AcsCase::Aes128Gcm => "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                    AcsCase::Aes128Cbc => "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                    AcsCase::Aes256Cbc => "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                    _ => "http://www.w3.org/2009/xmlenc11#aes256-gcm",
                },
            )?
        } else {
            grant
        };
        let grant = if matches!(case, AcsCase::Tampered) {
            use base64::Engine as _;
            let xml = String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(grant["SAMLResponse"].as_str().unwrap())?,
            )?;
            let doc = bergshamra::xml::uppsala::parse(&xml)?;
            let root = doc.document_element().ok_or("Response missing")?;
            let value = doc
                .descendants(root)
                .into_iter()
                .rfind(|node| {
                    doc.element(*node).is_some_and(|element| {
                        element
                            .name
                            .matches(Some("http://www.w3.org/2001/04/xmlenc#"), "CipherValue")
                    })
                })
                .ok_or("Cipher value missing")?;
            let mut bytes =
                base64::engine::general_purpose::STANDARD.decode(doc.text_content_deep(value))?;
            *bytes.last_mut().ok_or("Ciphertext missing")? ^= 1;
            let range = doc.node_range(value).ok_or("Cipher range missing")?;
            let mut xml = xml;
            xml.replace_range(
                range,
                &format!(
                    "<xenc:CipherValue>{}</xenc:CipherValue>",
                    base64::engine::general_purpose::STANDARD.encode(bytes)
                ),
            );
            let mut grant = grant;
            grant["SAMLResponse"] = json!(base64::engine::general_purpose::STANDARD.encode(xml));
            grant
        } else {
            grant
        };
        let grant =
            if matches!(case, AcsCase::EncryptedResponse | AcsCase::OuterOnly) || outer_policy {
                use base64::Engine as _;
                let xml = String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(grant["SAMLResponse"].as_str().unwrap())?,
                )?;
                let mut grant = grant;
                grant["SAMLResponse"] = json!(idp::signed_logout(&xml, wrong_key)?);
                grant
            } else {
                grant
            };
        let endpoint = ServerEndpoint::<Value>::new("sso", "acsEndpoint")
            .with_params(&json!({"providerId":provider_id}))?
            .with_body(
                &json!({"SAMLResponse":grant["SAMLResponse"],"RelayState":grant["RelayState"]}),
            )?;
        // Exercise a real cross-site IdP form POST even when a session cookie is present.
        let invoke = |endpoint| async {
            if http {
                let form = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("SAMLResponse", grant["SAMLResponse"].as_str().unwrap())
                    .append_pair("RelayState", grant["RelayState"].as_str().unwrap())
                    .finish();
                let mut incoming =
                    AuthRequest::new(HttpMethod::Post, format!("/sso/saml2/sp/acs/{provider_id}"));
                incoming.headers.extend([
                    (
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    ("origin".into(), "https://idp.example.test".into()),
                    ("cookie".into(), cookies(&owner)),
                ]);
                incoming.body = Some(form.into_bytes());
                Box::pin(auth.handle_request(incoming))
                    .await
                    .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
            } else {
                Ok(
                    Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
                        .await?
                        .into_response()?,
                )
            }
        };
        let completed = invoke(endpoint.clone()).await?;
        assert_eq!(completed.status, 302);
        let location = url::Url::parse(completed.headers.get("location").unwrap())?;
        assert!(
            store
                .get_latest_verification_by_identifier(&format!(
                    "auth-state:{}",
                    grant["RelayState"].as_str().unwrap()
                ))
                .await?
                .is_none()
        );
        let request_identifier = format!(
            "saml-authn-request:{}",
            grant["requestId"].as_str().unwrap()
        );
        let assertion = format!(
            "saml-used-assertion:{}",
            grant["assertionId"].as_str().unwrap()
        );
        if wrong_key
            || key_failure
            || matches!(case, AcsCase::Tampered)
            || policy_denied
            || signature_denied
        {
            assert_eq!(location.path(), "/failed");
            let query = location
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            if deprecated_rejected && !wrong_key {
                assert_eq!(query["error"], "saml_deprecated_algorithm");
                assert_eq!(
                    query["error_description"],
                    "SAML response uses deprecated data encryption algorithm: http://www.w3.org/2001/04/xmlenc#tripledes-cbc. Please configure your IdP to use AES-GCM."
                );
            } else if policy_denied && !wrong_key {
                assert_eq!(query["error"], "saml_algorithm_not_allowed");
                assert_eq!(
                    query["error_description"],
                    if policy_key {
                        "SAML key encryption algorithm not in allow-list: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                    } else {
                        "SAML data encryption algorithm not in allow-list: http://www.w3.org/2009/xmlenc11#aes256-gcm"
                    }
                );
            } else {
                assert_eq!(query["error"], "saml_error");
                assert_eq!(query["error_description"], "Invalid SAML response");
            }
            assert!(
                store
                    .get_latest_verification_by_identifier(&request_identifier)
                    .await?
                    .is_some()
            );
            assert!(
                store
                    .get_latest_verification_by_identifier(&assertion)
                    .await?
                    .is_none()
            );
            assert!(store.get_account(provider_id, email).await?.is_none());
            assert!(
                !completed
                    .headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.starts_with("better-auth.session_token="))
            );
        } else {
            assert_eq!(location.as_str(), format!("{ORIGIN}/complete"));
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert_eq!(body(&session)["user"]["name"], "SSO employee");
            assert_eq!(body(&session)["user"]["emailVerified"], false);
            assert!(
                body(&session)["session"]["token"]
                    .as_str()
                    .is_some_and(|token| !token.is_empty())
            );
            assert!(
                store
                    .get_latest_verification_by_identifier(&request_identifier)
                    .await?
                    .is_none()
            );
            let used = store
                .get_latest_verification_by_identifier(&assertion)
                .await?
                .ok_or("Assertion replay proof missing")?;
            let proof: Value = serde_json::from_str(used.value())?;
            assert_eq!(proof["assertionId"], grant["assertionId"]);
            assert_eq!(proof["issuer"], "https://idp.example.test/entity");
            assert_eq!(proof["providerId"], provider_id);
            let account = store
                .get_account(provider_id, email)
                .await?
                .ok_or("SAML account missing")?;
            assert_eq!(
                account.user_id(),
                body(&session)["user"]["id"].as_str().unwrap()
            );
            assert_eq!(account.access_token(), Some(""));
            assert_eq!(account.refresh_token(), Some(""));
            assert_ne!(
                account.user_id(),
                body(&owner)["user"]["id"].as_str().unwrap()
            );
            let replay = invoke(endpoint).await?;
            assert_eq!(replay.status, 302);
            let query = url::Url::parse(replay.headers.get("location").unwrap())?
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(query["error"], "invalid_saml_response");
            assert_eq!(query["error_description"], "Unknown or expired request ID");
        }
    }
    let mut rejected = request("/sign-out", Some(json!({})), &cookies(&owner));
    _ = rejected
        .headers
        .insert("origin".into(), "https://idp.example.test".into());
    _ = call(&auth, rejected, 403).await;
    authenticated(&auth, &cookies(&owner), "saml-acs-owner@example.test").await;
    if xml_metadata {
        let row = store.get_sso_provider(provider_id).await?.unwrap();
        let stored: Value = serde_json::from_str(row.saml_config.as_deref().unwrap())?;
        assert_eq!(
            stored["idpMetadata"]["entityID"],
            "https://unused.example.test/entity"
        );
        assert_eq!(
            stored["entryPoint"],
            "https://unused.example.test/entrypoint"
        );
        assert_eq!(
            stored["idpMetadata"]["metadata"],
            input["samlConfig"]["idpMetadata"]["metadata"]
        );
        let xml = stored["idpMetadata"]["metadata"].as_str().unwrap();
        for changed in [
            xml.replace(
                "https://idp.example.test/entity",
                "https://other-idp.example.test/entity",
            ),
            xml.replace(
                "https://idp.example.test/from-xml",
                "https://other-idp.example.test/sso",
            ),
        ] {
            let rejected = Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":provider_id,"samlConfig":{"idpMetadata":{"metadata":changed}}}))?,EndpointOptions { headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default() })).await.unwrap_err();
            assert_eq!(rejected.error.status_code(), 409);
            assert_eq!(store.get_sso_provider(provider_id).await?.unwrap(), row);
        }
    }
    B::close(connection).await
}

async fn sso_trusted_saml_verification_requires_mapping_and_exact_first_true_attribute<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(alibi::plugins::SsoConfig {
            trust_email_verified: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "trusted-saml-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    for mapped in [true, false] {
        let provider = if mapped {
            "trusted-saml-provider"
        } else {
            "unmapped-saml-provider"
        };
        let mut mapping = json!({"email":"email","name":"displayName"});
        if mapped {
            mapping["emailVerified"] = json!("verified-mailbox");
        }
        let registered = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider,"issuer":"https://sp.example.test/entity","domain":"example.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"mapping":mapping}}))?,EndpointOptions { headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default() })).await?.into_response()?;
        assert_eq!(registered.status, 200);
        let claims = if mapped {
            vec![
                (vec!["true"], true),
                (vec!["false"], false),
                (vec!["TRUE"], false),
                (vec!["1"], false),
                (vec!["true", "false"], true),
                (vec!["false", "true"], false),
            ]
        } else {
            vec![(vec!["true"], false)]
        };
        for (index, (values, expected)) in claims.into_iter().enumerate() {
            let email = format!("trusted-saml-{mapped}-{index}@example.test");
            let started = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::sign_in_sso_endpoint(
                    &json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete")}),
                )?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let grant = idp::grant_with_verified(
                body(&started)["url"].as_str().unwrap(),
                &email,
                false,
                Some(&values),
            )?;
            let completed = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::acs_endpoint(provider, &grant)?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(
                completed.headers.get("location").map(String::as_str),
                Some(format!("{ORIGIN}/complete").as_str())
            );
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert_eq!(body(&session)["user"]["emailVerified"], expected);
        }
    }
    B::close(connection).await
}
