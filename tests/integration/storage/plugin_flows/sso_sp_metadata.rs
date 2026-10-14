//! Generated service-provider metadata publishes the actual endpoint and policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
backend_tests!(
    sso_sp_metadata_publishes_registered_authority_and_acs,
    sso_sp_metadata_publishes_both_logout_bindings_when_enabled,
    sso_custom_sp_metadata_drives_authorization_and_validates_effective_policy
);
async fn sso_sp_metadata_publishes_registered_authority_and_acs<B: Backend>(db: Db) -> TestResult {
    metadata_flow::<B>(db, false).await
}
async fn sso_sp_metadata_publishes_both_logout_bindings_when_enabled<B: Backend>(
    db: Db,
) -> TestResult {
    metadata_flow::<B>(db, true).await
}
async fn metadata_flow<B: Backend>(db: Db, slo: bool) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            saml_enable_single_logout: slo,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "saml-metadata-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let input = json!({"providerId":"metadata-provider","issuer":"https://sp.example.test/issuer","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"spMetadata":{"entityID":"https://sp.example.test/metadata?tenant=engineering&region=eu"},"wantAssertionsSigned":true,"authnRequestsSigned":true}});
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
    let output = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "spMetadata")
                .with_query(&json!({"providerId":"metadata-provider"}))?,
            EndpointOptions::default(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(output.status, 200);
    assert_eq!(
        output.headers.get("content-type").map(String::as_str),
        Some("application/xml")
    );
    let xml = std::str::from_utf8(&output.body)?;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut elements = std::collections::HashMap::new();
    let mut texts = Vec::new();
    let mut logout_services = Vec::new();
    loop {
        match reader.read_event()? {
            quick_xml::events::Event::Start(event) | quick_xml::events::Event::Empty(event) => {
                let name = String::from_utf8(event.name().as_ref().to_vec())?;
                let attributes = event
                    .attributes()
                    .map(|attribute| {
                        let attribute = attribute?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                            String::from_utf8(attribute.key.as_ref().to_vec())?,
                            attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )?
                                .into_owned(),
                        ))
                    })
                    .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
                if name == "SingleLogoutService" {
                    logout_services.push(attributes);
                    continue;
                }
                assert!(
                    elements.insert(name, attributes).is_none(),
                    "unexpected duplicate metadata element"
                );
            }
            quick_xml::events::Event::Text(event) => texts.push(
                event
                    .xml_content(quick_xml::XmlVersion::Implicit1_0)?
                    .into_owned(),
            ),
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!(
        elements["EntityDescriptor"]["xmlns"],
        "urn:oasis:names:tc:SAML:2.0:metadata"
    );
    assert_eq!(
        elements["EntityDescriptor"]["entityID"],
        "https://sp.example.test/metadata?tenant=engineering&region=eu"
    );
    assert_eq!(elements["SPSSODescriptor"]["WantAssertionsSigned"], "true");
    assert_eq!(elements["SPSSODescriptor"]["AuthnRequestsSigned"], "true");
    assert_eq!(
        elements["SPSSODescriptor"]["protocolSupportEnumeration"],
        "urn:oasis:names:tc:SAML:2.0:protocol"
    );
    assert_eq!(
        elements["AssertionConsumerService"]["Location"],
        format!("{ORIGIN}/api/auth/sso/saml2/sp/acs/metadata-provider")
    );
    assert_eq!(
        elements["AssertionConsumerService"]["Binding"],
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    );
    assert_eq!(elements["AssertionConsumerService"]["index"], "0");
    assert_eq!(
        texts,
        vec!["urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
    );
    if slo {
        assert_eq!(logout_services.len(), 2);
        for (service, binding) in logout_services.iter().zip(["HTTP-POST", "HTTP-Redirect"]) {
            assert_eq!(
                service["Binding"],
                format!("urn:oasis:names:tc:SAML:2.0:bindings:{binding}")
            );
            assert_eq!(
                service["Location"],
                format!("{ORIGIN}/api/auth/sso/saml2/sp/slo/metadata-provider")
            );
        }
    } else {
        assert!(logout_services.is_empty());
    }
    assert!(!elements.contains_key("KeyDescriptor"));
    assert!(!xml.contains("BEGIN CERTIFICATE"));
    let missing = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "spMetadata")
                .with_query(&json!({"providerId":"missing-provider"}))?,
            EndpointOptions::default(),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 404);
    B::close(connection).await
}

async fn sso_custom_sp_metadata_drives_authorization_and_validates_effective_policy<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::store::{AccountStore, SsoProviderStore};
    use base64::Engine as _;
    use std::io::Read as _;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "custom-sp-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let acs = format!("{ORIGIN}/api/auth/sso/saml2/sp/acs/custom-sp-provider?from=metadata");
    let metadata = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/from-xml"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true" AuthnRequestsSigned="false"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}"/></md:SPSSODescriptor></md:EntityDescriptor>"#
    );
    let registration = json!({"providerId":"custom-sp-provider","issuer":"https://sp.example.test/unused-issuer","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"spMetadata":{"entityID":"https://sp.example.test/unused-field","metadata":metadata},"identifierFormat":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","wantAssertionsSigned":false}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&registration)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let output = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::sp_metadata_endpoint("custom-sp-provider")?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(output.status, 200);
    assert_eq!(
        output.headers.get("content-type").map(String::as_str),
        Some("application/xml")
    );
    assert_eq!(std::str::from_utf8(&output.body)?, metadata);
    let started = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::sign_in_sso_endpoint(
            &json!({"providerId":"custom-sp-provider","callbackURL":format!("{ORIGIN}/complete")}),
        )?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let authorization = body(&started)["url"].as_str().unwrap().to_owned();
    let url = url::Url::parse(&authorization)?;
    let encoded = url
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .unwrap()
        .1
        .into_owned();
    let raw = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let mut xml = String::new();
    _ = flate2::read::DeflateDecoder::new(raw.as_slice()).read_to_string(&mut xml)?;
    let doc = bergshamra::xml::uppsala::parse(&xml)?;
    let root = doc.document_element().unwrap();
    assert_eq!(
        doc.get_attribute(root, "AssertionConsumerServiceURL"),
        Some(acs.as_str())
    );
    let issuer = doc
        .children(root)
        .into_iter()
        .find(|node| {
            doc.element(*node).is_some_and(|e| {
                e.name
                    .matches(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Issuer")
            })
        })
        .unwrap();
    assert_eq!(
        doc.text_content_deep(issuer),
        "https://sp.example.test/from-xml"
    );
    let name = doc
        .children(root)
        .into_iter()
        .find(|node| {
            doc.element(*node).is_some_and(|e| {
                e.name
                    .matches(Some("urn:oasis:names:tc:SAML:2.0:protocol"), "NameIDPolicy")
            })
        })
        .unwrap();
    assert_eq!(
        doc.get_attribute(name, "Format"),
        Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    );
    let email = "custom-sp-employee@company.test";
    let grant = super::saml_idp::grant(&authorization, email, false)?;
    let completed = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::acs_endpoint("custom-sp-provider", &grant)?,
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
    assert!(
        store
            .get_account("custom-sp-provider", email)
            .await?
            .is_some()
    );
    let original = store.get_sso_provider("custom-sp-provider").await?.unwrap();
    for changed in [
        metadata.replace(
            "https://sp.example.test/from-xml",
            "https://sp.example.test/changed",
        ),
        metadata.replace("?from=metadata", "?from=changed"),
        metadata.replace(
            "WantAssertionsSigned=\"true\"",
            "WantAssertionsSigned=\"false\"",
        ),
    ] {
        let rejected = Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"custom-sp-provider","samlConfig":{"spMetadata":{"metadata":changed}}}))?,owned.clone())).await.unwrap_err();
        assert_eq!(rejected.error.status_code(), 409);
        assert_eq!(
            store
                .get_sso_provider("custom-sp-provider")
                .await?
                .unwrap()
                .saml_config,
            original.saml_config
        );
    }
    for (index, xml, code) in [
        (0, "<broken>".to_owned(), "SAML_INVALID_SP_METADATA"),
        (
            1,
            metadata.replace("urn:oasis:names:tc:SAML:2.0:metadata", "urn:wrong"),
            "SAML_INVALID_SP_METADATA",
        ),
        (
            2,
            metadata.replace("HTTP-POST", "HTTP-Redirect"),
            "SAML_INVALID_SP_METADATA",
        ),
        (
            3,
            metadata.replace(
                "WantAssertionsSigned=\"true\"",
                "WantAssertionsSigned=\"false\"",
            ),
            "SAML_SP_METADATA_ASSERTION_SIGNATURE_MISMATCH",
        ),
    ] {
        let mut rejected_input = registration.clone();
        rejected_input["providerId"] = json!(format!("invalid-sp-{index}"));
        rejected_input["samlConfig"]["spMetadata"]["metadata"] = json!(xml);
        rejected_input["samlConfig"]["wantAssertionsSigned"] = json!(true);
        let rejected = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&rejected_input)?,
            owned.clone(),
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400);
        assert_eq!(body(&rejected.error.to_auth_response())["code"], code);
        assert!(
            store
                .get_sso_provider(&format!("invalid-sp-{index}"))
                .await?
                .is_none()
        );
    }
    let mut oversized = registration.clone();
    oversized["providerId"] = json!("oversized-sp");
    oversized["samlConfig"]["spMetadata"]["metadata"] = json!("x".repeat(102401));
    let rejected = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&oversized)?,
        owned,
    ))
    .await
    .unwrap_err();
    assert_eq!(rejected.error.status_code(), 400);
    assert_eq!(
        body(&rejected.error.to_auth_response()),
        json!({"message":"SP metadata exceeds maximum allowed size (102400 bytes)"})
    );
    assert!(store.get_sso_provider("oversized-sp").await?.is_none());
    B::close(connection).await
}
