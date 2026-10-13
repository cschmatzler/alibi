//! Generated service-provider metadata publishes the actual endpoint and policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
backend_tests!(sso_sp_metadata_publishes_registered_authority_and_acs);
async fn sso_sp_metadata_publishes_registered_authority_and_acs<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
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
    assert!(!elements.contains_key("SingleLogoutService"));
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
