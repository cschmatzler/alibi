//! Public SAML configuration rejects unsupported algorithms before durable writes.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::SsoPlugin;
use alibi::store::SsoProviderStore;
backend_tests!(sso_saml_algorithm_admission_rejects_unknown_names_and_preserves_aliases);
async fn sso_saml_algorithm_admission_rejects_unknown_names_and_preserves_aliases<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "algorithm-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"algorithm-provider","issuer":"https://idp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"}}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let original = store.get_sso_provider("algorithm-provider").await?.unwrap();
    for (field, label) in [
        ("signatureAlgorithm", "signature"),
        ("digestAlgorithm", "digest"),
    ] {
        for (index, value) in [
            "md5",
            "https://idp.example.test/unknown-algorithm",
            "SHA256 ",
            "http://www.w3.org/2001/04/xmlenc#SHA256",
        ]
        .into_iter()
        .enumerate()
        {
            let message = format!("SAML {label} algorithm not recognized: {value}");
            let provider_id = format!("invalid-{field}-{index}");
            let mut candidate = input.clone();
            candidate["providerId"] = json!(provider_id);
            candidate["samlConfig"][field] = json!(value);
            for (update, body) in [
                (false, candidate),
                (
                    true,
                    json!({"providerId":"algorithm-provider","samlConfig":{(field):value}}),
                ),
            ] {
                let endpoint = if update {
                    SsoPlugin::update_sso_provider_endpoint(&body)?
                } else {
                    SsoPlugin::register_sso_provider_endpoint(&body)?
                };
                let response = match Box::pin(auth.dispatch_endpoint(endpoint, owned.clone())).await
                {
                    Ok(output) => output.into_response()?,
                    Err(error) => error.error.to_auth_response(),
                };
                assert_eq!(response.status, 400);
                assert_eq!(
                    super::body(&response),
                    json!({"code":"SAML_UNKNOWN_ALGORITHM","message":message})
                );
            }
            assert!(store.get_sso_provider(&provider_id).await?.is_none());
            assert_eq!(
                store.get_sso_provider("algorithm-provider").await?.unwrap(),
                original
            );
        }
    }
    for (index, (signature, digest)) in [
        ("RSA-SHA256", "SHA256"),
        ("ecdsa-sha384", "sha384"),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            "http://www.w3.org/2001/04/xmlenc#sha512",
        ),
        ("sha1", "sha1"),
        ("", ""),
    ]
    .into_iter()
    .enumerate()
    {
        let mut candidate = input.clone();
        let provider_id = format!("valid-algorithm-{index}");
        candidate["providerId"] = json!(provider_id);
        candidate["samlConfig"]["signatureAlgorithm"] = json!(signature);
        candidate["samlConfig"]["digestAlgorithm"] = json!(digest);
        let created = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&candidate)?,
            owned.clone(),
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 200);
        let updated=Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"algorithm-provider","samlConfig":{"signatureAlgorithm":signature,"digestAlgorithm":digest}}))?,owned.clone())).await?.into_response()?;
        assert_eq!(updated.status, 200);
        for id in [provider_id.as_str(), "algorithm-provider"] {
            let provider = store.get_sso_provider(id).await?.unwrap();
            let config: Value = serde_json::from_str(provider.saml_config.as_deref().unwrap())?;
            assert_eq!(config["signatureAlgorithm"], signature);
            assert_eq!(config["digestAlgorithm"], digest);
        }
    }
    B::close(connection).await
}
