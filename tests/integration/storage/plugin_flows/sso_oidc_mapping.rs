//! Protocol mapping admission protects identity configuration before durable writes.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::SsoPlugin;
use alibi::store::SsoProviderStore;
backend_tests!(
    sso_oidc_mapping_admission_requires_identity_fields_and_preserves_config,
    sso_saml_mapping_admission_requires_identity_fields_and_preserves_config
);
async fn sso_oidc_mapping_admission_requires_identity_fields_and_preserves_config<B: Backend>(
    db: Db,
) -> TestResult {
    mapping_admission_flow::<B>(db, false).await
}
async fn sso_saml_mapping_admission_requires_identity_fields_and_preserves_config<B: Backend>(
    db: Db,
) -> TestResult {
    mapping_admission_flow::<B>(db, true).await
}
async fn mapping_admission_flow<B: Backend>(db: Db, saml: bool) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "mapping-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let mut input = json!({"providerId":"mapping-provider","issuer":"https://idp.example.com","domain":"company.test","oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks","mapping":{"email":"mail","name":"label","image":"avatar","extraFields":{"department":"dept"}}}});
    let protocol = if saml { "samlConfig" } else { "oidcConfig" };
    if saml {
        _ = input.as_object_mut().unwrap().remove("oidcConfig");
        input["samlConfig"] = json!({"entryPoint":"https://idp.example.test/sso","cert":include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"},"mapping":{"email":"mail","name":"label","firstName":"given","lastName":"surname","extraFields":{"department":"dept"}}});
    }
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let row = store.get_sso_provider("mapping-provider").await?.unwrap();
    let config: Value = serde_json::from_str(if saml {
        row.saml_config.as_deref().unwrap()
    } else {
        row.oidc_config.as_deref().unwrap()
    })?;
    assert_eq!(config["mapping"], input[protocol]["mapping"]);
    let cases = [
        (
            json!(null),
            "[body.oidcConfig.mapping] Invalid input: expected object, received null",
        ),
        (
            json!([]),
            "[body.oidcConfig.mapping] Invalid input: expected object, received array",
        ),
        (
            json!("mapping"),
            "[body.oidcConfig.mapping] Invalid input: expected object, received string",
        ),
        (
            json!(12),
            "[body.oidcConfig.mapping] Invalid input: expected object, received number",
        ),
        (
            json!({"email":"mail"}),
            "[body.oidcConfig.mapping.name] Invalid input: expected string, received undefined",
        ),
        (
            json!({"name":"label"}),
            "[body.oidcConfig.mapping.email] Invalid input: expected string, received undefined",
        ),
        (
            json!({"email":3,"name":"label"}),
            "[body.oidcConfig.mapping.email] Invalid input: expected string, received number",
        ),
        (
            json!({"email":"mail","name":"label","image":false}),
            "[body.oidcConfig.mapping.image] Invalid input: expected string, received boolean",
        ),
        (
            json!({"email":"mail","name":"label","extraFields":[]}),
            "[body.oidcConfig.mapping.extraFields] Invalid input: expected record, received array",
        ),
        (
            json!({"email":"mail","name":"label","unknown":"field"}),
            r#"[body.oidcConfig.mapping] Unrecognized key: "unknown""#,
        ),
    ];
    for (index, (mut mapping, oidc_message)) in cases.into_iter().enumerate() {
        let message = oidc_message
            .replace("oidcConfig", protocol)
            .replace(".image]", if saml { ".firstName]" } else { ".image]" });
        if saml
            && let Some(image) = mapping
                .as_object_mut()
                .and_then(|mapping| mapping.remove("image"))
        {
            mapping["firstName"] = image;
        }

        let provider_id = format!("invalid-mapping-{index}");
        let mut invalid = input.clone();
        invalid["providerId"] = json!(provider_id);
        invalid[protocol]["mapping"] = mapping.clone();
        let registered = match Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&invalid)?,
            owned.clone(),
        ))
        .await
        {
            Ok(output) => output.into_response()?,
            Err(error) => error.error.to_auth_response(),
        };
        assert_eq!(registered.status, 400);
        assert_eq!(
            body(&registered),
            json!({"code":"VALIDATION_ERROR","message":message})
        );
        assert!(store.get_sso_provider(&provider_id).await?.is_none());
        let updated = match Box::pin(auth.dispatch_endpoint(
            SsoPlugin::update_sso_provider_endpoint(
                &json!({"providerId":"mapping-provider",(protocol):{"mapping":mapping}}),
            )?,
            owned.clone(),
        ))
        .await
        {
            Ok(output) => output.into_response()?,
            Err(error) => error.error.to_auth_response(),
        };
        assert_eq!(updated.status, 400);
        assert_eq!(
            body(&updated),
            json!({"code":"VALIDATION_ERROR","message":message})
        );
        assert_eq!(
            store.get_sso_provider("mapping-provider").await?.unwrap(),
            row
        );
    }
    B::close(connection).await
}
