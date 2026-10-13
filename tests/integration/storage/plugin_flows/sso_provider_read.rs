//! Provider reads authorize a real owner and redact persisted OIDC secrets.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::store::SsoProviderStore;
backend_tests!(
    sso_provider_read_redacts_secrets_and_denies_foreign_owners,
    sso_saml_provider_read_redacts_keys_and_projects_certificate_authority
);
async fn sso_provider_read_redacts_secrets_and_denies_foreign_owners<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-reader@example.test").await;
    let foreign = signup(&auth, "sso-foreign@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let created=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"read-provider","issuer":"https://idp.example.com","domain":"company.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks","pkce":true,"scopes":["openid","email"]}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(created.status, 200);
    let endpoint = ServerEndpoint::<Value>::new("sso", "getSSOProvider")
        .with_query(&json!({"providerId":"read-provider"}))?;
    let result = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(result.status, 200);
    assert_eq!(
        body(&result),
        json!({"providerId":"read-provider","type":"oidc","issuer":"https://idp.example.com","domain":"company.com","organizationId":null,"domainVerified":false,"oidcConfig":{"discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration","clientIdLastFour":"****ient","pkce":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks","scopes":["openid","email"],"tokenEndpointAuthentication":"client_secret_basic"},"spMetadataUrl":format!("{ORIGIN}/api/auth/sso/saml2/sp/metadata?providerId=read-provider")})
    );
    let denied = Box::pin(auth.dispatch_endpoint(
        endpoint.clone(),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&foreign))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    assert_eq!(
        body(&denied.error.to_auth_response()),
        json!({"message":"You don't have access to this provider"})
    );
    let missing = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "getSSOProvider")
                .with_query(&json!({"providerId":"missing-provider"}))?,
            owned,
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 404);
    assert_eq!(
        body(&missing.error.to_auth_response()),
        json!({"message":"Provider not found"})
    );
    assert_eq!(
        Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
            .await
            .unwrap_err()
            .error
            .status_code(),
        401
    );
    let row = store
        .get_sso_provider("read-provider")
        .await?
        .ok_or("Provider read removed its row")?;
    assert_eq!(
        serde_json::from_str::<Value>(row.oidc_config.as_deref().unwrap())?["clientSecret"],
        "stored-secret"
    );
    B::close(connection).await
}

async fn sso_saml_provider_read_redacts_keys_and_projects_certificate_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "saml-reader@example.test").await;
    let foreign = signup(&auth, "saml-reader-foreign@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let saml = json!({"entryPoint":"https://idp.example.test/sso","cert":"fallback-cert","privateKey":"private-sp-secret","idpMetadata":{"entityID":"https://idp.example.test/entity","cert":[cert,"malformed-cert"],"privateKey":"private-idp-secret","privateKeyPass":"idp-passphrase"},"spMetadata":{"privateKey":"nested-sp-secret","encPrivateKey":"decryption-secret"},"wantAssertionsSigned":true,"authnRequestsSigned":false,"audience":"urn:read:audience"});
    let created = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"saml-read-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":saml}))?,owned.clone())).await?.into_response()?;
    assert_eq!(created.status, 200);
    let endpoint = SsoPlugin::get_sso_provider_endpoint("saml-read-provider")?;
    let response = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(response.status, 200);
    let projected = body(&response);
    assert_eq!(
        projected,
        json!({"providerId":"saml-read-provider","type":"saml","issuer":"https://sp.example.test/entity","domain":"company.test","organizationId":null,"domainVerified":false,"spMetadataUrl":format!("{ORIGIN}/api/auth/sso/saml2/sp/metadata?providerId=saml-read-provider"),"samlConfig":{"entryPoint":"https://idp.example.test/sso","wantAssertionsSigned":true,"authnRequestsSigned":false,"audience":"urn:read:audience","certificate":[{"fingerprintSha256":"46:51:AA:26:63:79:35:81:81:8D:96:A4:13:DA:03:1F:B3:5E:B5:0C:7E:A9:0A:2C:E7:E2:55:21:48:C4:63:27","notBefore":"Oct  8 09:44:25 2026 GMT","notAfter":"Oct  5 09:44:25 2036 GMT","publicKeyAlgorithm":"RSA"},{"error":"Failed to parse certificate"}]}})
    );
    let listing = Box::pin(auth.dispatch_endpoint(SsoPlugin::list_sso_providers_endpoint(), owned))
        .await?
        .into_response()?;
    assert_eq!(body(&listing), json!({"providers":[projected]}));
    let denied = Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&foreign))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    let row = store
        .get_sso_provider("saml-read-provider")
        .await?
        .ok_or("Missing durable SAML provider")?;
    let stored: Value =
        serde_json::from_str(row.saml_config.as_deref().ok_or("Missing SAML config")?)?;
    assert_eq!(stored["privateKey"], "private-sp-secret");
    assert_eq!(stored["idpMetadata"]["privateKey"], "private-idp-secret");
    assert_eq!(stored["spMetadata"]["encPrivateKey"], "decryption-secret");
    B::close(connection).await
}
