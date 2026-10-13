//! Registration admits an authenticated owner and persists an enterprise provider.
use super::*;
use crate::storage::postgres_tests;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::store::SsoProviderStore;
backend_tests!(
    sso_registration_persists_owner_and_rejects_duplicate_and_reserved_ids,
    sso_registration_persists_manual_saml_and_requires_certificate_source
);
postgres_tests!(
    sso_registration_persists_owner_and_rejects_duplicate_and_reserved_ids,
    sso_registration_persists_manual_saml_and_requires_certificate_source
);
async fn sso_registration_persists_owner_and_rejects_duplicate_and_reserved_ids<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-owner@example.test").await;
    let input = json!({"providerId":"enterprise-oidc","issuer":"https://idp.example.com","domain":"company.com,subsidiary.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"enterprise-secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks","scopes":["openid","email"],"pkce":true}});
    let endpoint = ServerEndpoint::<Value>::new("sso", "registerSSOProvider").with_body(&input)?;
    let options = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let created = Box::pin(auth.dispatch_endpoint(endpoint.clone(), options.clone()))
        .await?
        .into_response()?;
    assert_eq!(created.status, 200);
    let provider = body(&created);
    assert_eq!(provider["providerId"], "enterprise-oidc");
    assert_eq!(provider["userId"], body(&owner)["user"]["id"]);
    assert_eq!(provider["domain"], "company.com,subsidiary.com");
    assert_eq!(provider["oidcConfig"]["clientSecret"], "enterprise-secret");
    assert_eq!(
        provider["oidcConfig"],
        json!({"issuer":"https://idp.example.com","clientId":"enterprise-client","clientSecret":"enterprise-secret","authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks","tokenEndpointAuthentication":"client_secret_basic","discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration","scopes":["openid","email"],"pkce":true,"overrideUserInfo":false})
    );
    assert!(provider["organizationId"].is_null());
    assert_eq!(
        provider["redirectURI"],
        format!("{ORIGIN}/api/auth/sso/callback/enterprise-oidc")
    );
    assert!(provider["samlConfig"].is_null());
    assert!(provider.get("domainVerified").is_none());
    let restarted = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::SsoPlugin::new())
        .build()
        .await?;
    let durable = restarted
        .store()
        .get_sso_provider("enterprise-oidc")
        .await?
        .ok_or("SSO provider was not persisted")?;
    assert_eq!(durable.id, provider["id"].as_str().unwrap());
    assert_eq!(
        durable.user_id.as_deref(),
        body(&owner)["user"]["id"].as_str()
    );
    assert_eq!(
        serde_json::from_str::<Value>(durable.oidc_config.as_deref().unwrap())?,
        provider["oidcConfig"]
    );
    let duplicate = Box::pin(auth.dispatch_endpoint(endpoint.clone(), options.clone()))
        .await
        .unwrap_err();
    assert_eq!(duplicate.error.status_code(), 422);
    assert_eq!(
        duplicate.error.to_auth_response().body,
        serde_json::to_vec(&json!({"message":"SSO provider with this providerId already exists"}))?
    );
    let mut reserved = input.clone();
    reserved["providerId"] = json!("credential");
    let denied = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("sso", "registerSSOProvider").with_body(&reserved)?,
        options,
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 422);
    let anonymous = Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(anonymous.error.status_code(), 401);
    assert_eq!(
        store
            .list_sso_providers_by_user(body(&owner)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        1
    );
    B::close(connection).await
}

async fn sso_registration_persists_manual_saml_and_requires_certificate_source<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(alibi::plugins::SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "saml-provider-owner@example.test").await;
    let options = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let input = json!({"providerId":"enterprise-saml","issuer":"https://sp.example.test","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"signatureAlgorithm":"rsa-sha256","digestAlgorithm":"sha256","mapping":{"email":"mail","name":"displayName"},"ignoredField":"discard"}});
    let created = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("sso", "registerSSOProvider").with_body(&input)?,
        options.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let provider = body(&created);
    assert_eq!(provider["userId"], body(&owner)["user"]["id"]);
    assert_eq!(
        provider["samlConfig"],
        json!({"issuer":"https://sp.example.test","entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"signatureAlgorithm":"rsa-sha256","digestAlgorithm":"sha256","mapping":{"email":"mail","name":"displayName"}})
    );
    assert!(provider["oidcConfig"].is_null());
    let persisted = store
        .get_sso_provider("enterprise-saml")
        .await?
        .ok_or("SAML provider missing")?;
    assert_eq!(persisted.id, provider["id"].as_str().unwrap());
    assert_eq!(
        serde_json::from_str::<Value>(persisted.saml_config.as_deref().unwrap())?,
        provider["samlConfig"]
    );
    let mut invalid = input.clone();
    invalid["providerId"] = json!("saml-without-cert");
    _ = invalid["samlConfig"]
        .as_object_mut()
        .unwrap()
        .remove("cert");
    let rejected = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("sso", "registerSSOProvider").with_body(&invalid)?,
        options,
    ))
    .await
    .unwrap_err();
    assert_eq!(rejected.error.status_code(), 400);
    assert_eq!(
        rejected.error.error_payload().1.as_deref(),
        Some("CERT_SOURCE_MISSING")
    );
    assert!(store.get_sso_provider("saml-without-cert").await?.is_none());
    B::close(connection).await
}
