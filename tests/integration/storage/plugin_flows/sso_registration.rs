//! Registration admits an authenticated owner and persists an enterprise provider.
use super::*;
use crate::storage::postgres_tests;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::store::SsoProviderStore;
backend_tests!(sso_registration_persists_owner_and_rejects_duplicate_and_reserved_ids);
postgres_tests!(sso_registration_persists_owner_and_rejects_duplicate_and_reserved_ids);
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
