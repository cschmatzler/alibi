//! Listing filters actual registered providers by the caller's authority.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
backend_tests!(sso_provider_list_filters_ownership_and_redacts_credentials);
async fn sso_provider_list_filters_ownership_and_redacts_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-list-owner@example.test").await;
    let foreign = signup(&auth, "sso-list-foreign@example.test").await;
    let empty = signup(&auth, "sso-list-empty@example.test").await;
    for (cookie, id, client_id) in [
        (cookies(&foreign), "foreign-provider", "foreign-client"),
        (cookies(&owner), "owned-alpha", "alpha-client"),
        (cookies(&owner), "owned-beta", "beta-client"),
    ] {
        let response=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":id,"issuer":"https://idp.example.com","domain":"company.com","oidcConfig":{"clientId":client_id,"clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"scopes":["openid","email"]}}))?,EndpointOptions{headers:Some([("cookie".into(),cookie)].into_iter().collect()),..Default::default()})).await?.into_response()?;
        assert_eq!(response.status, 200);
    }
    let endpoint = ServerEndpoint::<Value>::new("sso", "listSSOProviders");
    for (cookie, ids) in [
        (cookies(&owner), vec!["owned-alpha", "owned-beta"]),
        (cookies(&foreign), vec!["foreign-provider"]),
        (cookies(&empty), Vec::new()),
    ] {
        let response = Box::pin(auth.dispatch_endpoint(
            endpoint.clone(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let data = body(&response);
        let providers = data["providers"].as_array().unwrap();
        assert_eq!(
            providers
                .iter()
                .map(|provider| provider["providerId"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ids
        );
        for provider in providers {
            assert_eq!(provider["type"], "oidc");
            assert_eq!(provider["domainVerified"], false);
            assert!(provider["organizationId"].is_null());
            assert_eq!(provider["oidcConfig"]["clientIdLastFour"], "****ient");
            assert!(provider["oidcConfig"].get("clientId").is_none());
            assert!(provider["oidcConfig"].get("clientSecret").is_none());
            assert!(provider.get("userId").is_none());
        }
    }
    let anonymous = Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(anonymous.error.status_code(), 401);
    B::close(connection).await
}
