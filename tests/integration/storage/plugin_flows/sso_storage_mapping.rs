//! Actual provider lifecycle owns its mapped relation, including restart and DNS writes.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SessionManagementPlugin, SsoConfig, SsoPlugin};
use alibi::store::{SchemaMigrator, SsoProviderStore};
backend_tests!(sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes);
postgres_tests!(sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes);
async fn sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let dns = super::sso_dns::start().await;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    super::sso_storage_schema::configure(&mut config);
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    store.migrate().await?;
    store.migrate().await?;
    let build = || {
        AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(SsoPlugin::with_config(SsoConfig {
                domain_verification: true,
                domain_verification_dns_servers: vec![dns.address],
                ..Default::default()
            }))
            .build()
    };
    let auth = build().await?;
    let owner = signup(&auth, "mapped-sso-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"mapped-provider","issuer":"https://idp.example.com","domain":"company.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"durable-secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let physical: Value = serde_json::from_str(&db.table("application_sso_provider").await?)?;
    assert_eq!(physical[0]["application_provider"], "mapped-provider");
    assert_eq!(physical[0]["application_owner"], body(&owner)["user"]["id"]);
    assert_eq!(physical[0]["application_issuer"], input["issuer"]);
    assert_eq!(physical[0]["application_domain"], "company.test");
    assert!(physical[0]["application_org"].is_null());
    assert!(physical[0]["application_saml"].is_null());
    let oidc: Value = serde_json::from_str(physical[0]["application_oidc"].as_str().unwrap())?;
    assert_eq!(oidc["clientSecret"], "durable-secret");
    let token = body(&created)["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    *dns.records.lock().unwrap() =
        vec![vec![format!("_better-auth-token-mapped-provider={token}")]];
    let verified = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::verify_domain_endpoint("mapped-provider")?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(verified.status, 204);
    assert_eq!(
        store
            .get_sso_provider("mapped-provider")
            .await?
            .unwrap()
            .domain_verified,
        Some(true)
    );
    let updated=Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"mapped-provider","domain":"new-company.test","oidcConfig":{"clientId":"changed-client"}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(updated.status, 200);
    let row = store.get_sso_provider("mapped-provider").await?.unwrap();
    assert_eq!(row.domain, "new-company.test");
    assert_eq!(row.domain_verified, Some(false));
    let oidc: Value = serde_json::from_str(row.oidc_config.as_deref().unwrap())?;
    assert_eq!(oidc["clientId"], "changed-client");
    assert_eq!(oidc["clientSecret"], "durable-secret");
    let auth = build().await?;
    let read = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "getSSOProvider")
                .with_query(&json!({"providerId":"mapped-provider"}))?,
            owned.clone(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(read.status, 200);
    assert_eq!(body(&read)["domain"], "new-company.test");
    let listed =
        Box::pin(auth.dispatch_endpoint(SsoPlugin::list_sso_providers_endpoint(), owned.clone()))
            .await?
            .into_response()?;
    assert_eq!(listed.status, 200);
    assert_eq!(body(&listed)["providers"], json!([body(&read)]));
    assert_eq!(
        store
            .list_sso_providers_by_user(body(&owner)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        1
    );
    let removed = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::delete_sso_provider_endpoint("mapped-provider")?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(removed.status, 200);
    assert!(store.get_sso_provider("mapped-provider").await?.is_none());
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM application_sso_provider", &[])
            .await?,
        0
    );
    let session = call(&auth, request("/get-session", None, &cookies(&owner)), 200).await;
    assert_eq!(body(&session)["user"]["id"], body(&owner)["user"]["id"]);
    B::close(connection).await
}
