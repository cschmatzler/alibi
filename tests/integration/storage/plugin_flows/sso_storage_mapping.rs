//! Actual provider lifecycle owns its mapped relation, including restart and DNS writes.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SessionManagementPlugin, SsoConfig, SsoPlugin};
use alibi::store::{SchemaMigrator, SsoProviderStore, VerificationStore};
backend_tests!(
    sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes,
    sso_swapped_columns_preserve_provider_lifecycle_and_domain_writes,
    sso_swapped_domain_columns_match_reference_verification_conflict
);
postgres_tests!(
    sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes,
    sso_swapped_columns_preserve_provider_lifecycle_and_domain_writes,
    sso_swapped_domain_columns_match_reference_verification_conflict
);
async fn sso_mapped_storage_preserves_provider_lifecycle_and_domain_writes<B: Backend>(
    db: Db,
) -> TestResult {
    mapped_lifecycle::<B>(&db, "ordinary").await
}
async fn sso_swapped_columns_preserve_provider_lifecycle_and_domain_writes<B: Backend>(
    db: Db,
) -> TestResult {
    mapped_lifecycle::<B>(&db, "oidc").await
}
async fn sso_swapped_domain_columns_match_reference_verification_conflict<B: Backend>(
    db: Db,
) -> TestResult {
    mapped_lifecycle::<B>(&db, "domain").await
}
async fn mapped_lifecycle<B: Backend>(db: &Db, permutation: &str) -> TestResult {
    let dns = super::sso_dns::start().await;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    if permutation == "domain" {
        super::sso_storage_schema::configure_domain_swapped(&mut config);
    } else if permutation == "oidc" {
        super::sso_storage_schema::configure_swapped(&mut config);
    } else {
        super::sso_storage_schema::configure(&mut config);
    }
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
    assert_eq!(
        physical[0][if permutation == "domain" {
            "domain"
        } else if permutation == "oidc" {
            "oidcConfig"
        } else {
            "application_issuer"
        }],
        input["issuer"]
    );
    assert_eq!(
        physical[0][if permutation == "domain" {
            "issuer"
        } else {
            "application_domain"
        }],
        "company.test"
    );
    assert!(physical[0]["application_org"].is_null());
    assert!(physical[0]["application_saml"].is_null());
    let oidc: Value = serde_json::from_str(
        physical[0][if permutation == "oidc" {
            "issuer"
        } else {
            "application_oidc"
        }]
        .as_str()
        .unwrap(),
    )?;
    assert_eq!(oidc["clientSecret"], "durable-secret");
    let token = body(&created)["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    *dns.records.lock().unwrap() =
        vec![vec![format!("_better-auth-token-mapped-provider={token}")]];
    let verified = match Box::pin(auth.dispatch_endpoint(
        SsoPlugin::verify_domain_endpoint("mapped-provider")?,
        owned.clone(),
    ))
    .await
    {
        Ok(response) => response.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(
        verified.status,
        if permutation == "domain" { 409 } else { 204 }
    );
    if permutation == "domain" {
        assert_eq!(body(&verified)["code"], "SSO_PROVIDER_CHANGED");
        assert_eq!(
            body(&verified)["message"],
            "SSO provider changed while domain verification was in progress. Reload the provider and try again"
        );
    }

    assert_eq!(
        store
            .get_sso_provider("mapped-provider")
            .await?
            .unwrap()
            .domain_verified,
        Some(permutation != "domain")
    );
    assert!(
        store
            .get_latest_verification_by_identifier("_better-auth-token-mapped-provider")
            .await?
            .is_some()
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
