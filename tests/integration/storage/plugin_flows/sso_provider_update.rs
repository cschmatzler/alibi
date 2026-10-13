//! Partial updates preserve credentials and respect linked identity boundaries.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::store::{AccountStore, SsoProviderStore};
backend_tests!(sso_provider_update_preserves_omissions_and_rejects_linked_identity_changes);
postgres_tests!(sso_provider_update_preserves_omissions_and_rejects_linked_identity_changes);
async fn sso_provider_update_preserves_omissions_and_rejects_linked_identity_changes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-update-owner@example.test").await;
    let foreign = signup(&auth, "sso-update-foreign@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let created=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"update-provider","issuer":"https://idp.example.com","domain":"original.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"original-secret","skipDiscovery":true,"pkce":true,"scopes":["openid","email"],"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(created.status, 200);
    _ = store
        .create_account(alibi::CreateAccount {
            additional_fields: Default::default(),
            user_id: body(&owner)["user"]["id"].as_str().unwrap().into(),
            provider_id: "update-provider".into(),
            account_id: "linked-subject".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        })
        .await?;
    let endpoint=ServerEndpoint::<Value>::new("sso","updateSSOProvider").with_body(&json!({"providerId":"update-provider","domain":"updated.com","oidcConfig":{"clientSecret":"rotated-secret","scopes":["openid"],"pkce":false}}))?;
    let updated = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(updated.status, 200);
    let data = body(&updated);
    assert_eq!(data["domain"], "updated.com");
    assert_eq!(data["domainVerified"], false);
    assert_eq!(data["oidcConfig"]["scopes"], json!(["openid"]));
    assert_eq!(data["oidcConfig"]["pkce"], false);
    assert_eq!(data["oidcConfig"]["clientIdLastFour"], "****ient");
    assert!(data["oidcConfig"].get("clientSecret").is_none());
    let row = store.get_sso_provider("update-provider").await?.unwrap();
    let config: Value = serde_json::from_str(row.oidc_config.as_deref().unwrap())?;
    assert_eq!(config["clientSecret"], "rotated-secret");
    assert_eq!(config["clientId"], "enterprise-client");
    assert_eq!(config["tokenEndpoint"], "https://idp.example.com/token");
    assert_eq!(config["tokenEndpointAuthentication"], "client_secret_basic");
    for input in [
        json!({"providerId":"update-provider","issuer":"https://other-idp.example.com"}),
        json!({"providerId":"update-provider","oidcConfig":{"clientId":"different-client"}}),
    ] {
        let rejected = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "updateSSOProvider").with_body(&input)?,
            owned.clone(),
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 409);
        assert_eq!(
            body(&rejected.error.to_auth_response()),
            json!({"message":"Cannot change SSO provider identity fields while linked accounts exist"})
        );
        assert_eq!(
            store.get_sso_provider("update-provider").await?.unwrap(),
            row
        );
    }
    let empty = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "updateSSOProvider")
                .with_body(&json!({"providerId":"missing-provider"}))?,
            owned.clone(),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(empty.error.status_code(), 400);
    assert_eq!(
        body(&empty.error.to_auth_response()),
        json!({"message":"No fields provided for update"})
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
        Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
            .await
            .unwrap_err()
            .error
            .status_code(),
        401
    );
    B::close(connection).await
}
