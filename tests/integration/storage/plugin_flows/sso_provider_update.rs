//! Partial updates preserve credentials and respect linked identity boundaries.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::store::{AccountStore, SsoProviderStore};
backend_tests!(
    sso_provider_update_preserves_omissions_and_rejects_linked_identity_changes,
    sso_saml_update_merges_nested_credentials_and_guards_linked_identity
);
postgres_tests!(
    sso_provider_update_preserves_omissions_and_rejects_linked_identity_changes,
    sso_saml_update_merges_nested_credentials_and_guards_linked_identity
);
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
    for field in [
        "authorizationEndpoint",
        "tokenEndpoint",
        "userInfoEndpoint",
        "jwksEndpoint",
        "discoveryEndpoint",
    ] {
        for (value, detail) in [
            ("not-a-url", "must be valid"),
            (
                "ftp://idp.example.com/endpoint",
                "must use the http or https supported protocols",
            ),
        ] {
            let mut oidc = serde_json::Map::new();
            _ = oidc.insert(field.into(), json!(value));
            let response = match Box::pin(auth.dispatch_endpoint(
                SsoPlugin::update_sso_provider_endpoint(
                    &json!({"providerId":"update-provider","oidcConfig":oidc}),
                )?,
                owned.clone(),
            ))
            .await
            {
                Ok(output) => output.into_response()?,
                Err(error) => error.error.to_auth_response(),
            };
            assert_eq!(response.status, 400);
            assert_eq!(
                body(&response),
                if value == "not-a-url" {
                    json!({"code":"VALIDATION_ERROR","message":format!("[body.oidcConfig.{field}] Invalid URL")})
                } else {
                    json!({"code":"discovery_invalid_url","message":format!(r#"Invalid OIDC endpoint URL: The url "{field}" {detail}: {value}"#)})
                }
            );
            assert_eq!(
                store.get_sso_provider("update-provider").await?.unwrap(),
                row
            );
        }
    }
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

async fn sso_saml_update_merges_nested_credentials_and_guards_linked_identity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "saml-update-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let registered = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"saml-update-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"privateKey":"original-sp-key","idpMetadata":{"entityID":"https://idp.example.test/entity","privateKey":"original-idp-key","singleSignOnService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST","Location":"https://idp.example.test/post-sso"},{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","Location":"https://idp.example.test/sso"}],"singleLogoutService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST","Location":"https://idp.example.test/logout"}]},"spMetadata":{"entityID":"https://sp.example.test/entity","encPrivateKey":"original-decryption-key"},"idpInitiatedCallbackUrl":format!("{ORIGIN}/idp-complete"),"wantAssertionsSigned":true}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(registered.status, 200);
    let update = json!({"providerId":"saml-update-provider","domain":"updated.test","samlConfig":{"idpMetadata":{"privateKeyPass":"new-passphrase"},"spMetadata":{"privateKey":"nested-sp-key"},"authnRequestsSigned":false}});
    let response = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(&update)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(response.status, 200);
    assert_eq!(body(&response)["domain"], "updated.test");
    assert_eq!(body(&response)["samlConfig"]["authnRequestsSigned"], false);
    let started = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"saml-update-provider","callbackURL":format!("{ORIGIN}/complete")}))?,EndpointOptions::default())).await?.into_response()?;
    let grant = super::saml_idp::grant(
        body(&started)["url"].as_str().unwrap(),
        "saml-updated-user@example.test",
        false,
    )?;
    let completed = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "acsEndpoint")
                .with_params(&json!({"providerId":"saml-update-provider"}))?
                .with_body(&grant)?,
            EndpointOptions::default(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(completed.status, 302);
    assert!(
        store
            .get_account("saml-update-provider", "saml-updated-user@example.test")
            .await?
            .is_some()
    );
    let rotated = Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"saml-update-provider","samlConfig":{"privateKey":"rotated-sp-key","idpInitiatedCallbackUrl":null}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(rotated.status, 200);
    assert!(
        body(&rotated)["samlConfig"]
            .get("idpInitiatedCallbackUrl")
            .is_none()
    );
    let row = store
        .get_sso_provider("saml-update-provider")
        .await?
        .ok_or("Missing updated provider")?;
    let config: Value = serde_json::from_str(row.saml_config.as_deref().unwrap())?;
    assert_eq!(config["privateKey"], "rotated-sp-key");
    assert_eq!(config["idpMetadata"]["privateKey"], "original-idp-key");
    assert_eq!(config["idpMetadata"]["privateKeyPass"], "new-passphrase");
    assert_eq!(
        config["idpMetadata"]["singleLogoutService"][0]["Location"],
        "https://idp.example.test/logout"
    );
    assert_eq!(
        config["spMetadata"]["encPrivateKey"],
        "original-decryption-key"
    );
    assert_eq!(config["spMetadata"]["privateKey"], "nested-sp-key");
    for change in [
        json!({"idpMetadata":{"singleSignOnService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","Location":"https://other-idp.example.test/sso"},{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST","Location":"https://idp.example.test/post-sso"}]}}),
        json!({"idpMetadata":{"singleSignOnService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","Location":"https://idp.example.test/sso"},{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST","Location":"https://other-idp.example.test/post-sso"}]}}),
        json!({"audience":"urn:other:audience"}),
        json!({"idpMetadata":{"entityID":"https://other-idp.example.test/entity"}}),
        json!({"cert":"different-trust-anchor"}),
        json!({"spMetadata":{"entityID":"https://other-sp.example.test/entity"}}),
        json!({"wantAssertionsSigned":false}),
    ] {
        let rejected = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::update_sso_provider_endpoint(
                &json!({"providerId":"saml-update-provider","samlConfig":change}),
            )?,
            owned.clone(),
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 409);
        assert_eq!(
            store
                .get_sso_provider("saml-update-provider")
                .await?
                .unwrap(),
            row
        );
    }
    let unused = Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"saml-update-provider","samlConfig":{"entryPoint":"https://unused.example.test/changed"}}))?,owned)).await?.into_response()?;
    assert_eq!(unused.status, 200);
    let started = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"saml-update-provider","callbackURL":format!("{ORIGIN}/complete")}))?,EndpointOptions::default())).await?.into_response()?;
    let url = url::Url::parse(body(&started)["url"].as_str().unwrap())?;
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://idp.example.test"
    );
    assert_eq!(url.path(), "/sso");
    B::close(connection).await
}
