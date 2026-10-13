//! Removing actual client/resource membership revokes resource admission without deleting parents.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_unlink_is_idempotent_and_revokes_linked_client_admission);
async fn oauth_resource_unlink_is_idempotent_and_revokes_linked_client_admission<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "resource-unlink-owner@example.test").await;
    let resource = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"https://api.fixture.test/unlink","allowedScopes":["email"]}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(resource.status, 200);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Unlinked client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&client)["client_id"].as_str().unwrap().to_owned();
    let linked = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_link_client_resource_endpoint(
            "https://api.fixture.test/unlink",
            &id,
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&linked), json!({"linked":true}));
    let other = signup(&auth, "resource-unlink-other@example.test").await;
    let secondary = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"urn:fixture:still-linked","allowedScopes":["email"]}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(secondary.status, 200);
    let second_client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Other linked client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let second_id = body(&second_client)["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (identifier, client_id) in [
        ("urn:fixture:still-linked", id.as_str()),
        ("https://api.fixture.test/unlink", second_id.as_str()),
    ] {
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_link_client_resource_endpoint(identifier, client_id)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&response), json!({"linked":true}));
    }
    let other_rows = auth.store().list_oauth_client_resources(&second_id).await?;
    let other_row = other_rows[0].id.clone();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://api.fixture.test/unlink","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let admitted = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&admitted)["url"].as_str().unwrap())?;
    assert_eq!(url.path(), "/login");
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource",
        ])
        .await?;
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_unlink_client_resource_endpoint(
            "https://api.fixture.test/unlink",
            &id,
        )?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert_eq!(
        before,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource"
        ])
        .await?
    );
    let mut http = request(
        &format!("/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Funlink/clients/{id}"),
        None,
        &cookies(&owner),
    );
    http.method = alibi::HttpMethod::Delete;
    assert_eq!(Box::pin(auth.handle_request(http)).await?.status, 404);
    let unrelated = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
        ])
        .await?;
    let result = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminUnlinkClientResource").with_params(
            &json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Funlink","client_id":id}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&other))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(
        response.status, 200,
        "resource unlinking must be registered"
    );
    assert_eq!(body(&response), json!({"unlinked":true}));
    let remaining = auth.store().list_oauth_client_resources(&id).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].resource_id, "urn:fixture:still-linked");
    assert_eq!(
        auth.store().list_oauth_client_resources(&second_id).await?[0].id,
        other_row
    );
    assert_eq!(db.count("oauthClientResource").await?, 2);
    let state = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource",
        ])
        .await?;
    for (identifier, client_id) in [
        ("https://api.fixture.test/unlink", id.as_str()),
        ("urn:fixture:missing", "missing-client"),
    ] {
        let repeated = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_unlink_client_resource_endpoint(identifier, client_id)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(repeated.status, 200);
        assert_eq!(body(&repeated), json!({"unlinked":true}));
    }
    let rejected = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&rejected)["url"].as_str().unwrap())?;
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "error").unwrap().1,
        "invalid_target"
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "error_description")
            .unwrap()
            .1,
        format!("client {id} is not linked to resource(s) https://api.fixture.test/unlink")
    );
    assert_eq!(
        state,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource"
        ])
        .await?
    );
    assert_eq!(
        unrelated,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource"
        ])
        .await?
    );
    Ok(())
}
