//! Removing a durable resource removes it from actual authorization admission.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_delete_removes_catalog_policy_and_rejects_resource_authorization);
async fn oauth_resource_delete_removes_catalog_policy_and_rejects_resource_authorization<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            enforce_per_client_resources: false,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "resource-delete-owner@example.test").await;
    let other = signup(&auth, "resource-delete-other@example.test").await;
    let resource = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"https://api.fixture.test/delete","allowedScopes":["email"]}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(resource.status, 200);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Deletion observer","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://api.fixture.test/delete","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
            "oauth_resource",
            "oauth_client_resource",
        ])
        .await?;
    for (identifier, cookie, status, error) in [
        ("urn:fixture:missing", cookies(&owner), 404, "not_found"),
        ("https://api.fixture.test/delete", String::new(), 401, ""),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_delete_oauth_resource_endpoint(identifier)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if !error.is_empty() {
            assert_eq!(
                denied.body.as_ref().unwrap().get("error").unwrap().as_str(),
                Some(error)
            );
        }
        assert_eq!(
            before,
            db.tables(&[
                "users",
                "accounts",
                "sessions",
                "verifications",
                "jwks",
                "oauth_client",
                "oauth_consent",
                "oauth_resource",
                "oauth_client_resource"
            ])
            .await?
        );
    }
    let mut http = request(
        "/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Fdelete",
        None,
        &cookies(&owner),
    );
    http.method = alibi::HttpMethod::Delete;
    assert_eq!(Box::pin(auth.handle_request(http)).await?.status, 404);
    let unrelated = db
        .tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
            "oauth_client_resource",
        ])
        .await?;
    let result = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminDeleteOAuthResource")
                .with_params(&json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Fdelete"}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&other))].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200, "resource deletion must be registered");
    assert_eq!(body(&response), json!({"deleted":true}));
    assert_eq!(db.count("oauth_resource").await?, 0);
    assert!(
        auth.store()
            .get_oauth_resource("https://api.fixture.test/delete")
            .await?
            .is_none()
    );
    let missing = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_get_oauth_resource_endpoint("https://api.fixture.test/delete")?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 404);
    let repeated = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_delete_oauth_resource_endpoint(
            "https://api.fixture.test/delete",
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(repeated.error.status_code(), 404);
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
    assert_eq!(url.path(), "/callback");
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "error").unwrap().1,
        "invalid_target"
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "error_description")
            .unwrap()
            .1,
        "requested resource https://api.fixture.test/delete is not configured"
    );
    assert_eq!(
        unrelated,
        db.tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
            "oauth_client_resource"
        ])
        .await?
    );
    Ok(())
}
