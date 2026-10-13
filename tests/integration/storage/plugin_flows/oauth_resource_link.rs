//! Durable resource membership admits the linked client under the default provider policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_link_persists_unique_membership_and_admits_linked_client);
async fn oauth_resource_link_persists_unique_membership_and_admits_linked_client<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "resource-link-owner@example.test").await;
    let resource = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"https://api.fixture.test/link","allowedScopes":["email"]}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(resource.status, 200);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Linked client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&client)["client_id"].as_str().unwrap().to_owned();
    let other = signup(&auth, "resource-link-other@example.test").await;
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://api.fixture.test/link","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let denied = Box::pin(
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
    let url = url::Url::parse(ORIGIN)?.join(body(&denied)["url"].as_str().unwrap())?;
    assert_eq!(
        url.query_pairs()
            .find(|(name, _)| name == "error")
            .unwrap()
            .1,
        "invalid_target"
    );
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
    for (identifier, client_id, cookie, status, error) in [
        (
            "urn:fixture:missing",
            id.as_str(),
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            "https://api.fixture.test/link",
            "unknown-client",
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            "https://api.fixture.test/link",
            id.as_str(),
            String::new(),
            401,
            "",
        ),
    ] {
        let rejected = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_link_client_resource_endpoint(identifier, client_id)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), status);
        if !error.is_empty() {
            assert_eq!(
                rejected
                    .body
                    .as_ref()
                    .unwrap()
                    .get("error")
                    .unwrap()
                    .as_str(),
                Some(error)
            );
        }
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
    }
    let mut http = request(
        &format!("/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Flink/clients/{id}"),
        None,
        &cookies(&owner),
    );
    http.method = alibi::HttpMethod::Post;
    assert_eq!(Box::pin(auth.handle_request(http)).await?.status, 404);
    let start = chrono::Utc::now().timestamp_millis();
    let result = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminLinkClientResource").with_params(
            &json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Flink","client_id":id}),
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
    assert_eq!(response.status, 200, "resource linking must be registered");
    assert_eq!(body(&response), json!({"linked":true}));
    let rows = auth.store().list_oauth_client_resources(&id).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].client_id, id);
    assert_eq!(rows[0].resource_id, "https://api.fixture.test/link");
    assert_eq!(rows[0].metadata, Value::Null);
    let created = rows[0].created_at.unwrap().timestamp_millis();
    assert!(created >= start);
    assert!(created <= chrono::Utc::now().timestamp_millis());
    let row_id = rows[0].id.clone();
    let linked_state = db
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
    let duplicate = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_link_client_resource_endpoint(
            "https://api.fixture.test/link",
            &id,
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(duplicate.status, 200);
    assert_eq!(
        body(&duplicate),
        json!({"linked":true,"alreadyLinked":true})
    );
    assert_eq!(
        auth.store().list_oauth_client_resources(&id).await?[0].id,
        row_id
    );
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
    assert_eq!(
        linked_state,
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
    let removed = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_delete_oauth_resource_endpoint("https://api.fixture.test/link")?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&removed), json!({"deleted":true}));
    assert!(
        auth.store()
            .list_oauth_client_resources(&id)
            .await?
            .is_empty()
    );
    assert_eq!(db.count("oauthClientResource").await?, 0);
    assert!(auth.store().get_oauth_client(&id).await?.is_some());
    Ok(())
}
