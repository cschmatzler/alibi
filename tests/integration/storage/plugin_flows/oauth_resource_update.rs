//! Partial resource updates preserve identity and update real provider policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_update_persists_partial_policy_and_changes_authorization_admission);
async fn oauth_resource_update_persists_partial_policy_and_changes_authorization_admission<
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
    let owner = signup(&auth, "resource-update-owner@example.test").await;
    let original=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_resource_endpoint(&json!({"identifier":"https://api.fixture.test/update","name":"Original","allowedScopes":["email"],"accessTokenTtl":120,"refreshTokenTtl":3600,"signingAlgorithm":"EdDSA","customClaims":{"original":true},"metadata":{"tenant":"old"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(original.status, 200);
    let other = signup(&auth, "resource-update-other@example.test").await;
    let patch = json!({"name":"Updated","allowedScopes":["profile"],"accessTokenTtl":null,"customClaims":null,"metadata":{"tenant":"new"},"identifier":"urn:ignored:rename","policyVersion":99});
    let start = chrono::Utc::now().timestamp_millis();
    let unrelated = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthClientResource",
        ])
        .await?;
    let result = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthResource")
                .with_params(&json!({"identifier":"https%3A%2F%2Fapi.fixture.test%2Fupdate"}))?
                .with_body(&patch)?,
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
    assert_eq!(response.status, 200, "resource update must be registered");
    let updated = body(&response);
    let original = body(&original);
    assert_eq!(updated["id"], original["id"]);
    assert_eq!(updated["identifier"], original["identifier"]);
    assert_eq!(updated["createdAt"], original["createdAt"]);
    assert_eq!(updated["policyVersion"], 1);
    assert_eq!(updated["name"], "Updated");
    assert_eq!(updated["accessTokenTtl"], Value::Null);
    assert_eq!(updated["customClaims"], Value::Null);
    assert_eq!(updated["allowedScopes"], json!(["profile"]));
    assert_eq!(updated["metadata"], json!({"tenant":"new"}));
    assert_eq!(updated["refreshTokenTtl"], original["refreshTokenTtl"]);
    assert_eq!(updated["signingAlgorithm"], original["signingAlgorithm"]);
    let time = chrono::DateTime::parse_from_rfc3339(updated["updatedAt"].as_str().unwrap())?
        .timestamp_millis();
    assert!(time >= start);
    assert!(time <= chrono::Utc::now().timestamp_millis());
    let loaded = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_get_oauth_resource_endpoint("https://api.fixture.test/update")?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&loaded), updated);
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
            "oauthClientResource"
        ])
        .await?
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
    for (identifier, patch, cookie, status, error) in [
        (
            "urn:fixture:missing",
            json!({"name":"Unknown"}),
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            "https://api.fixture.test/update",
            json!({"name":"Unauthorized"}),
            String::new(),
            401,
            "",
        ),
        (
            "https://api.fixture.test/update",
            json!({"allowedScopes":[true]}),
            cookies(&owner),
            400,
            "",
        ),
        (
            "https://api.fixture.test/update",
            json!({"accessTokenTtl":-1}),
            cookies(&owner),
            400,
            "",
        ),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthResource")
                    .with_params(&json!({"identifier":identifier}))?
                    .with_body(&patch)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
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
        "/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Fupdate",
        Some(patch.clone()),
        &cookies(&owner),
    );
    http.method = alibi::HttpMethod::Patch;
    let hidden = Box::pin(auth.handle_request(http)).await?;
    assert_eq!(hidden.status, 404);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Policy observer","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    for (scope, path, error) in [
        ("email", "/callback", Some("invalid_scope")),
        ("profile", "/login", None),
    ] {
        let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":scope,"resource":"https://api.fixture.test/update","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
        let result = Box::pin(
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
        let url = url::Url::parse(ORIGIN)?.join(body(&result)["url"].as_str().unwrap())?;
        assert_eq!(url.path(), path);
        if let Some(error) = error {
            assert_eq!(
                url.query_pairs().find(|(key, _)| key == "error").unwrap().1,
                error
            );
        }
    }
    let disabled = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_update_oauth_resource_endpoint(
            "https://api.fixture.test/update",
            &json!({"disabled":true,"metadata":null}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&disabled)["disabled"], true);
    assert_eq!(body(&disabled)["metadata"], Value::Null);
    assert_eq!(body(&disabled)["name"], "Updated");
    let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"profile","resource":"https://api.fixture.test/update","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
    assert_eq!(db.count("oauthResource").await?, 1);
    Ok(())
}
