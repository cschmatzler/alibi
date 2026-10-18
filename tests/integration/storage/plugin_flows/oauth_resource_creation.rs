//! Server resource creation persists provider policy and admits the real resource.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
#[path = "../../../fixtures/oauth/resource-privileges.rs"]
mod resource_privileges;
backend_tests!(oauth_resource_creation_persists_policy_and_admits_resource_authorization);
async fn oauth_resource_creation_persists_policy_and_admits_resource_authorization<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            resource_privileges: None,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "resource-owner@example.test").await;
    let policy = Arc::new(resource_privileges::ResourcePrivileges::default());
    let guarded = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            resource_privileges: Some(policy.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let tables = [
        "user",
        "account",
        "session",
        "verification",
        "jwks",
        "oauthClient",
        "oauthConsent",
        "oauthResource",
        "oauthClientResource",
        "oauthAccessToken",
        "oauthRefreshToken",
    ];
    let before_validation = db.tables(&tables).await?;
    for target in [&auth, &guarded] {
        for cookie in [cookies(&owner), String::new()] {
            for (input, message) in [
                (
                    json!({}),
                    "[body.identifier] Invalid input: expected nonoptional, received undefined",
                ),
                (
                    json!({"disabled":"bad","name":42}),
                    "[body.identifier] Invalid input: expected nonoptional, received undefined; [body.name] Invalid input: expected string, received number; [body.disabled] Invalid input: expected boolean, received string",
                ),
                (
                    json!({"identifier":null}),
                    "[body.identifier] Invalid input: expected string, received null",
                ),
                (
                    json!({"identifier":42}),
                    "[body.identifier] Invalid input: expected string, received number",
                ),
                (
                    json!({"identifier":""}),
                    "[body.identifier] Too small: expected string to have >=1 characters",
                ),
                (
                    json!({"name":42,"identifier":null}),
                    "[body.identifier] Invalid input: expected string, received null; [body.name] Invalid input: expected string, received number",
                ),
            ] {
                let error = Box::pin(
                    target.dispatch_endpoint(
                        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(&input)?,
                        EndpointOptions {
                            headers: Some(
                                [
                                    ("cookie".into(), cookie.clone()),
                                    ("x-resource-decision".into(), "false".into()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                            ..Default::default()
                        },
                    ),
                )
                .await
                .unwrap_err();
                assert!(!error.body_absent);
                let mut response = alibi::endpoint::EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                if let Some(headers) = error.headers {
                    response.merge_headers(headers);
                }
                let response = response.to_response()?;
                assert_eq!(response.status, 400);
                assert_eq!(
                    body(&response),
                    json!({"code":"VALIDATION_ERROR","message":message})
                );
                assert_eq!(
                    response.headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert!(response.headers.get("set-cookie").is_none());
                assert!(policy.calls.lock().unwrap().is_empty());
                assert_eq!(db.tables(&tables).await?, before_validation);
            }
        }
    }
    // A schema-valid request reaches the configured callback instead of writing.
    let denied = Box::pin(
        guarded.dispatch_endpoint(
            OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
                &json!({"identifier":"urn:fixture:denied"}),
            )?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("x-resource-decision".into(), "false".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert!(denied.body_absent);
    assert_eq!(policy.calls.lock().unwrap().len(), 1);
    assert_eq!(db.tables(&tables).await?, before_validation);
    let input = json!({"identifier":"https://api.fixture.test/metrics","name":"Metrics","allowedScopes":["email"],"accessTokenTtl":120,"refreshTokenTtl":3600,"signingAlgorithm":"EdDSA","metadata":{"tenant":"fixture"},"customClaims":{"purpose":"metrics"}});
    let start = chrono::Utc::now().timestamp_millis();
    let result = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthResource")
                .with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200, "resource creation must be registered");
    let value = body(&response);
    assert_eq!(value["identifier"], input["identifier"]);
    assert_eq!(value["name"], "Metrics");
    assert_eq!(value["policyVersion"], 1);
    assert_eq!(value["disabled"], false);
    assert_eq!(value["dpopBoundAccessTokensRequired"], false);
    assert_eq!(value["signingKeyId"], Value::Null);
    assert_eq!(value["createdAt"], value["updatedAt"]);
    let issued = chrono::DateTime::parse_from_rfc3339(value["createdAt"].as_str().unwrap())?
        .timestamp_millis();
    assert!(issued >= start);
    assert!(issued <= chrono::Utc::now().timestamp_millis());
    let stored = auth
        .store()
        .get_oauth_resource("https://api.fixture.test/metrics")
        .await?
        .unwrap();
    assert_eq!(stored.id, value["id"].as_str().unwrap());
    assert_eq!(stored.metadata["accessTokenTtl"], 120);
    assert_eq!(stored.metadata["allowedScopes"], json!(["email"]));
    assert_eq!(
        stored.metadata["customClaims"],
        json!({"purpose":"metrics"})
    );
    assert_eq!(stored.metadata["metadata"], json!({"tenant":"fixture"}));
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
        ])
        .await?;
    for (input, cookie, status, error) in [
        (
            json!({"identifier":"https://api.fixture.test/metrics"}),
            cookies(&owner),
            400,
            "invalid_request",
        ),
        (
            json!({"identifier":"/relative"}),
            cookies(&owner),
            400,
            "invalid_target",
        ),
        (
            json!({"identifier":"https://api.fixture.test/fragment#bad"}),
            cookies(&owner),
            400,
            "invalid_target",
        ),
        (
            json!({"identifier":"https://api.fixture.test/no-session"}),
            String::new(),
            401,
            "",
        ),
        (
            json!({"identifier":"https://api.fixture.test/ttl","accessTokenTtl":0}),
            cookies(&owner),
            400,
            "",
        ),
        (
            json!({"identifier":"https://api.fixture.test/ttl","accessTokenTtl":1.5}),
            cookies(&owner),
            400,
            "",
        ),
        (
            json!({"identifier":"https://api.fixture.test/algorithm","signingAlgorithm":"RS384"}),
            cookies(&owner),
            400,
            "",
        ),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthResource")
                    .with_body(&input)?,
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
                "oauthResource"
            ])
            .await?
        );
    }
    let http = request(
        "/admin/oauth2/resources",
        Some(input.clone()),
        &cookies(&owner),
    );
    let hidden = auth.handle_request(http).await?;
    assert_eq!(hidden.status, 404);
    let defaults = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_resource_endpoint(
            &json!({"identifier":"urn:fixture:disabled","disabled":true}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(defaults.status, 200);
    assert_eq!(body(&defaults)["name"], "urn:fixture:disabled");
    assert_eq!(body(&defaults)["allowedScopes"], Value::Null);
    assert_eq!(body(&defaults)["policyVersion"], 1);
    let client=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Resource caller","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://api.fixture.test/metrics","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let unlinked = Box::pin(
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
    let target = url::Url::parse(ORIGIN)?.join(body(&unlinked)["url"].as_str().unwrap())?;
    assert_eq!(
        target
            .query_pairs()
            .find(|(name, _)| name == "error")
            .unwrap()
            .1,
        "invalid_target"
    );
    assert_eq!(
        target
            .query_pairs()
            .find(|(name, _)| name == "error_description")
            .unwrap()
            .1,
        format!(
            "client {} is not linked to resource(s) https://api.fixture.test/metrics",
            body(&client)["client_id"].as_str().unwrap()
        )
    );
    let open = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            enforce_per_client_resources: false,
            ..Default::default()
        }))
        .build()
        .await?;
    let before_auth = db
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
    for (resource, scope, path, error) in [
        ("https://api.fixture.test/metrics", "email", "/login", None),
        (
            "urn:fixture:disabled",
            "email",
            "/callback",
            Some("invalid_target"),
        ),
        (
            "https://api.fixture.test/metrics",
            "profile",
            "/callback",
            Some("invalid_scope"),
        ),
    ] {
        let mut query = query.clone();
        query["resource"] = json!(resource);
        query["scope"] = json!(scope);
        let result = Box::pin(
            open.dispatch_endpoint(
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
        assert_eq!(result.status, 200);
        let target = url::Url::parse(ORIGIN)?.join(body(&result)["url"].as_str().unwrap())?;
        assert_eq!(target.path(), path);
        if let Some(error) = error {
            assert_eq!(
                target
                    .query_pairs()
                    .find(|(key, _)| key == "error")
                    .unwrap()
                    .1,
                error
            );
        }
    }
    assert_eq!(
        before_auth,
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
    assert_eq!(db.count("oauthResource").await?, 2);
    Ok(())
}
