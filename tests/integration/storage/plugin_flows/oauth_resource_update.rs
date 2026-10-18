//! Partial resource updates preserve identity and update real provider policy.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
#[path = "../../../fixtures/oauth/resource-privileges.rs"]
mod resource_privileges;
backend_tests!(oauth_resource_update_persists_partial_policy_and_changes_authorization_admission);
async fn oauth_resource_update_persists_partial_policy_and_changes_authorization_admission<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let identifier = format!("https://api.fixture.test/update/{}", uuid::Uuid::new_v4());
    let encoded_identifier =
        url::form_urlencoded::byte_serialize(identifier.as_bytes()).collect::<String>();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            enforce_per_client_resources: false,
            cached_resources: [identifier.clone()].into_iter().collect(),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "resource-update-owner@example.test").await;
    let original=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_resource_endpoint(&json!({"identifier":identifier,"name":"Original","allowedScopes":["email"],"accessTokenTtl":120,"refreshTokenTtl":3600,"signingAlgorithm":"EdDSA","customClaims":{"original":true},"metadata":{"tenant":"old"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
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
                .with_params(&json!({"identifier":encoded_identifier}))?
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
        OAuthProviderPlugin::admin_get_oauth_resource_endpoint(&identifier)?,
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
            "oauthAccessToken",
            "oauthRefreshToken",
        ])
        .await?;
    let policy = Arc::new(resource_privileges::ResourcePrivileges::default());
    let guarded = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            resource_privileges: Some(policy.clone()),
            ..Default::default()
        }))
        .build()
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
            identifier.as_str(),
            json!({"name":"Unauthorized"}),
            String::new(),
            401,
            "",
        ),
        (
            identifier.as_str(),
            json!({"allowedScopes":[true]}),
            cookies(&owner),
            400,
            "",
        ),
        (
            identifier.as_str(),
            json!({"accessTokenTtl":-1}),
            cookies(&owner),
            400,
            "",
        ),
        (
            "https://api.fixture.test/update",
            json!({"identifier":null}),
            cookies(&owner),
            400,
            "[body.identifier] Invalid input: expected string, received null",
        ),
        (
            "https://api.fixture.test/update",
            json!({"identifier":42}),
            cookies(&owner),
            400,
            "[body.identifier] Invalid input: expected string, received number",
        ),
        (
            "https://api.fixture.test/update",
            json!({"identifier":""}),
            cookies(&owner),
            400,
            "[body.identifier] Too small: expected string to have >=1 characters",
        ),
        (
            "https://api.fixture.test/update",
            json!({"disabled":"bad","name":42}),
            String::new(),
            400,
            "[body.name] Invalid input: expected string, received number; [body.disabled] Invalid input: expected boolean, received string",
        ),
        (
            "https://api.fixture.test/update",
            json!({"name":42,"identifier":null}),
            cookies(&owner),
            400,
            "[body.identifier] Invalid input: expected string, received null; [body.name] Invalid input: expected string, received number",
        ),
    ] {
        let denied = Box::pin(
            guarded.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthResource")
                    .with_params(&json!({"identifier":identifier}))?
                    .with_body(&patch)?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookie),
                            (
                                "x-resource-decision".into(),
                                if status == 400 { "false" } else { "true" }.into(),
                            ),
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
        assert_eq!(denied.error.status_code(), status);
        let calls = std::mem::take(&mut *policy.calls.lock().unwrap());
        assert_eq!(calls.len(), usize::from(status == 404));
        if error.starts_with("[body.") {
            assert!(!denied.body_absent);
            let mut response = alibi::endpoint::EndpointResponse::error(denied.error);
            if let Some(body) = denied.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = denied.headers {
                response.merge_headers(headers);
            }
            let response = response.to_response()?;
            assert_eq!(response.status, 400);
            assert_eq!(
                body(&response),
                json!({"code":"VALIDATION_ERROR","message":error})
            );
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert!(response.headers.get("set-cookie").is_none());
        } else if !error.is_empty() {
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
                "oauthClientResource",
                "oauthAccessToken",
                "oauthRefreshToken"
            ])
            .await?
        );
    }
    let denied = Box::pin(
        guarded.dispatch_endpoint(
            OAuthProviderPlugin::admin_update_oauth_resource_endpoint(
                "https://api.fixture.test/update",
                &json!({"name":"Denied"}),
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
    assert_eq!(
        db.tables(&[
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
            "oauthRefreshToken"
        ])
        .await?,
        before
    );
    let mut http = request(
        &format!("/admin/oauth2/resources/{encoded_identifier}"),
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
        let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":scope,"resource":identifier,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
            &identifier,
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
    let query = json!({"client_id":body(&client)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"profile","resource":identifier,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
