//! Consent updates persist client-approved scopes while preserving the grant identity.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_consent_update_persists_allowed_scopes_without_changing_grant_identity);
async fn oauth_consent_update_persists_allowed_scopes_without_changing_grant_identity<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "consent-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email profile","state":"consent-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let producer = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize").with_query(&query)?,
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
    let url = url::Url::parse(ORIGIN)?.join(body(&producer)["url"].as_str().unwrap())?;
    let signed = url.query().unwrap();
    let accepted = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, Some("email"), Some(signed))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request("/oauth2/consent", None, "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(accepted.status, 200);
    let other = signup(&auth, "consent-list-other@example.test").await;
    let listed = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_consents_endpoint(),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let expected = body(&listed).as_array().unwrap()[0].clone();
    let consent_id = expected["id"].as_str().unwrap();
    let start = chrono::Utc::now().timestamp_millis();
    let changed = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthConsent")
                .with_body(&json!({"id":consent_id,"update":{"scopes":["profile"]}}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await;
    let response = match changed {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200, "consent update must be registered");
    let updated = body(&response);
    assert_eq!(updated["id"], consent_id);
    assert_eq!(updated["clientId"], id);
    assert_eq!(updated["userId"], expected["userId"]);
    assert_eq!(updated["createdAt"], expected["createdAt"]);
    assert_eq!(updated["scopes"], json!(["profile"]));
    let time = chrono::DateTime::parse_from_rfc3339(updated["updatedAt"].as_str().unwrap())?
        .timestamp_millis();
    assert!(time >= start / 1000 * 1000);
    assert!(time <= chrono::Utc::now().timestamp_millis());
    for field in ["resources", "referenceId", "requestedUserInfoClaims"] {
        assert_eq!(updated[field], expected[field]);
    }
    let before = db
        .tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
        ])
        .await?;
    for (input, cookie, status, error) in [
        (
            json!({"id":consent_id,"update":{"scopes":["openid"]}}),
            cookies(&owner),
            400,
            "invalid_request",
        ),
        (
            json!({"id":consent_id,"update":{"scopes":["email"]}}),
            cookies(&other),
            401,
            "",
        ),
        (
            json!({"id":consent_id,"update":{"scopes":["email"]}}),
            String::new(),
            401,
            "",
        ),
        (
            json!({"id":"unknown-consent","update":{"scopes":["email"]}}),
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            json!({"id":"","update":{"scopes":["email"]}}),
            cookies(&owner),
            404,
            "not_found",
        ),
        (
            json!({"id":consent_id,"update":{"scopes":[true]}}),
            cookies(&owner),
            400,
            "",
        ),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthConsent")
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
            if error == "invalid_request" {
                assert_eq!(
                    denied
                        .body
                        .as_ref()
                        .unwrap()
                        .get("error_description")
                        .unwrap()
                        .as_str(),
                    Some(
                        format!(
                            "unable to provide scopes to {}",
                            body(&owner)["user"]["id"].as_str().unwrap()
                        )
                        .as_str()
                    )
                );
            }
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
                "oauth_consent"
            ])
            .await?
        );
    }
    let loaded = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_consent_endpoint(consent_id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&loaded), updated);
    let unrelated = db
        .tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
        ])
        .await?;
    let cleared = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthConsent")
                .with_body(&json!({"id":consent_id,"update":{"scopes":[]}}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(cleared.status, 200);
    assert_eq!(body(&cleared)["scopes"], json!([]));
    assert_eq!(body(&cleared)["id"], consent_id);
    assert_eq!(body(&cleared)["createdAt"], expected["createdAt"]);
    let loaded = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_consent_endpoint(consent_id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&loaded), body(&cleared));
    assert_eq!(
        unrelated,
        db.tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client"
        ])
        .await?
    );
    assert_eq!(db.count("oauth_consent").await?, 1);
    Ok(())
}
