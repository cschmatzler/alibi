//! Revoking a durable consent restores the real authorization consent requirement.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_consent_delete_removes_owned_grant_and_requires_consent_again);
async fn oauth_consent_delete_removes_owned_grant_and_requires_consent_again<B: Backend>(
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
    assert_eq!(expected["userId"], body(&owner)["user"]["id"]);
    let grant_query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"consent-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let before_redirect = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&grant_query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
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
    let before_url = url::Url::parse(body(&before_redirect)["url"].as_str().unwrap())?;
    assert_eq!(before_url.host_str(), Some("app.fixture.test"));
    assert!(
        before_url
            .query_pairs()
            .any(|(name, value)| name == "code" && value.len() == 32)
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
        ])
        .await?;
    for (input, cookie, status, error) in [
        (json!({"id":consent_id}), cookies(&other), 401, ""),
        (json!({"id":consent_id}), String::new(), 401, ""),
        (
            json!({"id":"unknown-consent"}),
            cookies(&owner),
            404,
            "not_found",
        ),
        (json!({"id":""}), cookies(&owner), 404, "not_found"),
        (json!({"id":42}), cookies(&owner), 400, ""),
    ] {
        let result = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "deleteOAuthConsent")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await;
        assert_eq!(
            result.as_ref().err().map(|error| error.error.status_code()),
            Some(status),
            "consent deletion must enforce actual grant ownership"
        );
        let denied = result.unwrap_err();
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
                "oauthConsent"
            ])
            .await?
        );
    }
    let unrelated = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
        ])
        .await?;
    let deleted = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::delete_oauth_consent_endpoint(consent_id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(deleted.status, 200);
    assert!(deleted.body.is_empty());
    assert_eq!(
        deleted.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(db.count("oauthConsent").await?, 0);
    let missing = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_consent_endpoint(consent_id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 404);
    let repeated = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::delete_oauth_consent_endpoint(consent_id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(repeated.error.status_code(), 404);
    let reprompt = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&grant_query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
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
    assert_eq!(reprompt.status, 200);
    let url = url::Url::parse(ORIGIN)?.join(body(&reprompt)["url"].as_str().unwrap())?;
    assert_eq!(url.path(), "/consent");
    assert!(!url.query_pairs().any(|(name, _)| name == "code"));
    assert_eq!(
        unrelated,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient"
        ])
        .await?
    );
    Ok(())
}
