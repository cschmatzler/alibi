//! Single consent reads enforce actual ownership and leave durable grants unchanged.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_consent_read_preserves_owned_grant_and_rejects_foreign_owner);
async fn oauth_consent_read_preserves_owned_grant_and_rejects_foreign_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "consent-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email profile","state":"consent-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let producer = auth
        .dispatch_endpoint(
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
        )
        .await?
        .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&producer)["url"].as_str().unwrap())?;
    let signed = url.query().unwrap();
    let accepted = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::oauth2_consent_endpoint(true, Some("email"), Some(signed))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                request: Some(request("/oauth2/consent", None, "")),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(accepted.status, 200);
    let other = signup(&auth, "consent-list-other@example.test").await;
    let listed = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::get_oauth_consents_endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    let expected = body(&listed).as_array().unwrap()[0].clone();
    let consent_id = expected["id"].as_str().unwrap();
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
    for (query, cookie, status, error, description) in [
        (json!({"id":consent_id}), cookies(&owner), 200, "", ""),
        (json!({"id":consent_id}), cookies(&other), 401, "", ""),
        (json!({"id":consent_id}), String::new(), 401, "", ""),
        (
            json!({"id":"unknown-consent"}),
            cookies(&owner),
            404,
            "not_found",
            "no consent",
        ),
        (
            json!({"id":""}),
            cookies(&owner),
            404,
            "not_found",
            "missing id parameter",
        ),
        (json!({"id":42}), cookies(&owner), 400, "", ""),
    ] {
        let result = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthConsent")
                    .with_query(&query)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await;
        if status == 200 {
            let response = match result {
                Ok(output) => output.into_response()?,
                Err(error) => error.error.to_auth_response(),
            };
            assert_eq!(
                response.status, 200,
                "single consent retrieval must be registered"
            );
            assert_eq!(body(&response), expected);
            assert_eq!(body(&response)["clientId"], id);
            assert_eq!(body(&response)["scopes"], json!(["email"]));
        } else {
            let denied = result.unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            if !error.is_empty() {
                let value = denied.body.as_ref().unwrap();
                assert_eq!(value.get("error").unwrap().as_str(), Some(error));
                assert_eq!(
                    value.get("error_description").unwrap().as_str(),
                    Some(description)
                );
            }
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
    Ok(())
}
