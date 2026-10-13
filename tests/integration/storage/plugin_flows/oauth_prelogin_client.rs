//! Prelogin display lookup consumes the genuine authorization proof without a session.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_prelogin_client_requires_signed_authorization);
async fn oauth_prelogin_client_requires_signed_authorization<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "prelogin-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Prelogin client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClientPublicPrelogin")
                .with_body(&json!({"client_id":id,"oauth_query":signed}))?,
            EndpointOptions::default(),
        )
        .await;
    let denied = output.unwrap_err();
    assert_eq!(
        denied.error.status_code(),
        400,
        "disabled policy must reject before lookup"
    );
    assert!(denied.body_absent);
    let enabled = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            allow_public_client_prelogin: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
        ])
        .await?;
    let tampered = signed.replace("sig=", "sig=tampered");
    for (input, status, error) in [
        (json!({"client_id":id,"oauth_query":signed}), 200, None),
        (json!({"client_id":id}), 401, Some("invalid_signature")),
        (
            json!({"client_id":id,"oauth_query":tampered}),
            400,
            Some("invalid_signature"),
        ),
        (
            json!({"client_id":id,"oauth_query":format!("{signed}&sig=duplicate")}),
            400,
            Some("invalid_signature"),
        ),
        (
            json!({"client_id":"missing-client","oauth_query":signed}),
            404,
            Some("not_found"),
        ),
    ] {
        let output = enabled
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClientPublicPrelogin")
                    .with_body(&input)?,
                EndpointOptions::default(),
            )
            .await;
        if let Some(error) = error {
            let denied = output.unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            assert_eq!(
                denied.body.as_ref().unwrap().get("error").unwrap().as_str(),
                Some(error)
            );
        } else {
            let response = output?.into_response()?;
            assert_eq!(response.status, status);
            assert_eq!(
                body(&response),
                json!({"client_id":id,"client_name":"Prelogin client","client_uri":"https://app.fixture.test","redirect_uris":[]})
            );
        }
    }
    let expired = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            code_expires_in: -1.0,
            ..Default::default()
        }))
        .build()
        .await?;
    let produced = expired
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
    let url = url::Url::parse(ORIGIN)?.join(body(&produced)["url"].as_str().unwrap())?;
    let rejected = enabled
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClientPublicPrelogin")
                .with_body(&json!({"client_id":id,"oauth_query":url.query().unwrap()}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.error.status_code(), 400);
    assert_eq!(
        rejected
            .body
            .as_ref()
            .unwrap()
            .get("error")
            .unwrap()
            .as_str(),
        Some("invalid_signature")
    );
    assert_eq!(
        before,
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
