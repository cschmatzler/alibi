//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_end_session_verifies_hint_and_deletes_only_its_real_session);
async fn oauth_end_session_verifies_hint_and_deletes_only_its_real_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "logout-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":"none","skip_consent":true,"enable_end_session":true,"post_logout_redirect_uris":["https://app.fixture.test/logout"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email profile","state":"token-state","nonce":"oidc-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
    let grant = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
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
    assert_eq!(grant.status, 200);
    let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    assert_eq!(callback.path(), "/callback");
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let endpoint =
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?;
    let output = Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(output.status, 200);
    let token = body(&output);
    assert_eq!(token["scope"], "openid email profile");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());

    let hint = token["id_token"].as_str().unwrap();
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(hint.split('.').nth(1).unwrap())?,
    )?;
    assert_eq!(claims["sid"], body(&observed)["session"]["id"]);
    assert_eq!(claims["sub"], body(&owner)["user"]["id"]);
    for (input, status, error, description) in [
        (
            json!({}),
            400,
            "invalid_request",
            "No active session is available for logout",
        ),
        (
            json!({"client_id":"missing"}),
            400,
            "invalid_client",
            "The logout client does not exist",
        ),
        (
            json!({"client_id":id,"id_token_hint":"tampered"}),
            401,
            "invalid_token",
            "The id_token_hint is invalid",
        ),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2EndSession")
                    .with_query(&input)?,
                EndpointOptions::default(),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
    }
    let input = json!({"client_id":id});
    let denied = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2EndSession").with_query(&input)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_request","error_description":"User confirmation is required to complete logout"})
    );
    let unrelated = signup(&auth, "logout-other@example.test").await;
    let input = json!({"id_token_hint":hint,"post_logout_redirect_uri":"https://app.fixture.test/logout","state":"logout-state"});
    let ended = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2EndSession").with_query(&input)?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(ended.error.status_code(), 302);
    assert_eq!(
        ended
            .headers
            .as_ref()
            .and_then(|headers| headers.get("content-type"))
            .map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        ended.headers.unwrap().get("location").map(String::as_str),
        Some("https://app.fixture.test/logout?state=logout-state")
    );
    for (owner, live) in [(&owner, false), (&unrelated, true)] {
        let observed = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("session-management", "getSession"),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(!body(&observed).is_null(), live);
    }
    let repeated=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","oauth2EndSession").with_query(&json!({"id_token_hint":hint,"post_logout_redirect_uri":"https://evil.fixture.test/logout"}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(repeated.status, 200);
    assert_eq!(body(&repeated), Value::Null);
    Ok(())
}
