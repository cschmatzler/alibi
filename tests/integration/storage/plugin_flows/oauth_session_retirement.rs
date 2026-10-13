//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_signout_retires_bound_access_while_offline_refresh_survives);
async fn oauth_signout_retires_bound_access_while_offline_refresh_survives<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "retirement-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"client_secret_post","skip_consent":true,"grant_types":["authorization_code","refresh_token"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client_secret = body(&created)["client_secret"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email offline_access","state":"token-state","nonce":"oidc-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
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
    let input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":client_secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
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
    assert_eq!(token["scope"], "openid email offline_access");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    let refresh = token["refresh_token"].as_str().unwrap();
    assert_eq!(refresh.len(), 32);

    let other = signup(&auth, "retirement-other@example.test").await;
    let grant = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&other)),
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
    let url = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    let code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let mut other_input = input.clone();
    other_input["code"] = json!(code);
    let issued = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&other_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(other_input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(issued.status, 200);
    let other_access = body(&issued)["access_token"].as_str().unwrap().to_owned();
    assert_ne!(other_access, plaintext);
    use alibi::store::OAuthTokenKind;
    let protected =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(plaintext));
    let before = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Access, &protected)
        .await?
        .unwrap();
    assert!(
        !before
            .metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
    );
    let started = chrono::Utc::now().timestamp_millis();
    let ended = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("session-management", "signOut"),
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("origin".into(), ORIGIN.into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(ended.status, 200);
    let finished = chrono::Utc::now().timestamp_millis();
    let after = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Access, &protected)
        .await?
        .unwrap();
    assert!(
        after
            .metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null()),
        "the bound access row must be marked revoked after session deletion"
    );
    let revoked =
        chrono::DateTime::parse_from_rfc3339(after.metadata["revoked"].as_str().unwrap())?
            .timestamp_millis();
    assert!((started..=finished).contains(&revoked));
    assert_eq!(after.id, before.id);
    assert_eq!(after.session_id, None, "session FK uses SET NULL");
    let denied = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_user_info_endpoint(),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), format!("Bearer {plaintext}"))]
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
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_token","error_description":"Invalid access token"})
    );
    for (token, hint, active) in [
        (plaintext, "access_token", false),
        (refresh, "refresh_token", true),
    ] {
        let input = json!({"client_id":id,"client_secret":client_secret,"token":token,"token_type_hint":hint});
        let observed = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(observed.status, 200);
        assert_eq!(body(&observed)["active"], active);
    }
    let protected =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(refresh));
    let row = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &protected)
        .await?
        .unwrap();
    assert!(
        !row.metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
    );
    let unaffected = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_user_info_endpoint(),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), format!("Bearer {other_access}"))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(unaffected.status, 200);
    assert_eq!(body(&unaffected)["sub"], body(&other)["user"]["id"]);
    Ok(())
}
