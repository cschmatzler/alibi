//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_offline_code_issues_linked_refresh_and_replay_removes_both);
async fn oauth_offline_code_issues_linked_refresh_and_replay_removes_both<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "offline-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"none","skip_consent":true,"grant_types":["authorization_code","refresh_token"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email offline_access","state":"token-state","code_challenge":challenge,"code_challenge_method":"S256"});
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
    assert_eq!(token["scope"], "email offline_access");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    let refresh = token["refresh_token"]
        .as_str()
        .expect("offline_access must issue a refresh token");
    assert_eq!(refresh.len(), 32);
    assert!(refresh.bytes().all(|byte| byte.is_ascii_alphabetic()));
    assert!(token.get("id_token").is_none());

    let hash = |token: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token))
    };
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(refresh))
        .await?
        .unwrap();
    let access = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash(plaintext))
        .await?
        .unwrap();
    assert_eq!(stored.client_id, id);
    assert_eq!(stored.user_id, access.user_id);
    assert_eq!(stored.session_id, access.session_id);
    assert_eq!(stored.authorization_code_id, Some(hash(&code)));
    assert_eq!(
        stored.metadata["scopes"],
        json!(["email", "offline_access"])
    );
    assert_eq!(stored.metadata["resources"], Value::Null);
    assert_eq!(
        stored.expires_at.timestamp() - stored.created_at.timestamp(),
        2_592_000
    );
    assert_eq!(access.metadata["refreshId"], stored.id);
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let auth_time =
        chrono::DateTime::parse_from_rfc3339(stored.metadata["authTime"].as_str().unwrap())?;
    let actual_created = chrono::DateTime::parse_from_rfc3339(
        body(&observed)["session"]["createdAt"].as_str().unwrap(),
    )?;
    assert_eq!(
        auth_time.timestamp_millis(),
        actual_created.timestamp_millis()
    );
    assert!(stored.metadata["authTime"].as_str().is_some());
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, refresh)
            .await?
            .is_none()
    );
    let replay = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_grant","error_description":"invalid code"})
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash(plaintext))
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(refresh))
            .await?
            .is_none()
    );
    Ok(())
}
