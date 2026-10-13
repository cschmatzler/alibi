//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_revocation_retires_access_and_revokes_refresh_family);
async fn oauth_revocation_retires_access_and_revokes_refresh_family<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "revocation-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"client_secret_post","skip_consent":true,"grant_types":["authorization_code","refresh_token"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let secret = body(&created)["client_secret"].as_str().unwrap().to_owned();
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
    let input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
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

    let hash = |value: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(value))
    };
    let revoke_input = json!({"client_id":id,"client_secret":secret,"token":plaintext,"token_type_hint":"access_token"});
    let revoked = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&revoke_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(revoke_input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(revoked.status, 200);
    assert!(revoked.body.is_empty());
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
            .is_some()
    );
    let repeated = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&revoke_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(revoke_input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(repeated.error.status_code(), 400);
    assert_eq!(
        repeated.body.unwrap().to_json_value()?,
        json!({"error":"invalid_request","error_description":"Invalid access token"})
    );
    let second = Box::pin(
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
    let second_url = url::Url::parse(body(&second)["url"].as_str().unwrap())?;
    let code = second_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let second_input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let second_tokens = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&second_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(second_input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let second_tokens = body(&second_tokens);
    let second_access = second_tokens["access_token"].as_str().unwrap();
    let second_refresh = second_tokens["refresh_token"].as_str().unwrap();
    let revocation_started = chrono::Utc::now().timestamp();
    let revoke_input = json!({"client_id":id,"client_secret":secret,"token":second_refresh,"token_type_hint":"refresh_token"});
    let revoked = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&revoke_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(revoke_input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(revoked.status, 200);
    assert!(revoked.body.is_empty());
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash(second_access))
            .await?
            .is_none()
    );
    let row = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(second_refresh))
        .await?
        .unwrap();
    let revocation_time =
        chrono::DateTime::parse_from_rfc3339(row.metadata["revoked"].as_str().unwrap())?;
    assert_eq!(revocation_time.timestamp_subsec_nanos(), 0);
    assert!(revocation_time.timestamp() >= revocation_started);
    assert!(revocation_time.timestamp() <= chrono::Utc::now().timestamp());
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(refresh))
            .await?
            .is_some()
    );
    let introspect_input = json!({"client_id":id,"client_secret":secret,"token":second_refresh,"token_type_hint":"refresh_token"});
    let inactive = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect")
                .with_body(&introspect_input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(introspect_input), "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(body(&inactive), json!({"active":false}));
    let repeated = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&revoke_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(revoke_input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(repeated.error.status_code(), 400);
    assert_eq!(
        repeated.body.unwrap().to_json_value()?,
        json!({"error":"invalid_request","error_description":"refresh token revoked"})
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(refresh))
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(second_refresh))
            .await?
            .is_none()
    );
    let race_grant = Box::pin(
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
    let race_url = url::Url::parse(body(&race_grant)["url"].as_str().unwrap())?;
    let code = race_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let race_input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let race_tokens = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&race_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(race_input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let race_tokens = body(&race_tokens);
    let race_access = race_tokens["access_token"].as_str().unwrap();
    let race_refresh = race_tokens["refresh_token"].as_str().unwrap();

    let input = json!({"client_id":id,"client_secret":secret,"token":race_refresh,"token_type_hint":"refresh_token"});
    let first = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(input.clone()), "")),
            ..Default::default()
        },
    ));
    let second = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/revoke", Some(input.clone()), "")),
            ..Default::default()
        },
    ));
    let (first, second) = tokio::join!(first, second);
    let status = |result: Result<
        alibi::endpoint::EndpointOutput<Value>,
        alibi::endpoint::EndpointError,
    >|
     -> u16 {
        match result {
            Ok(output) => output.into_response().unwrap().status,
            Err(error) => error.error.status_code(),
        }
    };
    let mut statuses = [status(first), status(second)];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 400]);
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash(race_refresh))
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash(race_access))
            .await?
            .is_none()
    );
    Ok(())
}
