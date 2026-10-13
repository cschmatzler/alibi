//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_refresh_grant_narrows_scope_rotates_and_replay_removes_family);
async fn oauth_refresh_grant_narrows_scope_rotates_and_replay_removes_family<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "refresh-owner@example.test").await;
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

    use alibi::store::OAuthTokenKind;
    let hash = |token: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token))
    };
    let original = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
        .await?
        .unwrap();
    for (input, code, description) in [
        (
            json!({"grant_type":"refresh_token"}),
            "invalid_request",
            "Missing required client_id",
        ),
        (
            json!({"grant_type":"refresh_token","client_id":id}),
            "invalid_request",
            "Missing a required refresh_token for refresh_token grant",
        ),
        (
            json!({"grant_type":"refresh_token","client_id":id,"refresh_token":"missing"}),
            "invalid_grant",
            "session not found",
        ),
        (
            json!({"grant_type":"refresh_token","client_id":"foreign","refresh_token":refresh}),
            "invalid_grant",
            "invalid refresh token",
        ),
        (
            json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh,"scope":"profile"}),
            "invalid_scope",
            "unable to issue scope profile",
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":code,"error_description":description})
        );
        assert_eq!(
            auth.store()
                .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
                .await?
                .unwrap()
                .metadata,
            original.metadata
        );
    }
    let input = json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh,"scope":"email"});
    let rotated = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(rotated.status, 200);
    let rotated = body(&rotated);
    assert_eq!(rotated["scope"], "email");
    assert_eq!(rotated["expires_in"], 3600);
    assert_eq!(rotated["token_type"], "Bearer");
    let next_access = rotated["access_token"].as_str().unwrap();
    let next_refresh = rotated["refresh_token"].as_str().unwrap();
    assert_ne!(next_access, plaintext);
    assert_ne!(next_refresh, refresh);
    assert_eq!(next_access.len(), 32);
    assert_eq!(next_refresh.len(), 32);
    let old = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
        .await?
        .unwrap();
    assert!(!old.metadata["revoked"].is_null());
    assert_eq!(old.metadata["rotatedAt"], old.metadata["revoked"]);
    let next = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash(next_refresh))
        .await?
        .unwrap();
    assert_eq!(next.metadata["scopes"], json!(["email"]));
    assert_eq!(next.metadata["authTime"], original.metadata["authTime"]);
    assert_eq!(next.user_id, original.user_id);
    assert_eq!(next.session_id, original.session_id);
    assert_eq!(next.authorization_code_id, original.authorization_code_id);
    let linked = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Access, &hash(next_access))
        .await?
        .unwrap();
    assert_eq!(linked.metadata["refreshId"], next.id);
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Access, &hash(plaintext))
            .await?
            .is_some()
    );
    let input = json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh});
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_grant","error_description":"invalid refresh token"})
    );
    for (kind, value) in [
        (OAuthTokenKind::Access, plaintext),
        (OAuthTokenKind::Access, next_access),
        (OAuthTokenKind::Refresh, refresh),
        (OAuthTokenKind::Refresh, next_refresh),
    ] {
        assert!(
            auth.store()
                .get_oauth_token(kind, &hash(value))
                .await?
                .is_none()
        );
    }
    Ok(())
}
