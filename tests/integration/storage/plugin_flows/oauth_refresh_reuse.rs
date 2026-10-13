//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_refresh_reuse_replays_encrypted_response_and_preserves_family_on_mismatch);
async fn oauth_refresh_reuse_replays_encrypted_response_and_preserves_family_on_mismatch<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(
            alibi::plugins::OAuthProviderConfig {
                refresh_token_reuse_interval: 60.0,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "reuse-owner@example.test").await;
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
    let input = json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh});
    let issued = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(issued.status, 200);
    let issued = body(&issued);
    let stored = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
        .await?
        .unwrap();
    let encrypted = stored.metadata["rotationReplayResponse"]
        .as_str()
        .expect("reuse interval must persist encrypted replay authority");
    assert!(!encrypted.contains(issued["access_token"].as_str().unwrap()));
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead as _, KeyInit as _},
    };
    let bytes = encrypted
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let plain = XChaCha20Poly1305::new(&sha2::Sha256::digest(SECRET.as_bytes()))
        .decrypt(&XNonce::try_from(&bytes[..24])?, &bytes[24..])
        .map_err(|_| "invalid replay encryption")?;
    let replay: Value = serde_json::from_slice(&plain)?;
    assert_eq!(replay["response"], issued);
    assert_eq!(
        replay["request"]["effectiveScopes"],
        json!(["email", "offline_access"])
    );
    let expires = chrono::DateTime::parse_from_rfc3339(
        stored.metadata["rotationReplayExpiresAt"].as_str().unwrap(),
    )?;
    let rotated =
        chrono::DateTime::parse_from_rfc3339(stored.metadata["rotatedAt"].as_str().unwrap())?;
    assert_eq!(expires.timestamp() - rotated.timestamp(), 60);
    let repeated = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(repeated.status, 200);
    let repeated = body(&repeated);
    for key in [
        "access_token",
        "refresh_token",
        "expires_at",
        "scope",
        "token_type",
    ] {
        assert_eq!(repeated[key], issued[key]);
    }
    assert!(repeated["expires_in"].as_i64().unwrap() <= 3600);
    let mut different = input.clone();
    different["scope"] = json!("email");
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&different)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(different), "")),
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
    assert!(
        auth.store()
            .get_oauth_token(
                OAuthTokenKind::Access,
                &hash(issued["access_token"].as_str().unwrap())
            )
            .await?
            .is_some()
    );
    assert!(
        auth.store()
            .get_oauth_token(
                OAuthTokenKind::Refresh,
                &hash(issued["refresh_token"].as_str().unwrap())
            )
            .await?
            .is_some()
    );
    let recovered = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&recovered)["access_token"], issued["access_token"]);
    let expired_at = (chrono::Utc::now() - chrono::Duration::seconds(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(db.text("UPDATE \"oauthRefreshToken\" SET \"rotationReplayExpiresAt\"=$1 WHERE \"id\"=$2 RETURNING \"id\"",&[&expired_at,&stored.id]).await?,Some(stored.id.clone()));
    let expired = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
        .await?
        .unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(
            expired.metadata["rotationReplayExpiresAt"]
                .as_str()
                .unwrap()
        )? < chrono::Utc::now()
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
        (
            OAuthTokenKind::Access,
            issued["access_token"].as_str().unwrap(),
        ),
        (OAuthTokenKind::Refresh, refresh),
        (
            OAuthTokenKind::Refresh,
            issued["refresh_token"].as_str().unwrap(),
        ),
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
