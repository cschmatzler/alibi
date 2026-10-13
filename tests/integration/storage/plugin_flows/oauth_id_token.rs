//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_openid_code_issues_verified_client_and_access_bound_id_token);
async fn oauth_openid_code_issues_verified_client_and_access_bound_id_token<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oidc-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":"none","skip_consent":true}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
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

    let id_token = token["id_token"]
        .as_str()
        .expect("openid must issue a signed ID token");
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let issuer = format!(
        "{}{}",
        auth.context().config.base_url,
        auth.context().config.base_path
    );
    let verifier =
        alibi::plugins::jwt::JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                issuer: Some(issuer.clone()),
                audience: Some(alibi::plugins::jwt::JwtAudience::One(id.clone())),
                ..Default::default()
            },
            ..Default::default()
        });
    let payload = verifier
        .verify_jwt(id_token, Some(&issuer), None, auth.context())
        .await?
        .expect("ID token must verify against the actual persisted JWK");
    assert_eq!(payload["iss"], issuer);
    assert_eq!(payload["aud"], id);
    assert_eq!(payload["sub"], body(&observed)["user"]["id"]);
    assert_eq!(payload["nonce"], "oidc-nonce");
    assert_eq!(payload["acr"], "0");
    let actual_time = chrono::DateTime::parse_from_rfc3339(
        body(&observed)["session"]["createdAt"].as_str().unwrap(),
    )?
    .timestamp();
    assert_eq!(payload["auth_time"], actual_time);
    assert_eq!(
        payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
        36_000
    );
    let digest = sha2::Sha512::digest(plaintext);
    let expected_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..32]);
    assert_eq!(payload["at_hash"], expected_hash);
    for field in ["email", "email_verified", "name", "picture", "sid"] {
        assert!(!payload.contains_key(field));
    }
    let parts = id_token.split('.').collect::<Vec<_>>();
    let mut signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;
    signature[0] ^= 1;
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );
    assert!(
        verifier
            .verify_jwt(&tampered, Some(&issuer), None, auth.context())
            .await?
            .is_none()
    );
    let foreign =
        alibi::plugins::jwt::JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                audience: Some(alibi::plugins::jwt::JwtAudience::One(
                    "foreign-client".into(),
                )),
                ..Default::default()
            },
            ..Default::default()
        });
    assert!(
        foreign
            .verify_jwt(id_token, Some(&issuer), None, auth.context())
            .await?
            .is_none()
    );
    Ok(())
}
