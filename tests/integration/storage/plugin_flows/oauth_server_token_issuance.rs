//! Trusted issuance creates usable authority without replaying an authorization-code endpoint.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
use alibi::plugins::{OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin};
use alibi::store::OAuthTokenKind;
use alibi::{AuthSession as _, AuthUser as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(oauth_server_issue_tokens_persists_machine_user_and_signed_authority);
postgres_tests!(oauth_server_issue_tokens_persists_machine_user_and_signed_authority);
async fn oauth_server_issue_tokens_persists_machine_user_and_signed_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "server-issuance@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Trusted issuer","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let owner_id = client.user_id.as_deref().unwrap();
    let user = auth.store().get_user_by_id(owner_id).await?.unwrap();
    let session = auth
        .store()
        .get_user_sessions(owner_id)
        .await?
        .into_iter()
        .next()
        .unwrap();
    let issuer = format!(
        "{}{}",
        auth.config().base_url.trim_end_matches('/'),
        auth.config().base_path
    );
    let userinfo = format!("{issuer}/oauth2/userinfo");
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "issueTokensFixture",
            operation_id: "issueTokensFixture",
            path: Some("/fixture/issue-tokens".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let params = OAuthTokenIssueParams::new(client.clone(), vec!["email".into()]);
    let denied = provider
        .issue_tokens(auth.context(), &call, None, &params)
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 500);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"server_error","error_description":"issueTokens requires a grant type; pass it to getOAuthProviderApi(ctx, opts, grantType)."})
    );
    for name in ["machine", "user", "openid", "resource", "bound"] {
        let with_user = matches!(name, "user" | "openid" | "bound");
        let scopes = if name == "openid" {
            vec!["openid".into(), "email".into()]
        } else if name == "resource" {
            vec!["email".into()]
        } else {
            vec!["email".into(), "offline_access".into()]
        };
        let mut params = OAuthTokenIssueParams::new(client.clone(), scopes.clone());
        params.token_response =
            Some(json!({"access_token":"injected","scope":"injected","custom":"receipt"}));
        if with_user {
            params.user = Some(auth.context().trusted_user_view(&user));
        }
        if name == "user" {
            params.session_id = Some(session.id().as_ref().into());
            params.reference_id = Some("reference-123".into());
            params.auth_time = Some(session.created_at());
            params.requested_user_info_claims = Some(vec!["email".into()]);
        }
        if name == "openid" {
            params.nonce = Some("nonce-123".into());
            params.id_token_claims = Some(
                json!({"sub":"injected","at_hash":"injected","email":"injected","custom":"receipt"}),
            );
        }
        if name == "resource" {
            params.resources = Some(vec![userinfo.clone()]);
            params.access_token_claims =
                Some(json!({"sub":"injected","iss":"injected","custom":"receipt"}));
        }
        if name == "bound" {
            params.confirmation = Some(json!({"jkt":"bound-key"}));
        }
        let issued = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await?;
        assert_eq!(issued["scope"], scopes.join(" "));
        assert_eq!(issued["custom"], "receipt");
        assert_eq!(issued["expires_in"], 3600);
        assert_eq!(
            issued["token_type"],
            if name == "bound" { "DPoP" } else { "Bearer" }
        );
        let access = issued["access_token"].as_str().unwrap();
        if name == "resource" {
            let claims = verified_claims(auth.context(), access).await?;
            assert_eq!(claims["sub"], id);
            assert_eq!(claims["aud"], userinfo);
            assert_eq!(claims["client_id"], id);
            assert_eq!(claims["azp"], id);
            assert_eq!(claims["iss"], issuer);
            assert_eq!(claims["custom"], "receipt");
            assert_eq!(claims["scope"], "email");
        } else {
            assert_eq!(access.len(), 32);
            assert!(access.bytes().all(|byte| byte.is_ascii_alphabetic()));
            let row = auth
                .store()
                .get_oauth_token(
                    OAuthTokenKind::Access,
                    &URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(access)),
                )
                .await?
                .unwrap();
            assert_eq!(row.client_id, id);
            assert_eq!(
                row.user_id.as_deref(),
                with_user.then_some(user.id().as_ref())
            );
            assert_eq!(row.metadata["scopes"], json!(scopes));
            if name == "user" {
                assert_eq!(row.session_id.as_deref(), Some(session.id().as_ref()));
                assert_eq!(row.metadata["referenceId"], "reference-123");
                assert_eq!(row.metadata["requestedUserInfoClaims"], json!(["email"]));
            }
            if name == "bound" {
                assert_eq!(row.metadata["confirmation"], json!({"jkt":"bound-key"}));
            }
            if with_user && name != "openid" {
                let refresh = issued["refresh_token"].as_str().unwrap();
                let retained = auth
                    .store()
                    .get_oauth_token(
                        OAuthTokenKind::Refresh,
                        &URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(refresh)),
                    )
                    .await?
                    .unwrap();
                assert_eq!(row.metadata["refreshId"], retained.id);
                assert_eq!(retained.user_id, row.user_id);
                assert_eq!(retained.metadata["scopes"], json!(scopes));
                if name == "user" {
                    assert_eq!(retained.metadata["referenceId"], "reference-123");
                    assert_eq!(
                        retained.metadata["requestedUserInfoClaims"],
                        json!(["email"])
                    );
                }
            } else {
                assert!(issued.get("refresh_token").is_none());
            }
        }
        if name == "openid" {
            let claims =
                verified_claims(auth.context(), issued["id_token"].as_str().unwrap()).await?;
            assert_eq!(claims["sub"], user.id().as_ref());
            assert_eq!(claims["aud"], id);
            assert_eq!(claims["nonce"], "nonce-123");
            assert_eq!(claims["custom"], "receipt");
            assert!(claims.get("email").is_none());
            assert_eq!(
                claims["at_hash"],
                URL_SAFE_NO_PAD.encode(&sha2::Sha512::digest(access)[..32])
            );
        } else {
            assert!(issued.get("id_token").is_none());
        }
    }
    Ok(())
}
async fn verified_claims<S: alibi::AuthSchema>(
    ctx: &alibi::AuthContext<S>,
    token: &str,
) -> TestResult<Value> {
    use ed25519_dalek::Verifier as _;
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let keys = ctx.database.list_jwks().await?;
    let key = keys
        .iter()
        .find(|key| Some(key.id.as_str()) == header["kid"].as_str())
        .unwrap();
    let public: Value = serde_json::from_str(&key.public_key)?;
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public["x"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)?
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?)
}
