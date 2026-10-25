//! Trusted issuance creates usable authority without replaying an authorization-code endpoint.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
use alibi::plugins::{OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin};
use alibi::store::OAuthTokenKind;
use alibi::{AuthSession as _, AuthUser as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::Digest as _;
backend_tests!(
    oauth_server_issue_tokens_persists_machine_user_and_signed_authority,
    oauth_sender_confirmation_survives_validation_and_introspection,
    oauth_jwt_introspection_uses_live_resource_peer_authority,
    oauth_requested_userinfo_claims_follow_opaque_refresh_authority
);
postgres_tests!(
    oauth_server_issue_tokens_persists_machine_user_and_signed_authority,
    oauth_sender_confirmation_survives_validation_and_introspection,
    oauth_jwt_introspection_uses_live_resource_peer_authority,
    oauth_requested_userinfo_claims_follow_opaque_refresh_authority
);
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
                json!({"sub":"injected","at_hash":"injected","email":"injected","s_hash":"injected","nickname":"Custom nickname","custom":"receipt"}),
            );
        }
        if name == "resource" {
            params.resources = Some(vec![userinfo.clone()]);
            params.access_token_claims = Some(
                json!({"sub":"injected","iss":"injected","auth_time":123,"acr":"injected","amr":["injected"],"custom":"receipt"}),
            );
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
            for key in ["auth_time", "acr", "amr"] {
                assert!(claims.get(key).is_none());
            }
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
            assert!(claims.get("s_hash").is_none());
            assert_eq!(claims["nickname"], "Custom nickname");
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
async fn oauth_sender_confirmation_survives_validation_and_introspection<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "confirmation-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Confirmation consumer","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let created = body(&created);
    let id = created["client_id"].as_str().unwrap();
    let client = provider.get_client(auth.context(), id).await?.unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
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
    for (confirmation, kind, present) in [
        (json!({"jkt":"bound-key"}), "DPoP", true),
        (json!({"x5t#S256":"certificate"}), "Bearer", true),
        (json!({"jkt":""}), "Bearer", true),
        (json!({"jkt":17}), "Bearer", true),
        (json!({}), "Bearer", true),
        (json!([]), "Bearer", true),
        (json!(false), "Bearer", false),
        (Value::Null, "Bearer", false),
    ] {
        let mut params = OAuthTokenIssueParams::new(
            client.clone(),
            vec!["email".into(), "offline_access".into()],
        );
        params.user = Some(auth.context().trusted_user_view(&user));
        params.confirmation = Some(confirmation.clone());
        let issued = provider
            .issue_tokens(
                auth.context(),
                &call,
                Some("urn:fixture:confirmation"),
                &params,
            )
            .await?;
        assert_eq!(issued["token_type"], kind);
        let mut payloads = vec![
            provider
                .validate_access_token(
                    auth.context(),
                    issued["access_token"].as_str().unwrap(),
                    None,
                )
                .await?,
        ];
        for token_kind in ["access_token", "refresh_token"] {
            let response=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({"client_id":id,"client_secret":created["client_secret"],"token":issued[token_kind],"token_type_hint":token_kind}))?,EndpointOptions::default())).await?.into_response()?;
            assert_eq!(response.status, 200);
            payloads.push(body(&response));
        }
        for payload in payloads {
            assert_eq!(payload["active"], true);
            assert_eq!(payload["token_type"], kind);
            assert_eq!(payload.get("cnf"), present.then_some(&confirmation));
        }
    }
    Ok(())
}
async fn oauth_jwt_introspection_uses_live_resource_peer_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::endpoint::ServerEndpoint;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "jwt-introspection@example.test").await;
    let headers = [("cookie".into(), cookies(&owner))]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let mut clients = Vec::new();
    for name in ["issuer", "peer", "stranger"] {
        let response=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":name,"redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some(headers.clone()),..Default::default()})).await?.into_response()?;
        assert_eq!(response.status, 201);
        clients.push(body(&response));
    }
    let resource = "https://api.fixture.test/introspection/signed";
    let registered = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthResource")
                .with_body(&json!({"identifier":resource}))?,
            EndpointOptions {
                headers: Some(headers.clone()),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(registered.status, 200);
    for client in &clients[..2] {
        let linked = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminLinkClientResource")
                    .with_params(&json!({"identifier":resource,"client_id":client["client_id"]}))?,
                EndpointOptions {
                    headers: Some(headers.clone()),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(linked.status, 200);
    }
    let client = provider
        .get_client(auth.context(), clients[0]["client_id"].as_str().unwrap())
        .await?
        .unwrap();
    let owner_id = client.user_id.clone().unwrap();
    let user = auth.store().get_user_by_id(&owner_id).await?.unwrap();
    let mut params =
        OAuthTokenIssueParams::new(client, vec!["email".into(), "offline_access".into()]);
    params.user = Some(auth.context().trusted_user_view(&user));
    params.resources = Some(vec![resource.into()]);
    params.confirmation = Some(json!({"jkt":"trusted-binding"}));
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
    let issued = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:introspection"),
            &params,
        )
        .await?;
    let token = issued["access_token"].as_str().unwrap();
    for (index, client) in clients.iter().enumerate() {
        let response=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({"client_id":client["client_id"],"client_secret":client["client_secret"],"token":token,"token_type_hint":"access_token"}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(response.status, 200);
        let claims = body(&response);
        if index == 2 {
            assert_eq!(claims, json!({"active":false}));
            continue;
        }
        assert_eq!(claims["active"], true);
        assert_eq!(claims["client_id"], clients[0]["client_id"]);
        assert_eq!(claims["sub"], owner_id);
        assert_eq!(claims["aud"], resource);
        assert_eq!(claims["cnf"], json!({"jkt":"trusted-binding"}));
        assert_eq!(claims["token_type"], "DPoP");
    }
    let prefixed = format!("  dpop   {token}  ");
    let response=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({"client_id":clients[0]["client_id"],"client_secret":clients[0]["client_secret"],"token":prefixed}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(body(&response)["active"], true);
    let parts = token.split('.').collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    *signature.first_mut().unwrap() ^= 1;
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(signature)
    );
    // A JWT that fails verification is reported like any unknown token.
    let failure=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({"client_id":clients[0]["client_id"],"client_secret":clients[0]["client_secret"],"token":tampered,"token_type_hint":"access_token"}))?,EndpointOptions::default())).await?;
    assert_eq!(failure.value().to_json_value()?, json!({"active":false}));
    let unlinked = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminUnlinkClientResource")
                .with_params(&json!({"identifier":resource,"client_id":clients[1]["client_id"]}))?,
            EndpointOptions {
                headers: Some(headers),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(unlinked.status, 200);
    let response=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_introspect_endpoint(&json!({"client_id":clients[1]["client_id"],"client_secret":clients[1]["client_secret"],"token":token}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(body(&response), json!({"active":false}));
    Ok(())
}
async fn oauth_requested_userinfo_claims_follow_opaque_refresh_authority<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::endpoint::ServerEndpoint;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "requested-info@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Requested claims","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = provider
        .get_client(
            auth.context(),
            body(&created)["client_id"].as_str().unwrap(),
        )
        .await?
        .unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
    let user_id = client.user_id.clone().unwrap();
    let mut params =
        OAuthTokenIssueParams::new(client, vec!["openid".into(), "offline_access".into()]);
    params.user = Some(auth.context().trusted_user_view(&user));
    params.requested_user_info_claims = Some(vec!["email".into()]);
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
    let mut issued = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:claims"), &params)
        .await?;
    for stage in ["seed", "inherited", "cleared", "jwt"] {
        if stage == "jwt" {
            params.refresh_token = None;
            params.requested_user_info_claims = Some(vec!["email".into()]);
            params.resources = Some(vec![format!(
                "{}{}/oauth2/userinfo",
                auth.config().base_url.trim_end_matches('/'),
                auth.config().base_path
            )]);
            issued = provider
                .issue_tokens(auth.context(), &call, Some("urn:fixture:claims"), &params)
                .await?;
        }
        let response = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_user_info_endpoint(),
                EndpointOptions {
                    headers: Some(
                        [(
                            "authorization".into(),
                            format!("Bearer {}", issued["access_token"].as_str().unwrap()),
                        )]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let expected = if matches!(stage, "seed" | "inherited") {
            json!({"sub":user_id,"email":"requested-info@example.test"})
        } else {
            json!({"sub":user_id})
        };
        assert_eq!(body(&response), expected);
        if stage == "seed" || stage == "inherited" {
            let hash = provider
                .hash_token(issued["refresh_token"].as_str().unwrap(), "refresh_token")
                .await?;
            params.refresh_token = auth
                .store()
                .get_oauth_token(OAuthTokenKind::Refresh, &hash)
                .await?;
            params.requested_user_info_claims = if stage == "seed" {
                None
            } else {
                Some(Vec::new())
            };
            issued = provider
                .issue_tokens(auth.context(), &call, Some("urn:fixture:claims"), &params)
                .await?;
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
