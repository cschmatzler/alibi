//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
#[path = "../../../fixtures/oauth/credential-generators.rs"]
mod credential_generators;
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_refresh_reuse_replays_encrypted_response_and_preserves_family_on_mismatch);
async fn oauth_refresh_reuse_replays_encrypted_response_and_preserves_family_on_mismatch<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let generators = Arc::new(credential_generators::Generators::default());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        refresh_token_reuse_interval: 60.0,
        opaque_access_token_generator: Some(credential_generators::access(generators.clone())),
        refresh_token_generator: Some(credential_generators::refresh(generators.clone())),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "reuse-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"none","skip_consent":true,"grant_types":["authorization_code","refresh_token"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email offline_access","state":"token-state","nonce":"generator-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
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
    assert_eq!(token["scope"], "openid email offline_access");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext, "application-access-1");
    let refresh = token["refresh_token"]
        .as_str()
        .expect("offline_access must issue a refresh token");
    assert_eq!(refresh, "application-refresh-1");
    assert!(token["id_token"].is_string());
    assert_eq!(*generators.calls.lock().unwrap(), ["refresh", "access"]);

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
    assert_eq!(issued["access_token"], "application-access-2");
    assert_eq!(issued["refresh_token"], "application-refresh-2");
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let session_id = stored.session_id.clone().unwrap();
    let expected_calls = ["refresh", "access", "refresh", "access"];
    assert_eq!(*generators.calls.lock().unwrap(), expected_calls);
    assert_eq!(*generators.contexts.lock().unwrap(), expected_calls.map(|kind|json!({
        "kind":kind,"userId":user_id,"clientId":id,"scopes":["openid","email","offline_access"],"sessionId":session_id,
    })));
    for access in [plaintext, issued["access_token"].as_str().unwrap()] {
        let row = auth
            .store()
            .get_oauth_token(OAuthTokenKind::Access, &hash(access))
            .await?
            .unwrap();
        assert_eq!(row.token, hash(access));
        assert_ne!(row.token, access);
        let info = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_user_info_endpoint(),
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {access}"))]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(body(&info)["sub"], user_id);
    }
    let revoked = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_revoke_endpoint(
            &json!({"client_id":id,"token":plaintext,"token_type_hint":"access_token"}),
        )?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(revoked.status, 200);
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Access, &hash(plaintext))
            .await?
            .is_none()
    );
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
        json!(["email", "offline_access", "openid"])
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
    for scope in [
        "offline_access email openid",
        "openid email offline_access email",
    ] {
        let mut equivalent = input.clone();
        equivalent["scope"] = json!(scope);
        let replayed = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&equivalent)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(equivalent), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(replayed.status, 200);
        let replayed = body(&replayed);
        for key in [
            "access_token",
            "refresh_token",
            "expires_at",
            "scope",
            "token_type",
        ] {
            assert_eq!(replayed[key], issued[key]);
        }
        let unchanged = auth
            .store()
            .get_oauth_token(OAuthTokenKind::Refresh, &hash(refresh))
            .await?
            .unwrap();
        assert_eq!(
            unchanged.metadata["rotationReplayResponse"],
            stored.metadata["rotationReplayResponse"]
        );
        assert_eq!(
            unchanged.metadata["rotationReplayExpiresAt"],
            stored.metadata["rotationReplayExpiresAt"]
        );
    }
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
    for field in ["access_token", "token_type", "refresh_token"] {
        let mut malformed = replay.clone();
        if field == "access_token" {
            _ = malformed["response"].as_object_mut().unwrap().remove(field);
        } else {
            malformed["response"][field] = json!(17);
        }
        let mut nonce = [0u8; 24];
        rand::fill(&mut nonce);
        let encrypted_part = XChaCha20Poly1305::new(&sha2::Sha256::digest(SECRET.as_bytes()))
            .encrypt(
                &XNonce::from(nonce),
                serde_json::to_string(&malformed)?.as_bytes(),
            )
            .map_err(|_| "invalid replay encryption")?;
        let changed = nonce
            .iter()
            .chain(encrypted_part.iter())
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        auth.store()
            .store_oauth_refresh_replay(&stored.id, &changed)
            .await?;
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
        assert!(
            auth.store()
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &hash(issued["refresh_token"].as_str().unwrap())
                )
                .await?
                .is_some()
        );
    }
    auth.store()
        .store_oauth_refresh_replay(&stored.id, encrypted)
        .await?;
    let input = json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh});
    let valid = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&valid)["access_token"], issued["access_token"]);
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
    assert_eq!(
        *generators.calls.lock().unwrap(),
        expected_calls,
        "all reuse and rejected retries bypass generators"
    );
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth.store().get_user_by_id(&user_id).await?.unwrap();
    let mut params =
        OAuthTokenIssueParams::new(client, vec!["email".into(), "offline_access".into()]);
    params.user = Some(auth.context().trusted_user_view(&user));
    params.session_id = Some(session_id.clone());
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "generatorFixture",
            operation_id: "generatorFixture",
            path: None,
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let counts = || async {
        Ok::<_, alibi::AuthError>((
            auth.store()
                .list_oauth_tokens_for_session(OAuthTokenKind::Access, &session_id)
                .await?
                .len(),
            auth.store()
                .list_oauth_tokens_for_session(OAuthTokenKind::Refresh, &session_id)
                .await?
                .len(),
        ))
    };
    for kind in ["refresh", "access"] {
        *generators.refresh_mode.lock().unwrap() =
            if kind == "refresh" { "error" } else { "" }.into();
        *generators.access_mode.lock().unwrap() =
            if kind == "access" { "error" } else { "" }.into();
        let before = counts().await?;
        let failed = provider
            .issue_tokens(
                auth.context(),
                &call,
                Some("urn:fixture:generators"),
                &params,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(failed.error,alibi::AuthError::Internal(ref message) if message==&format!("{kind} generator failed"))
        );
        assert_eq!(
            counts().await?,
            (before.0, before.1 + usize::from(kind == "access")),
            "opaque access failure retains the early refresh row"
        );
    }
    *generators.refresh_mode.lock().unwrap() = "fixed".into();
    *generators.access_mode.lock().unwrap() = "fixed".into();
    let fixed = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:generators"),
            &params,
        )
        .await?;
    assert_eq!(fixed["access_token"], "application-access-fixed");
    assert_eq!(fixed["refresh_token"], "application-refresh-fixed");
    let before = counts().await?;
    let call_count = generators.calls.lock().unwrap().len();
    assert!(
        provider
            .issue_tokens(
                auth.context(),
                &call,
                Some("urn:fixture:generators"),
                &params
            )
            .await
            .is_err()
    );
    assert_eq!(counts().await?, before);
    assert_eq!(
        generators.calls.lock().unwrap().len(),
        call_count + 1,
        "refresh collision is not silently retried"
    );
    *generators.refresh_mode.lock().unwrap() = String::new();
    let before = counts().await?;
    let call_count = generators.calls.lock().unwrap().len();
    assert!(
        provider
            .issue_tokens(
                auth.context(),
                &call,
                Some("urn:fixture:generators"),
                &params
            )
            .await
            .is_err()
    );
    assert_eq!(counts().await?, (before.0, before.1 + 1));
    assert_eq!(
        generators.calls.lock().unwrap().len(),
        call_count + 2,
        "access collision retains early refresh, without retry"
    );
    *generators.refresh_mode.lock().unwrap() = "empty".into();
    *generators.access_mode.lock().unwrap() = "empty".into();
    let empty = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:generators"),
            &params,
        )
        .await?;
    assert_eq!(empty["access_token"], "");
    assert_eq!(empty["refresh_token"], "");
    for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
        assert!(
            auth.store()
                .get_oauth_token(kind, &hash(""))
                .await?
                .is_some(),
            "empty output is hashed, not replaced by randomness"
        );
    }
    *generators.refresh_mode.lock().unwrap() = String::new();
    *generators.access_mode.lock().unwrap() = String::new();
    params.resources = Some(vec![format!("{ORIGIN}/api/auth/oauth2/userinfo")]);
    let access_count = *generators.access_count.lock().unwrap();
    let signed = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:generators"),
            &params,
        )
        .await?;
    assert!(
        JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                issuer: Some(format!("{ORIGIN}/api/auth")),
                audience: Some(alibi::plugins::jwt::JwtAudience::One(format!(
                    "{ORIGIN}/api/auth/oauth2/userinfo"
                ))),
                ..Default::default()
            },
            ..Default::default()
        })
        .verify_jwt(
            signed["access_token"].as_str().unwrap(),
            None,
            None,
            auth.context()
        )
        .await?
        .is_some()
    );
    assert_eq!(
        *generators.access_count.lock().unwrap(),
        access_count,
        "JWT access issuance does not call the opaque generator or use it for jti"
    );
    Ok(())
}
