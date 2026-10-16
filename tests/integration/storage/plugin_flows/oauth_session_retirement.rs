//! Session deletion retires issued authority and notifies real relying parties.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_signout_retires_bound_access_while_offline_refresh_survives);
async fn oauth_signout_retires_bound_access_while_offline_refresh_survives<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    struct DeleteGate(Arc<std::sync::atomic::AtomicU8>);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for DeleteGate {
        async fn before_delete_session(
            &self,
            _: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> alibi::AuthResult<HookControl> {
            match self.0.load(std::sync::atomic::Ordering::SeqCst) {
                1 => Ok(HookControl::Cancel),
                2 => Err(alibi::AuthError::internal("application rejected deletion")),
                _ => Ok(HookControl::Continue),
            }
        }
    }
    let (received, mut receipts) = tokio::sync::mpsc::unbounded_channel();
    let rp = axum::Router::new().route(
        "/{target}",
        axum::routing::post(
            move |axum::extract::Path(target): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  text: String| {
                let received = received.clone();
                async move {
                    received.send((target.clone(), headers, text)).unwrap();
                    if target == "failure" {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::NO_CONTENT
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rp_url = format!("http://{}", listener.local_addr()?);
    let rp_task = tokio::spawn(async move { axum::serve(listener, rp).await.unwrap() });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let gate = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            DeleteGate(gate.clone()),
        ))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            pairwise_secret: Some("native-pairwise-secret-at-least-32-characters".into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "retirement-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"client_secret_post","skip_consent":true,"grant_types":["authorization_code","refresh_token"],"enable_end_session":true,"subject_type":"pairwise"}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    // Persist the local RP transport address without weakening registration's
    // HTTPS/public-host policy, which has its own owner.
    let mut client = auth.store().get_oauth_client(&id).await?.unwrap();
    client.metadata["backchannel_logout_uri"] = json!(format!("{rp_url}/success"));
    _ = auth
        .store()
        .update_oauth_client_metadata(&id, client.metadata, chrono::Utc::now())
        .await?;
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
    let id_claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
            token["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        )?,
    )?;
    assert_ne!(id_claims["sub"], body(&owner)["user"]["id"]);

    // Each recipient gets real session-bound authority before eligibility changes.
    let mut recipient_ids = std::collections::HashMap::from([("success".to_owned(), id.clone())]);
    for target in ["failure", "disabled", "no-uri"] {
        let mut metadata = body(&created).clone();
        for key in [
            "client_id",
            "client_secret",
            "id",
            "created_at",
            "updated_at",
        ] {
            _ = metadata.as_object_mut().unwrap().remove(key);
        }
        metadata["client_name"] = json!(target);
        let issued_client = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthClient")
                    .with_body(&metadata)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(issued_client.status, 201);
        let client = body(&issued_client);
        _ = recipient_ids.insert(
            target.to_owned(),
            client["client_id"].as_str().unwrap().to_owned(),
        );
        let mut next_query = query.clone();
        next_query["client_id"] = client["client_id"].clone();
        let granted = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_authorize_endpoint(&next_query)?,
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
        let url = url::Url::parse(body(&granted)["url"].as_str().unwrap())?;
        let code = url
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let mut next_input = input.clone();
        next_input["client_id"] = client["client_id"].clone();
        next_input["client_secret"] = client["client_secret"].clone();
        next_input["code"] = json!(code);
        let issued = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&next_input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(next_input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(issued.status, 200);
        if target != "no-uri" {
            let client_id = client["client_id"].as_str().unwrap();
            let mut row = auth.store().get_oauth_client(client_id).await?.unwrap();
            row.metadata["backchannel_logout_uri"] = json!(format!("{rp_url}/{target}"));
            row.metadata["disabled"] = json!(target == "disabled");
            _ = auth
                .store()
                .update_oauth_client_metadata(client_id, row.metadata, chrono::Utc::now())
                .await?;
        }
    }

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
    // Preparation must not send or retire anything when the adapter vetoes/fails.
    for mode in [1, 2] {
        gate.store(mode, std::sync::atomic::Ordering::SeqCst);
        let result = auth
            .store()
            .delete_session(body(&owner)["token"].as_str().unwrap())
            .await;
        assert_eq!(result.is_err(), mode == 2);
        assert!(
            auth.store()
                .get_session(body(&owner)["token"].as_str().unwrap())
                .await?
                .is_some()
        );
        assert!(receipts.try_recv().is_err());
        let row = auth
            .store()
            .get_oauth_token(OAuthTokenKind::Access, &protected)
            .await?
            .unwrap();
        assert!(row.metadata.get("revoked").is_none_or(Value::is_null));
    }
    gate.store(0, std::sync::atomic::Ordering::SeqCst);
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
    let jwks = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("jwt", "getJwks"),
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let keys: jsonwebtoken::jwk::JwkSet = serde_json::from_value(body(&jwks))?;
    let mut targets = Vec::new();
    let mut identifiers = std::collections::HashSet::new();
    for _ in 0..2 {
        let (target, headers, form) =
            tokio::time::timeout(std::time::Duration::from_secs(2), receipts.recv())
                .await?
                .unwrap();
        assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
        assert_eq!(headers["accept"], "application/json");
        let fields: Vec<_> = url::form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "logout_token");
        let header = jsonwebtoken::decode_header(&fields[0].1)?;
        assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
        let key = keys.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_issuer(&[format!("{ORIGIN}/api/auth")]);
        validation.set_audience(&[&recipient_ids[&target]]);
        let claims = jsonwebtoken::decode::<Value>(
            &fields[0].1,
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?
        .claims;
        assert_eq!(claims["sub"], id_claims["sub"]);
        assert_eq!(claims["sid"], id_claims["sid"]);
        assert_eq!(claims["aud"], recipient_ids[&target]);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            120
        );
        assert!(
            (started / 1000..=chrono::Utc::now().timestamp())
                .contains(&claims["iat"].as_i64().unwrap())
        );
        assert_eq!(
            claims["events"],
            json!({"http://schemas.openid.net/event/backchannel-logout":{}})
        );
        assert!(claims.get("nonce").is_none());
        let jti = claims["jti"].as_str().unwrap();
        assert_eq!(jti.len(), 32);
        assert!(identifiers.insert(jti.to_owned()));
        targets.push(target);
    }
    targets.sort();
    assert_eq!(targets, ["failure", "success"]);
    assert!(
        receipts.try_recv().is_err(),
        "no retries or ineligible recipients"
    );
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
    assert_ne!(body(&unaffected)["sub"], id_claims["sub"]);
    // Disabling JWT delivery must not disable retirement of opaque authority.
    let no_delivery = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            disable_jwt_plugin: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let ended = Box::pin(
        no_delivery.dispatch_endpoint(
            ServerEndpoint::<Value>::new("session-management", "signOut"),
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&other)),
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
    assert!(receipts.try_recv().is_err());
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(&other_access));
    let row = no_delivery
        .store()
        .get_oauth_token(OAuthTokenKind::Access, &protected)
        .await?
        .unwrap();
    assert!(
        row.metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
    );
    rp_task.abort();
    Ok(())
}
