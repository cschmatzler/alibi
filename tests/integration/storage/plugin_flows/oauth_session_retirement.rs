//! Session deletion retires issued authority and notifies real relying parties.
use super::*;
use alibi::AuthSession as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(
    oauth_signout_retires_bound_access_while_offline_refresh_survives,
    oauth_bulk_revocation_notifies_each_deleted_session,
    oauth_preserved_signout_retires_authority_once,
    oauth_preserved_bulk_retirement_skips_ended_audit_rows,
    oauth_logout_retains_dynamic_authority_and_signing_context
);
#[path = "../../../fixtures/oauth/logout-context.rs"]
mod logout_context;
async fn oauth_signout_retires_bound_access_while_offline_refresh_survives<B: Backend>(
    db: Db,
) -> TestResult {
    retirement_case::<B>(db, false, false).await
}
async fn oauth_bulk_revocation_notifies_each_deleted_session<B: Backend>(db: Db) -> TestResult {
    retirement_case::<B>(db, true, false).await
}
async fn oauth_preserved_signout_retires_authority_once<B: Backend>(db: Db) -> TestResult {
    retirement_case::<B>(db, false, true).await
}
async fn oauth_preserved_bulk_retirement_skips_ended_audit_rows<B: Backend>(db: Db) -> TestResult {
    retirement_case::<B>(db, true, true).await
}

async fn issue_for_session<S: AuthSchema>(
    auth: &Alibi<S>,
    session: &AuthResponse,
    query: &Value,
    input: Value,
) -> TestResult<Value> {
    issue_for_session_at(auth, session, query, input, None).await
}

async fn issue_for_session_at<S: AuthSchema>(
    auth: &Alibi<S>,
    session: &AuthResponse,
    query: &Value,
    mut input: Value,
    authority: Option<&str>,
) -> TestResult<Value> {
    let physical = |path: &str, body| {
        let mut input = request(path, body, "");
        if let Some(authority) = authority {
            input = input
                .with_url(url::Url::parse(&format!("https://{authority}/api/auth{path}")).unwrap());
            _ = input.headers.insert("host".into(), authority.into());
        }
        input
    };
    let grant = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(session)),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(physical("/oauth2/authorize", None)),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(grant.status, 200);
    let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    assert_eq!(callback.path(), "/callback");
    input["code"] = json!(
        callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    );
    let issued = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
        EndpointOptions {
            request: Some(physical("/oauth2/token", Some(input))),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(issued.status, 200);
    Ok(body(&issued))
}

async fn oauth_logout_retains_dynamic_authority_and_signing_context<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::jwt::{JwtClaimsConfig, JwtPluginConfig};
    let (received, mut receipts) = tokio::sync::mpsc::unbounded_channel();
    let rp = axum::Router::new().route(
        "/logout",
        axum::routing::post(move |text: String| {
            let received = received.clone();
            async move {
                received.send(text).unwrap();
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let rp_url = format!("http://{}/logout", listener.local_addr()?);
    let rp_task = tokio::spawn(async move { axum::serve(listener, rp).await.unwrap() });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for background in [false, true] {
        for explicit in [false, true] {
            let ring = Arc::new(logout_context::LogoutContext::default());
            let mut config = AuthConfig::new(SECRET).base_url(ORIGIN).dynamic_base_url(
                alibi::config::DynamicBaseUrl {
                    allowed_hosts: vec![
                        "tenant-a.fixture.test".into(),
                        "tenant-b.fixture.test".into(),
                    ],
                    protocol: Some(alibi::config::BaseUrlProtocol::Https),
                    fallback: Some("https://fallback.fixture.test".into()),
                },
            );
            if background {
                config.background_tasks = Some(ring.clone());
            }
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .plugin(super::auth_probe::fast_password())
                .plugin(SessionManagementPlugin::new())
                .plugin(JwtPlugin::with_config(JwtPluginConfig {
                    keyring: Some(ring.clone()),
                    disable_setting_jwt_header: true,
                    claims: JwtClaimsConfig {
                        issuer: explicit.then(|| "https://explicit.fixture.test/issuer".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    pairwise_secret: Some("native-pairwise-secret-at-least-32-characters".into()),
                    ..Default::default()
                }))
                .build()
                .await?;
            let mut recipient = None;
            let mut previous_subject = None;
            for (index, host) in [
                "tenant-a.fixture.test",
                "tenant-b.fixture.test",
                "fallback.fixture.test",
            ]
            .into_iter()
            .enumerate()
            {
                let owner = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password", "signUpEmail").with_body(&json!({"email":format!("logout-{background}-{explicit}-{index}@example.test"),"name":"Owner","password":PASSWORD}))?, EndpointOptions {
                    headers: (index != 2).then(|| [("host".into(), host.into())].into_iter().collect()), ..Default::default()
                })).await?.into_response()?;
                assert_eq!(owner.status, 200);
                if recipient.is_none() {
                    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthClient").with_body(&json!({"client_name":"Logout context","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"client_secret_post","skip_consent":true,"grant_types":["authorization_code","refresh_token"],"enable_end_session":true,"subject_type":"pairwise"}))?, EndpointOptions { headers: Some([("cookie".into(),cookies(&owner)),("host".into(),host.into())].into_iter().collect()), ..Default::default() })).await?.into_response()?;
                    assert_eq!(created.status, 201);
                    let client = body(&created);
                    let id = client["client_id"].as_str().unwrap();
                    let mut row = auth.store().get_oauth_client(id).await?.unwrap();
                    row.metadata["backchannel_logout_uri"] = json!(rp_url);
                    _ = auth
                        .store()
                        .update_oauth_client_metadata(id, row.metadata, chrono::Utc::now())
                        .await?;
                    recipient = Some(client);
                }
                let client = recipient.as_ref().unwrap();
                let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier));
                let issued = issue_for_session_at(&auth,&owner,&json!({"client_id":client["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email offline_access","code_challenge":challenge,"code_challenge_method":"S256"}),json!({"grant_type":"authorization_code","client_id":client["client_id"],"client_secret":client["client_secret"],"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"}),Some(host)).await?;
                let keys_response = Box::pin(auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("jwt", "getJwks"),
                    EndpointOptions::default(),
                ))
                .await?
                .into_response()?;
                let keys: jsonwebtoken::jwk::JwkSet = serde_json::from_value(body(&keys_response))?;
                let expected_issuer = if explicit {
                    "https://explicit.fixture.test/issuer".to_owned()
                } else {
                    format!("https://{host}/api/auth")
                };
                let verify = |token: &str,
                              issuer: &str|
                 -> Result<
                    jsonwebtoken::TokenData<Value>,
                    jsonwebtoken::errors::Error,
                > {
                    let header = jsonwebtoken::decode_header(token)?;
                    let mut validation = jsonwebtoken::Validation::new(header.alg);
                    validation.set_issuer(&[issuer]);
                    validation.set_audience(&[client["client_id"].as_str().unwrap()]);
                    jsonwebtoken::decode(
                        token,
                        &jsonwebtoken::DecodingKey::from_jwk(
                            keys.find(header.kid.as_deref().unwrap()).unwrap(),
                        )?,
                        &validation,
                    )
                };
                let id = verify(issued["id_token"].as_str().unwrap(), &expected_issuer)?;
                ring.calls.lock().unwrap().clear();
                let logical_host = if index == 0 {
                    "tenant-b.fixture.test"
                } else {
                    host
                };
                let mut headers = [
                    ("cookie".into(), cookies(&owner)),
                    ("origin".into(), format!("https://{host}")),
                    ("x-logout-proof".into(), "logical".into()),
                ]
                .into_iter()
                .collect::<std::collections::HashMap<String, String>>();
                if index != 2 {
                    _ = headers.insert("host".into(), logical_host.into());
                }
                let mut physical = request("/sign-out", Some(json!({})), "").with_url(
                    url::Url::parse(&format!("https://{host}/api/auth/sign-out"))?,
                );
                physical.headers = headers.clone();
                _ = physical.headers.insert("host".into(), host.into());
                _ = physical
                    .headers
                    .insert("x-logout-proof".into(), "physical".into());
                _ = physical
                    .headers
                    .insert("content-type".into(), "application/json".into());
                let started = chrono::Utc::now().timestamp();
                let ended = if index == 1 {
                    Box::pin(auth.handle_request(physical)).await?
                } else {
                    Box::pin(auth.dispatch_endpoint(
                        ServerEndpoint::<Value>::new("session-management", "signOut"),
                        EndpointOptions {
                            headers: Some(headers),
                            request: (index == 0).then_some(physical),
                            ..Default::default()
                        },
                    ))
                    .await?
                    .into_response()?
                };
                assert_eq!(ended.status, 200);
                ring.drain().await?;
                let form = tokio::time::timeout(std::time::Duration::from_secs(2), receipts.recv())
                    .await?
                    .unwrap();
                let fields: Vec<_> = url::form_urlencoded::parse(form.as_bytes())
                    .into_owned()
                    .collect();
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].0, "logout_token");
                let token = &fields[0].1;
                let logout = verify(token, &expected_issuer)
                    .map_err(|error| format!("logout JWT issuer {expected_issuer}: {error}"))?;
                assert_eq!(logout.header.typ.as_deref(), Some("logout+jwt"));
                assert_eq!(logout.header.kid, id.header.kid);
                assert_eq!(logout.header.alg, id.header.alg);
                assert_eq!(logout.claims["sub"], id.claims["sub"]);
                assert_ne!(logout.claims["sub"], body(&owner)["user"]["id"]);
                if let Some(previous) = previous_subject {
                    assert_ne!(logout.claims["sub"], previous);
                }
                previous_subject = Some(logout.claims["sub"].clone());
                assert_eq!(logout.claims["sid"], id.claims["sid"]);
                assert_eq!(logout.claims["aud"], client["client_id"]);
                assert!(
                    (started..=chrono::Utc::now().timestamp())
                        .contains(&logout.claims["iat"].as_i64().unwrap())
                );
                assert_eq!(
                    logout.claims["exp"].as_i64().unwrap() - logout.claims["iat"].as_i64().unwrap(),
                    120
                );
                assert_eq!(
                    logout.claims["events"],
                    json!({"http://schemas.openid.net/event/backchannel-logout":{}})
                );
                assert!(logout.claims.get("nonce").is_none());
                assert!(verify(token, "https://wrong.fixture.test/api/auth").is_err());
                if !explicit {
                    assert!(
                        verify(
                            token,
                            &format!(
                                "https://{}/api/auth",
                                if index == 0 {
                                    logical_host
                                } else {
                                    "tenant-a.fixture.test"
                                }
                            )
                        )
                        .is_err()
                    );
                }
                let calls = ring.calls.lock().unwrap().clone();
                assert_eq!(
                    calls,
                    vec![
                        json!({"operation":"read","path":"/sign-out","physicalHost":(index != 2).then_some(host),"physicalProof":(index != 2).then_some("physical"),"logicalHost":(index != 2).then_some(if index==1 {host}else{logical_host}),"logicalProof":if index==1 {"physical"}else{"logical"}})
                    ]
                );
                assert_eq!(auth.context().config.base_url, ORIGIN);
                assert!(
                    auth.store()
                        .get_session(body(&owner)["token"].as_str().unwrap())
                        .await?
                        .is_none()
                );
                assert!(receipts.try_recv().is_err());
            }
        }
    }
    rp_task.abort();
    B::close(connection).await
}

async fn revoke_all<S: AuthSchema>(
    auth: &Alibi<S>,
    session: &AuthResponse,
) -> alibi::AuthResult<AuthResponse> {
    Box::pin(
        auth.dispatch_endpoint(
            SessionManagementPlugin::revoke_sessions_endpoint(),
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(session)),
                        ("origin".into(), ORIGIN.into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|error| error.error)?
    .into_response()
}

async fn retirement_case<B: Backend>(db: Db, bulk: bool, preserve: bool) -> TestResult {
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    struct DeleteGate(Arc<std::sync::atomic::AtomicU8>, Arc<Mutex<Vec<String>>>);
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
        async fn after_delete_session(
            &self,
            session: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> alibi::AuthResult<()> {
            self.1
                .lock()
                .unwrap()
                .push(session.id().as_ref().to_owned());
            Ok(())
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
    let completed = Arc::new(Mutex::new(Vec::new()));
    let cache = Arc::new(alibi::store::MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    if preserve {
        config.session.secondary_storage = Some(cache.clone());
        config.session.store_in_database = true;
        config.session.preserve_in_database = true;
    }
    let preserved_config = config.clone();
    let auth = AuthBuilder::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            DeleteGate(gate.clone(), completed.clone()),
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
    let input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":client_secret,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let token = issue_for_session(&auth, &owner, &query, input.clone()).await?;
    let online_grant = issue_for_session(&auth, &owner, &query, input.clone()).await?;
    let downscope = json!({"grant_type":"refresh_token","client_id":id,"client_secret":body(&created)["client_secret"],"refresh_token":online_grant["refresh_token"],"scope":"openid email"});
    let online = body(
        &Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&downscope)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(downscope), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?,
    );
    assert_eq!(online["scope"], "openid email");
    assert!(online["refresh_token"].is_string());
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
        let mut next_input = input.clone();
        next_input["client_id"] = client["client_id"].clone();
        next_input["client_secret"] = client["client_secret"].clone();
        _ = issue_for_session(&auth, &owner, &next_query, next_input).await?;
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

    let sibling = if bulk {
        let session = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"retirement-owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let issued = issue_for_session(&auth, &session, &query, input.clone()).await?;
        Some((session, issued))
    } else {
        None
    };
    let sibling_sid = if let Some((session, _)) = &sibling {
        Some(
            auth.store()
                .get_session(body(session)["token"].as_str().unwrap())
                .await?
                .unwrap()
                .id()
                .as_ref()
                .to_owned(),
        )
    } else {
        None
    };
    let other = signup(&auth, "retirement-other@example.test").await;
    let other_token = issue_for_session(&auth, &other, &query, input.clone()).await?;
    let other_access = other_token["access_token"].as_str().unwrap().to_owned();
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
    for mode in [1, 2].into_iter().filter(|_| !preserve || bulk) {
        gate.store(mode, std::sync::atomic::Ordering::SeqCst);
        let result = if bulk {
            revoke_all(&auth, &owner).await.map(|_| ())
        } else {
            auth.store()
                .delete_session(body(&owner)["token"].as_str().unwrap())
                .await
        };
        assert_eq!(result.is_err(), mode == 2);
        assert!(
            auth.store()
                .get_session(body(&owner)["token"].as_str().unwrap())
                .await?
                .is_some()
        );
        assert!(receipts.try_recv().is_err());
        assert!(completed.lock().unwrap().is_empty());
        let row = auth
            .store()
            .get_oauth_token(OAuthTokenKind::Access, &protected)
            .await?
            .unwrap();
        assert!(row.metadata.get("revoked").is_none_or(Value::is_null));
        if let Some((session, token)) = &sibling {
            assert!(
                auth.store()
                    .get_session(body(session)["token"].as_str().unwrap())
                    .await?
                    .is_some()
            );
            let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                sha2::Sha256::digest(token["access_token"].as_str().unwrap()),
            );
            let row = auth
                .store()
                .get_oauth_token(OAuthTokenKind::Access, &protected)
                .await?
                .unwrap();
            assert!(row.metadata.get("revoked").is_none_or(Value::is_null));
        }
    }
    gate.store(0, std::sync::atomic::Ordering::SeqCst);
    let started = chrono::Utc::now().timestamp_millis();
    let ended = if bulk {
        revoke_all(&auth, &owner).await?
    } else {
        Box::pin(
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
        .into_response()?
    };
    assert_eq!(ended.status, 200);
    let ended_sid = id_claims["sid"].as_str().unwrap();
    let audit = auth.store().get_session_by_id(ended_sid).await?;
    assert_eq!(audit.is_some(), preserve);
    let audit_expiry = audit.as_ref().map(alibi::AuthSession::expires_at);
    if let Some(audit) = &audit {
        assert!(audit.expires_at() <= chrono::Utc::now());
        assert!(audit.expires_at().timestamp_millis() >= started);
        use alibi::store::CacheAdapter as _;
        assert!(
            cache
                .get(body(&owner)["token"].as_str().unwrap())
                .await?
                .is_none()
        );
    }
    assert_eq!(completed.lock().unwrap().len(), if bulk { 2 } else { 1 });
    assert!(
        auth.store()
            .get_session(body(&owner)["token"].as_str().unwrap())
            .await?
            .is_none()
    );
    if let Some((session, _)) = &sibling {
        assert!(
            auth.store()
                .get_session(body(session)["token"].as_str().unwrap())
                .await?
                .is_none()
        );
    }
    assert!(
        auth.store()
            .get_session(body(&other)["token"].as_str().unwrap())
            .await?
            .is_some()
    );
    let jwks = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("jwt", "getJwks"),
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let keys: jsonwebtoken::jwk::JwkSet = serde_json::from_value(body(&jwks))?;
    let mut identifiers = std::collections::HashSet::new();
    let mut notified_sessions = Vec::new();
    for _ in 0..if bulk { 3 } else { 2 } {
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
        notified_sessions.push((target.clone(), claims["sid"].as_str().unwrap().to_owned()));
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
    }
    let mut expected_sessions = vec![
        (
            "failure".to_owned(),
            id_claims["sid"].as_str().unwrap().to_owned(),
        ),
        (
            "success".to_owned(),
            id_claims["sid"].as_str().unwrap().to_owned(),
        ),
    ];
    if let Some(sid) = sibling_sid {
        expected_sessions.push(("success".to_owned(), sid));
    }
    expected_sessions.sort();
    notified_sessions.sort();
    assert_eq!(notified_sessions, expected_sessions);
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
    assert_eq!(after.session_id.as_deref(), preserve.then_some(ended_sid));
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
    assert!(alibi::endpoint::is_endpoint_api_error(&denied.error));
    assert_eq!(denied.error.status_code(), 401);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_token","error_description":"Invalid access token"})
    );
    for (token, hint, active) in [
        (plaintext, "access_token", false),
        (refresh, "refresh_token", true),
        (
            online["access_token"].as_str().unwrap(),
            "access_token",
            false,
        ),
        (
            online["refresh_token"].as_str().unwrap(),
            "refresh_token",
            false,
        ),
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
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
        online["refresh_token"].as_str().unwrap(),
    ));
    let online_row = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &protected)
        .await?
        .unwrap();
    assert!(
        online_row
            .metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
    );
    // Repeated single deletion, bulk sweeps, and expiry cleanup must neither
    // notify again nor rewrite retained audit history or revocation timestamps.
    auth.store()
        .delete_session(body(&owner)["token"].as_str().unwrap())
        .await?;
    auth.store()
        .delete_user_sessions(body(&owner)["user"]["id"].as_str().unwrap())
        .await?;
    assert_eq!(auth.store().delete_expired_sessions().await?, 0);
    assert_eq!(completed.lock().unwrap().len(), if bulk { 2 } else { 1 });
    assert!(receipts.try_recv().is_err());
    let repeated = auth.store().get_session_by_id(ended_sid).await?;
    assert_eq!(repeated.is_some(), preserve);
    assert_eq!(
        repeated.as_ref().map(alibi::AuthSession::expires_at),
        audit_expiry
    );
    let unchanged = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &protected)
        .await?
        .unwrap();
    assert_eq!(unchanged.metadata, online_row.metadata);
    if let Some((_, token)) = &sibling {
        for (kind, value, revoked) in [
            (OAuthTokenKind::Access, "access_token", true),
            (OAuthTokenKind::Refresh, "refresh_token", false),
        ] {
            let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(token[value].as_str().unwrap()));
            let row = auth
                .store()
                .get_oauth_token(kind, &protected)
                .await?
                .unwrap();
            assert_eq!(
                row.metadata
                    .get("revoked")
                    .is_some_and(|value| !value.is_null()),
                revoked
            );
        }
    }
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
    if preserve {
        use alibi::store::CacheAdapter as _;
        let other_token = body(&other)["token"].as_str().unwrap().to_owned();
        let other_sid = auth
            .store()
            .get_session(&other_token)
            .await?
            .unwrap()
            .id()
            .as_ref()
            .to_owned();
        let live = auth
            .store()
            .get_session_by_id(&other_sid)
            .await?
            .unwrap()
            .expires_at();
        for mode in [1, 2] {
            gate.store(mode, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                auth.store().delete_session(&other_token).await.is_err(),
                mode == 2
            );
            assert!(cache.get(&other_token).await?.is_none());
            assert_eq!(
                auth.store()
                    .get_session_by_id(&other_sid)
                    .await?
                    .unwrap()
                    .expires_at(),
                live
            );
            assert_eq!(completed.lock().unwrap().len(), if bulk { 2 } else { 1 });
            assert!(receipts.try_recv().is_err());
            let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(&other_access));
            let authority = auth
                .store()
                .get_oauth_token(OAuthTokenKind::Access, &protected)
                .await?
                .unwrap();
            assert!(authority.metadata.get("revoked").is_none_or(Value::is_null));
            let accepted = Box::pin(
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
            assert_eq!(accepted.status, 200);
        }
        gate.store(0, std::sync::atomic::Ordering::SeqCst);
    }
    // Disabling JWT delivery must not disable retirement of opaque authority.
    let no_delivery = AuthBuilder::new(preserved_config.clone())
        .store(B::store(Arc::new(preserved_config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            disable_jwt_plugin: true,
            ..Default::default()
        }))
        .build()
        .await?;
    if preserve {
        no_delivery
            .store()
            .delete_session(body(&other)["token"].as_str().unwrap())
            .await?;
    } else {
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
    }
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
