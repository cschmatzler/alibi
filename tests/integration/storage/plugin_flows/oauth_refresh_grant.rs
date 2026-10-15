//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(
    oauth_refresh_grant_narrows_scope_rotates_and_replay_removes_family,
    oauth_authorization_code_registration_implicitly_issues_and_rotates_refresh_tokens,
    oauth_custom_token_hashing_protects_real_grant_and_refresh_storage,
    oauth_server_access_validation_checks_live_opaque_and_signed_tokens
);
postgres_tests!(
    oauth_authorization_code_registration_implicitly_issues_and_rotates_refresh_tokens,
    oauth_custom_token_hashing_protects_real_grant_and_refresh_storage,
    oauth_server_access_validation_checks_live_opaque_and_signed_tokens
);
async fn oauth_refresh_grant_narrows_scope_rotates_and_replay_removes_family<B: Backend>(
    db: Db,
) -> TestResult {
    refresh_lifecycle::<B>(db, true, false, false).await
}
async fn oauth_authorization_code_registration_implicitly_issues_and_rotates_refresh_tokens<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    refresh_lifecycle::<B>(db, false, false, false).await
}
#[derive(Debug)]
struct TypedTokenHasher;
#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenHasher for TypedTokenHasher {
    async fn hash(&self, token: &str, kind: &str) -> alibi::AuthResult<String> {
        Ok(format!(
            "app:{kind}:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token))
        ))
    }
}
async fn oauth_custom_token_hashing_protects_real_grant_and_refresh_storage<B: Backend>(
    db: Db,
) -> TestResult {
    refresh_lifecycle::<B>(db, false, true, false).await
}
async fn oauth_server_access_validation_checks_live_opaque_and_signed_tokens<B: Backend>(
    db: Db,
) -> TestResult {
    refresh_lifecycle::<B>(db, false, false, true).await
}
async fn refresh_lifecycle<B: Backend>(
    db: Db,
    explicit_refresh: bool,
    custom_hash: bool,
    server_validation: bool,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::with_config(alibi::plugins::OAuthProviderConfig {
        token_hasher: custom_hash.then(|| {
            std::sync::Arc::new(TypedTokenHasher)
                as std::sync::Arc<dyn alibi::plugins::OAuthTokenHasher>
        }),
        ..Default::default()
    });
    for kind in [
        "authorization_code",
        "access_token",
        "refresh_token",
        "application-kind",
    ] {
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest("known-token"));
        assert_eq!(
            provider.hash_token("known-token", kind).await?,
            if custom_hash {
                format!("app:{kind}:{expected}")
            } else {
                expected
            }
        );
    }
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "refresh-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":if custom_hash {"client_secret_post"} else {"none"},"skip_consent":true,"grant_types":if explicit_refresh{vec!["authorization_code","refresh_token"]}else{vec!["authorization_code"]}}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let secret = body(&created)["client_secret"].as_str().map(str::to_owned);
    let credential_body = |mut input: Value| {
        if let Some(secret) = &secret {
            input["client_secret"] = json!(secret);
        }
        input
    };
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
    let code_hash =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&code));
    let code_hash = if custom_hash {
        format!("app:authorization_code:{code_hash}")
    } else {
        code_hash
    };
    assert!(
        auth.store()
            .get_verification_by_identifier(&code_hash)
            .await?
            .is_some()
    );
    let input = credential_body(
        json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"}),
    );
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
    let hash = |token: &str, kind: OAuthTokenKind| {
        let hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(token));
        if custom_hash {
            format!(
                "app:{}:{hash}",
                if matches!(kind, OAuthTokenKind::Refresh) {
                    "refresh_token"
                } else {
                    "access_token"
                }
            )
        } else {
            hash
        }
    };
    assert!(
        auth.store()
            .get_verification_by_identifier(
                &provider.hash_token(&code, "authorization_code").await?
            )
            .await?
            .is_none(),
        "code exchange consumes its protected grant"
    );
    let original = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &hash(refresh, OAuthTokenKind::Refresh),
        )
        .await?
        .unwrap();
    assert_eq!(original.token, hash(refresh, OAuthTokenKind::Refresh));
    assert_eq!(
        original.authorization_code_id.as_deref(),
        Some(code_hash.as_str())
    );
    if server_validation {
        let now = chrono::Utc::now().timestamp();
        let audience = format!(
            "{}{}{}",
            auth.config().base_url.trim_end_matches('/'),
            auth.config().base_path,
            "/oauth2/userinfo"
        );
        let issuer = format!(
            "{}{}",
            auth.config().base_url.trim_end_matches('/'),
            auth.config().base_path
        );
        let mut cases = vec![
            ("opaque".to_owned(), plaintext.to_owned(), None, true, false),
            (
                "opaque-bound".into(),
                plaintext.into(),
                Some(id.clone()),
                true,
                false,
            ),
            (
                "opaque-foreign".into(),
                plaintext.into(),
                Some("foreign".into()),
                false,
                false,
            ),
            ("refresh".into(), refresh.into(), None, false, true),
            ("missing".into(), "missing".into(), None, false, true),
            (
                "bearer".into(),
                format!("Bearer {plaintext}"),
                None,
                false,
                true,
            ),
        ];
        for (name, changes) in [
            ("jwt", json!({})),
            ("expired", json!({"exp":now-10})),
            ("issuer", json!({"iss":"https://foreign.test"})),
            ("future", json!({"nbf":now+90})),
            ("audience", json!({"aud":"https://foreign.test"})),
            ("missing-client", json!({"azp":"missing-client"})),
            ("no-sub", json!({"sub":null})),
            ("no-azp", json!({"azp":null})),
            ("missing-session", json!({"sid":"missing-session"})),
            ("live-session", json!({"sid":original.session_id})),
            (
                "no-sub-live-session",
                json!({"sub":null,"sid":original.session_id}),
            ),
        ] {
            let mut payload =
                json!({"iss":issuer,"aud":audience,"azp":id,"sub":"owner","iat":now,"exp":now+60});
            for (key, value) in changes.as_object().unwrap() {
                if value.is_null() {
                    _ = payload.as_object_mut().unwrap().remove(key);
                } else {
                    payload[key] = value.clone();
                }
            }
            let jwt = auth.context().extensions.get::<JwtPlugin>().unwrap();
            let signed = jwt
                .sign_jwt_json(
                    &alibi::utils::json::JsValue::from(payload),
                    &Default::default(),
                    None,
                    auth.context(),
                )
                .await?;
            cases.push((
                name.into(),
                signed,
                None,
                matches!(
                    name,
                    "jwt" | "no-sub" | "live-session" | "no-sub-live-session"
                ),
                false,
            ));
        }
        let signed = cases
            .iter()
            .find(|(name, ..)| name == "jwt")
            .unwrap()
            .1
            .clone();
        let mut parts = signed.split('.').map(str::to_owned).collect::<Vec<_>>();
        let first = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, first);
        cases.push(("bad-signature".into(), parts.join("."), None, false, false));
        for (name, value, bound, active, missing) in cases {
            for require_active in [false, true] {
                let result = if require_active {
                    provider
                        .require_active_access_token(auth.context(), &value, bound.as_deref())
                        .await
                } else {
                    provider
                        .validate_access_token(auth.context(), &value, bound.as_deref())
                        .await
                };
                if matches!(name.as_str(), "issuer" | "future" | "bad-signature") {
                    let error = result.expect_err(&name);
                    assert_eq!(error.error.status_code(), 500, "{name}");
                } else if missing || (require_active && !active) {
                    let error = result.expect_err(&name);
                    assert_eq!(error.error.status_code(), 401, "{name}");
                    assert_eq!(
                        error
                            .headers
                            .unwrap()
                            .get("WWW-Authenticate")
                            .map(String::as_str),
                        Some(
                            "Bearer error=\"invalid_token\", error_description=\"Invalid access token\""
                        )
                    );
                    assert_eq!(
                        error.body.unwrap().to_json_value()?,
                        json!({"error":"invalid_token","error_description":"Invalid access token"})
                    );
                } else {
                    let payload = result?;
                    assert_eq!(payload["active"], active, "{name}");
                    if active {
                        assert_eq!(payload["client_id"], id);
                        assert_eq!(payload["iss"], issuer);
                        assert_eq!(payload["token_type"], "Bearer");
                        if name.starts_with("opaque") {
                            assert_eq!(payload["scope"], "email offline_access");
                            assert_eq!(payload["sub"], original.user_id.as_deref().unwrap());
                            assert_eq!(payload["sid"], original.session_id.as_deref().unwrap());
                        } else {
                            assert_eq!(payload["aud"], audience);
                            assert_eq!(
                                payload.get("sub").and_then(Value::as_str),
                                if matches!(name.as_str(), "no-sub" | "no-sub-live-session") {
                                    None
                                } else {
                                    Some("owner")
                                }
                            );
                        }
                    } else {
                        assert_eq!(payload, json!({"active":false}));
                    }
                }
            }
        }
    }
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
            OAuthProviderPlugin::oauth2_token_endpoint(&credential_body(input.clone()))?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(credential_body(input)), "")),
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
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &hash(refresh, OAuthTokenKind::Refresh)
                )
                .await?
                .unwrap()
                .metadata,
            original.metadata
        );
    }
    let input = credential_body(
        json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh,"scope":"email"}),
    );
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
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &hash(refresh, OAuthTokenKind::Refresh),
        )
        .await?
        .unwrap();
    assert!(!old.metadata["revoked"].is_null());
    assert_eq!(old.metadata["rotatedAt"], old.metadata["revoked"]);
    let next = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &hash(next_refresh, OAuthTokenKind::Refresh),
        )
        .await?
        .unwrap();
    assert_eq!(next.metadata["scopes"], json!(["email"]));
    assert_eq!(next.metadata["authTime"], original.metadata["authTime"]);
    assert_eq!(next.user_id, original.user_id);
    assert_eq!(next.session_id, original.session_id);
    assert_eq!(next.authorization_code_id, original.authorization_code_id);
    let linked = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Access,
            &hash(next_access, OAuthTokenKind::Access),
        )
        .await?
        .unwrap();
    assert_eq!(linked.metadata["refreshId"], next.id);
    assert!(
        auth.store()
            .get_oauth_token(
                OAuthTokenKind::Access,
                &hash(plaintext, OAuthTokenKind::Access)
            )
            .await?
            .is_some()
    );
    if custom_hash {
        for value in [next_access, next_refresh] {
            let input = credential_body(json!({"client_id":id,"token":value}));
            let response = Box::pin(auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_introspect_endpoint(&input)?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(response.status, 200);
            assert_eq!(body(&response)["active"], true);
            assert_eq!(body(&response)["client_id"], id);
            assert_eq!(body(&response)["scope"], "email");
        }
        let denied = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_user_info_endpoint(),
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {next_access}"))]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":"invalid_scope","error_description":"Missing required scope"})
        );
        let input = credential_body(json!({"client_id":id,"token":plaintext}));
        let revoked = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_revoke_endpoint(&input)?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(revoked.status, 200);
        assert!(
            auth.store()
                .get_oauth_token(
                    OAuthTokenKind::Access,
                    &hash(plaintext, OAuthTokenKind::Access)
                )
                .await?
                .is_none()
        );
        let inactive = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_introspect_endpoint(&input)?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&inactive), json!({"active":false}));
    }
    let input = credential_body(
        json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh}),
    );
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
                .get_oauth_token(kind, &hash(value, kind))
                .await?
                .is_none()
        );
    }
    Ok(())
}
