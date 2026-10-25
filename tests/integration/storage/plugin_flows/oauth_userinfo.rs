//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;

#[derive(Debug, Default)]
struct UserInfoRequests(Mutex<Vec<Option<AuthRequest>>>);

#[async_trait::async_trait]
impl alibi::plugins::OAuthUserInfoClaimsContributor for UserInfoRequests {
    async fn contribute(
        &self,
        input: alibi::plugins::OAuthUserInfoClaimsInput<'_>,
    ) -> alibi::AuthResult<serde_json::Map<String, Value>> {
        self.0.lock().unwrap().push(input.context.request);
        Ok(serde_json::Map::new())
    }
}

backend_tests!(oauth_userinfo_resolves_scoped_claims_from_real_access_authority);
async fn oauth_userinfo_resolves_scoped_claims_from_real_access_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let receipts = Arc::new(UserInfoRequests::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(
            alibi::plugins::OAuthProviderConfig {
                custom_user_info_claims: Some(receipts.clone()),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "userinfo-owner@example.test").await;
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
    assert!(
        callback
            .query_pairs()
            .any(|(key, value)| key == "state" && value == "token-state")
    );
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

    let expected = json!({"sub":body(&owner)["user"]["id"],"name":"Native owner","given_name":"Native","family_name":"owner","email":"userinfo-owner@example.test","email_verified":false});
    for (header, input, method, attach) in [
        (format!("Bearer {plaintext}"), None, HttpMethod::Get, true),
        (
            format!("bearer   {plaintext}  "),
            None,
            HttpMethod::Get,
            true,
        ),
        (plaintext.to_owned(), None, HttpMethod::Get, true),
        (format!("Bearer {plaintext}"), None, HttpMethod::Get, false),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            true,
        ),
    ] {
        let endpoint = ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo");
        let endpoint = if let Some(body) = &input {
            endpoint.with_body(body)?
        } else {
            endpoint
        };
        let mut physical = request("/oauth2/userinfo", input.clone(), "");
        physical.method = method.clone();
        let response = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                headers: Some([("authorization".into(), header)].into_iter().collect()),
                request: attach.then_some(physical),
                method: Some(method),
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        assert_eq!(body(&response), expected);
    }
    for (header, input, method, attach, status, error, description) in [
        (
            String::new(),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Get,
            true,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            String::new(),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            false,
            401,
            "invalid_request",
            "access token not found",
        ),
        (
            format!("Bearer {plaintext}"),
            Some(json!({"access_token":plaintext})),
            HttpMethod::Post,
            true,
            400,
            "invalid_request",
            "Multiple access token transport methods are not allowed",
        ),
        (
            "Bearer missing-token".into(),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_token",
            "Invalid access token",
        ),
        (
            format!("DPoP {plaintext}"),
            None,
            HttpMethod::Get,
            true,
            401,
            "invalid_token",
            "DPoP authorization requires a DPoP-bound access token",
        ),
    ] {
        let endpoint = ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo");
        let endpoint = if let Some(body) = &input {
            endpoint.with_body(body)?
        } else {
            endpoint
        };
        let mut physical = request("/oauth2/userinfo", input, "");
        physical.method = method.clone();
        let denied = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                headers: Some([("authorization".into(), header)].into_iter().collect()),
                request: attach.then_some(physical),
                method: Some(method),
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if description == "Invalid access token" {
            assert_eq!(
                denied
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("www-authenticate"))
                    .map(String::as_str),
                Some("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"")
            );
        }
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
    }

    // The public adapter must consume the admitted form, not reparse the JSON
    // dispatch bytes. Private dispatch above independently owns optional Request.
    receipts.0.lock().unwrap().clear();
    for (value, kind) in [
        (json!(null), "null"),
        (json!(17), "number"),
        (json!([plaintext]), "array"),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_user_info_endpoint()
                    .with_body(&json!({"access_token":value}))?,
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {plaintext}"))]
                            .into_iter()
                            .collect(),
                    ),
                    request: Some(request("/oauth2/userinfo", None, "")),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        let denied = denied.error.to_auth_response();
        assert_eq!(denied.status, 400);
        assert_eq!(
            body(&denied),
            json!({"code":"VALIDATION_ERROR","message":format!("[body.access_token] Invalid input: expected string, received {kind}")})
        );
    }
    assert!(receipts.0.lock().unwrap().is_empty());
    let provider = OAuthProviderPlugin::new();
    let authority = |row: alibi::store::OAuthToken| {
        (
            row.id,
            row.token,
            row.client_id,
            row.user_id,
            row.session_id,
            row.authorization_code_id,
            row.metadata,
            row.created_at,
            row.expires_at,
        )
    };
    let hash = provider.hash_token(plaintext, "access_token").await?;
    let original = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
        .await?
        .unwrap();
    let mut failures = Vec::new();
    for (method, header, form, status, expected_body) in [
        (
            HttpMethod::Post,
            "".to_owned(),
            format!("access_token={plaintext}"),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Post,
            " \t ".to_owned(),
            format!("access_token={plaintext}"),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Post,
            format!("Bearer {plaintext}"),
            format!("access_token={plaintext}"),
            400,
            json!({"error":"invalid_request","error_description":"Multiple access token transport methods are not allowed"}),
        ),
        (
            HttpMethod::Post,
            format!("Bearer {plaintext}"),
            "access_token=".into(),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Post,
            format!("Bearer {plaintext}"),
            String::new(),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Get,
            format!("Bearer {plaintext}"),
            String::new(),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Get,
            String::new(),
            String::new(),
            401,
            json!({"error":"invalid_request","error_description":"access token not found"}),
        ),
        (
            HttpMethod::Post,
            String::new(),
            format!("access_token=missing&access_token={plaintext}"),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Post,
            String::new(),
            format!("access_token={plaintext}&access_token="),
            401,
            json!({"error":"invalid_request","error_description":"access token not found"}),
        ),
    ] {
        let mut physical = request("/oauth2/userinfo", None, "");
        physical.set_query_pairs([("access_token", plaintext)]);
        physical.method = method;
        _ = physical.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        _ = physical.headers.insert("authorization".into(), header);
        physical.body = Some(form.into_bytes());
        let original_request = physical.clone();
        let response = Box::pin(auth.handle_request(physical)).await?;
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        if response.status != status || body(&response) != expected_body {
            failures.push(format!(
                "unbound: expected {status} {expected_body}, got {} {}",
                response.status,
                body(&response)
            ));
        }
        let calls = std::mem::take(&mut *receipts.0.lock().unwrap());
        if response.status == 200 {
            assert_eq!(calls.len(), 1);
            let received = calls[0].as_ref().unwrap();
            assert_eq!(received.method(), original_request.method());
            assert_eq!(received.path(), original_request.path());
            assert_eq!(received.body, original_request.body);
        } else {
            assert!(
                calls.is_empty(),
                "denied reads must not invoke claims callbacks"
            );
        }
    }
    assert_eq!(
        authority(
            auth.store()
                .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
                .await?
                .unwrap()
        ),
        authority(original)
    );

    // Obtain a second, genuinely sender-bound token through the same client,
    // PKCE grant and consumed code, not by seeding confirmation metadata.
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
    assert!(
        callback
            .query_pairs()
            .any(|(key, value)| key == "state" && value == "token-state")
    );
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let mut bound_input = input.clone();
    bound_input["code"] = json!(code);
    let token_url = format!("{ORIGIN}/api/auth/oauth2/token");
    let proof = super::oauth_dpop_proof::proof(
        json!({"htm":"POST","htu":token_url,"jti":"userinfo-issue","iat":chrono::Utc::now().timestamp()}),
        json!({}),
    )?;
    let issued = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&bound_input)?,
        EndpointOptions {
            headers: Some([("dpop".into(), proof)].into_iter().collect()),
            request: Some(request("/oauth2/token", Some(bound_input), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(issued.status, 200);
    assert_eq!(body(&issued)["token_type"], "DPoP");
    let bound = body(&issued)["access_token"].as_str().unwrap().to_owned();
    let bound_hash = provider.hash_token(&bound, "access_token").await?;
    let original = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &bound_hash)
        .await?
        .unwrap();
    assert_eq!(
        original.metadata["confirmation"]["jkt"],
        "yAJQz9pEsZrW3t2ISLq2eQ2bDNmV0AHCGdbF-8RSbko"
    );
    // The request URL deliberately differs from the configured base URL, as
    // behind a rewriting proxy: proofs bind the public URL built from the base
    // URL and the request's own path below the base path.
    let public = format!("{ORIGIN}/api/auth/oauth2/userinfo");
    let uri = public.as_str();
    let request_uri = "https://userinfo.fixture.test/api/auth/oauth2/userinfo";
    let proof = |method: &str, url: &str, jti: &str| {
        super::oauth_dpop_proof::proof(
            json!({"htm":method,"htu":url,"jti":jti,"iat":chrono::Utc::now().timestamp(),"ath":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&bound))}),
            json!({}),
        )
    };
    let accepted_proof = proof("POST", uri, "userinfo-post")?;
    for (method, header, form, proof, status, expected_body) in [
        (
            HttpMethod::Post,
            format!("DPoP {bound}"),
            format!("access_token={bound}"),
            proof("POST", uri, "userinfo-mixed")?,
            400,
            json!({"error":"invalid_request","error_description":"Multiple access token transport methods are not allowed"}),
        ),
        (
            HttpMethod::Post,
            String::new(),
            format!("access_token={bound}"),
            proof("POST", uri, "userinfo-body")?,
            401,
            json!({"error":"invalid_token","error_description":"DPoP-bound access token requires the DPoP authorization scheme"}),
        ),
        (
            HttpMethod::Post,
            format!("DPoP {bound}"),
            String::new(),
            proof("GET", uri, "userinfo-method")?,
            401,
            json!({"error":"invalid_dpop_proof","error_description":"DPoP proof htm does not match the request method"}),
        ),
        (
            HttpMethod::Post,
            format!("DPoP {bound}"),
            String::new(),
            proof("POST", "https://wrong.test/userinfo", "userinfo-url")?,
            401,
            json!({"error":"invalid_dpop_proof","error_description":"DPoP proof htu does not match the request URL"}),
        ),
        (
            HttpMethod::Post,
            format!("DPoP {bound}"),
            String::new(),
            accepted_proof.clone(),
            200,
            expected.clone(),
        ),
        (
            HttpMethod::Post,
            format!("DPoP {bound}"),
            String::new(),
            accepted_proof,
            401,
            json!({"error":"invalid_dpop_proof","error_description":"DPoP proof jti has already been used"}),
        ),
        (
            HttpMethod::Get,
            format!("DPoP {bound}"),
            String::new(),
            proof("GET", uri, "userinfo-get")?,
            200,
            expected.clone(),
        ),
    ] {
        let mut physical =
            request("/oauth2/userinfo", None, "").with_url(format!("{request_uri}?ignored=1").parse()?);
        physical.method = method;
        physical.headers.extend([
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("authorization".into(), header),
            ("dpop".into(), proof),
        ]);
        physical.body = Some(form.into_bytes());
        let original_request = physical.clone();
        let response = Box::pin(auth.handle_request(physical)).await?;
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            Some("no-cache")
        );
        if response.status != status || body(&response) != expected_body {
            failures.push(format!(
                "bound: expected {status} {expected_body}, got {} {}",
                response.status,
                body(&response)
            ));
        }
        let calls = std::mem::take(&mut *receipts.0.lock().unwrap());
        if response.status == 200 {
            assert_eq!(calls.len(), 1);
            let received = calls[0].as_ref().unwrap();
            assert_eq!(received.method(), original_request.method());
            assert_eq!(received.url(), original_request.url());
            assert_eq!(received.body, original_request.body);
        } else {
            assert!(
                calls.is_empty(),
                "denied reads must not invoke claims callbacks"
            );
        }
    }
    let denied = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_user_info_endpoint(),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), format!("DPoP {bound}"))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_token","error_description":"DPoP-bound access token requires an HTTP request context"})
    );
    assert_eq!(
        authority(
            auth.store()
                .get_oauth_token(alibi::store::OAuthTokenKind::Access, &bound_hash)
                .await?
                .unwrap()
        ),
        authority(original)
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));

    for scope in ["openid", "email"] {
        let mut query = query.clone();
        query["scope"] = json!(scope);
        if scope == "email" {
            _ = query.as_object_mut().unwrap().remove("nonce");
        }
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
        let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        let issued = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let scoped_token = body(&issued)["access_token"].as_str().unwrap().to_owned();
        let result = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
                EndpointOptions {
                    headers: Some(
                        [("authorization".into(), format!("Bearer {scoped_token}"))]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await;
        if scope == "openid" {
            assert_eq!(
                body(&result?.into_response()?),
                json!({"sub":body(&owner)["user"]["id"]})
            );
            let input =
                json!({"client_id":id,"token":scoped_token,"token_type_hint":"access_token"});
            let retired = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2Revoke").with_body(&input)?,
                EndpointOptions {
                    request: Some(request("/oauth2/revoke", Some(input), "")),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(retired.status, 200);
            let denied = Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
                    EndpointOptions {
                        headers: Some(
                            [("authorization".into(), format!("Bearer {scoped_token}"))]
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
        } else {
            let denied = result.unwrap_err();
            assert_eq!(denied.error.status_code(), 400);
            assert_eq!(
                denied.body.unwrap().to_json_value()?,
                json!({"error":"invalid_scope","error_description":"Missing required scope"})
            );
        }
    }
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    auth.store()
        .update_session_expiry(
            body(&observed)["session"]["token"].as_str().unwrap(),
            chrono::Utc::now() - chrono::Duration::seconds(1),
        )
        .await?;
    let denied = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2UserInfo"),
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
    Ok(())
}
