//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/token-response-fields.rs"]
pub(super) mod token_response_fields;
backend_tests!(
    oauth_token_exchanges_bound_code_and_revokes_on_replay,
    oauth_configured_token_response_fields_follow_real_grant_lifecycle
);

async fn oauth_configured_token_response_fields_follow_real_grant_lifecycle<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession as _;
    use alibi::plugins::{OAuthProviderConfig, OAuthTokenIssueParams};
    use alibi::store::OAuthTokenKind;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let fields = Arc::new(token_response_fields::TokenResponseFields::default());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        custom_token_response_fields: Some(fields.clone()),
        disable_jwt_plugin: true,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "response-owner@example.test").await;
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let session = auth
        .store()
        .get_user_sessions(&user_id)
        .await?
        .pop()
        .unwrap();
    let options = || EndpointOptions {
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
    };
    let created = Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
        "client_name":"Response fields","redirect_uris":["https://app.fixture.test/callback"],
        "scope":"profile email offline_access","token_endpoint_auth_method":"none","skip_consent":true,
        "metadata":{"tenant":"application"}
    }))?, options())).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client_id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let resource = "https://api.fixture.test/response-fields";
    let registered = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthResource").with_body(
            &json!({"identifier":resource,"allowedScopes":["email","offline_access"]}),
        )?,
        options(),
    ))
    .await?
    .into_response()?;
    assert_eq!(registered.status, 200);
    let linked = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminLinkClientResource")
                .with_params(&json!({"identifier":resource,"client_id":client_id}))?,
            options(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(linked.status, 200);
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":client_id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback",
        "scope":"profile email offline_access","resource":resource,"state":"response-state","code_challenge":challenge,"code_challenge_method":"S256"});
    let mut issued = Value::Null;
    let public_request = |input: &Value| {
        let mut req = request("/oauth2/token", None, "");
        req.method = HttpMethod::Post;
        _ = req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.body = Some(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(
                    input
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str().unwrap())),
                )
                .finish()
                .into_bytes(),
        );
        req
    };
    let assert_failure = |response: &AuthResponse, mode: &str| {
        let (status, expected) = match mode {
            "api" => (
                422,
                json!({"code":"RESPONSE_REJECTED","message":"Operator response denied"}),
            ),
            "forbidden" => (403, json!({"message":"Operator response forbidden"})),
            "upstream" => (
                409,
                json!({"code":"RESPONSE_CONFLICT","message":"Operator response conflict"}),
            ),
            _ => (500, Value::Null),
        };
        assert_eq!(response.status, status);
        if mode == "ordinary" {
            assert!(response.body.is_empty());
            for name in ["content-type", "cache-control", "pragma"] {
                assert!(
                    response.headers.get(name).is_none(),
                    "ordinary failure leaked {name}: {:?}",
                    response.headers
                );
            }
        } else {
            assert_eq!(body(response), expected);
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(
                response.headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(
                response.headers.get("pragma").map(String::as_str),
                Some("no-cache")
            );
        }
    };
    for mode in ["ordinary", "api", "forbidden", "upstream", "success"] {
        *fields.mode.lock().unwrap() = mode.into();
        let grant = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            options(),
        ))
        .await?
        .into_response()?;
        assert_eq!(grant.status, 200);
        let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let input = json!({"grant_type":"authorization_code","client_id":client_id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        let response = Box::pin(auth.handle_request(public_request(&input))).await?;
        if mode == "success" {
            assert_eq!(response.status, 200);
            issued = body(&response);
            assert_eq!(
                issued["application_metadata"],
                json!({"service":"billing","plan":"pro"})
            );
        } else {
            assert_failure(&response, mode);
            for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
                assert!(
                    auth.store()
                        .list_oauth_tokens_for_session(kind, session.id().as_ref())
                        .await?
                        .is_empty()
                );
            }
        }
    }
    let receipt = json!({"grant":"authorization_code","userId":user_id,"email":"response-owner@example.test",
        "scopes":["email","offline_access"],"metadata":{"tenant":"application"},
        "verification":{"type":"authorization_code","userId":user_id,"sessionId":session.id().as_ref(),
            "scope":"profile email offline_access","state":"response-state","clientId":client_id,"challenge":challenge}});
    assert_eq!(*fields.calls.lock().unwrap(), vec![receipt; 5]);
    let original = issued["refresh_token"].as_str().unwrap().to_owned();
    for mode in ["ordinary", "api", "forbidden", "upstream", "success"] {
        *fields.mode.lock().unwrap() = mode.into();
        let input = json!({"grant_type":"refresh_token","client_id":client_id,"refresh_token":original,"scope":"email"});
        let response = Box::pin(auth.handle_request(public_request(&input))).await?;
        if mode == "success" {
            assert_eq!(response.status, 200);
            issued = body(&response);
        } else {
            assert_failure(&response, mode);
            for kind in [OAuthTokenKind::Access, OAuthTokenKind::Refresh] {
                assert_eq!(
                    auth.store()
                        .list_oauth_tokens_for_session(kind, session.id().as_ref())
                        .await?
                        .len(),
                    1
                );
            }
            let hash = provider.hash_token(&original, "refresh_token").await?;
            let row = auth
                .store()
                .get_oauth_token(OAuthTokenKind::Refresh, &hash)
                .await?
                .unwrap();
            assert!(row.metadata.get("revoked").is_none_or(Value::is_null));
        }
    }
    assert_eq!(
        &fields.calls.lock().unwrap()[5..],
        vec![
            json!({"grant":"refresh_token","userId":user_id,
        "email":"response-owner@example.test","scopes":["email"],"metadata":{"tenant":"application"},"verification":null});
            5
        ]
    );
    assert_eq!(issued["scope"], "email");
    assert_eq!(
        issued["application_metadata"],
        json!({"service":"billing","plan":"pro"})
    );
    assert_eq!(issued["per_request"], "global");
    assert_eq!(issued["toString"], "application-toString");
    assert_eq!(issued["__proto__"], json!({"applicationPrototype":true}));
    assert_eq!(issued["nullable"], Value::Null);
    assert_eq!(issued["token_type"], "Bearer");
    assert_eq!(issued["expires_in"], 3600);
    assert!(issued.get("id_token").is_none());
    assert_ne!(issued["refresh_token"], original);
    for (key, kind) in [
        ("access_token", OAuthTokenKind::Access),
        ("refresh_token", OAuthTokenKind::Refresh),
    ] {
        let token = issued[key].as_str().unwrap();
        let hash = provider.hash_token(token, key).await?;
        let row = auth.store().get_oauth_token(kind, &hash).await?.unwrap();
        assert_eq!(row.client_id, client_id);
        assert_eq!(row.user_id.as_deref(), Some(user_id.as_str()));
        assert_eq!(row.metadata["scopes"], json!(["email"]));
        if key == "access_token" {
            assert_eq!(
                row.expires_at.timestamp(),
                issued["expires_at"].as_i64().unwrap()
            );
        }
    }
    // Trusted per-issuance fields override global fields, never protocol fields,
    // including optional protocol fields that are absent for a machine token.
    let client = provider
        .get_client(auth.context(), &client_id)
        .await?
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(client, vec!["email".into()]);
    params.token_response = Some(
        json!({"per_request":"native","access_token":"injected","refresh_token":"injected","id_token":"injected"}),
    );
    let call = alibi::endpoint::EndpointCall::new(
        &alibi::endpoint::EndpointDefinition {
            name: "nativeResponse",
            operation_id: "nativeResponse",
            path: None,
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    // The trusted API must keep the error class, not turn an ordinary callback
    // exception into an intentional empty-body API error.
    for mode in ["ordinary", "forbidden", "upstream"] {
        *fields.mode.lock().unwrap() = mode.into();
        let failure = provider
            .issue_tokens(auth.context(), &call, Some("urn:native:response"), &params)
            .await
            .unwrap_err();
        match mode {
            "ordinary" => assert!(matches!(
                failure.error,
                alibi::AuthError::CallbackFailure(_)
            )),
            "forbidden" => assert!(
                matches!(failure.error, alibi::AuthError::Forbidden(ref message) if message == "Operator response forbidden")
            ),
            _ => assert!(matches!(
                failure.error,
                alibi::AuthError::Upstream {
                    status: 409,
                    code: "RESPONSE_CONFLICT",
                    ..
                }
            )),
        }
        assert!(!failure.body_absent);
    }
    *fields.mode.lock().unwrap() = "success".into();
    let machine = provider
        .issue_tokens(auth.context(), &call, Some("urn:native:response"), &params)
        .await?;
    assert_eq!(machine["per_request"], "native");
    assert_eq!(
        machine["application_metadata"],
        json!({"service":"billing","plan":"pro"})
    );
    assert_eq!(machine["token_type"], "Bearer");
    assert_eq!(machine["scope"], "email");
    assert!(machine.get("refresh_token").is_none());
    assert!(machine.get("id_token").is_none());
    let hash = provider
        .hash_token(machine["access_token"].as_str().unwrap(), "access_token")
        .await?;
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Access, &hash)
            .await?
            .unwrap()
            .user_id
            .is_none()
    );
    assert_eq!(
        fields.calls.lock().unwrap().last(),
        Some(
            &json!({"grant":"urn:native:response","userId":null,"email":null,"scopes":["email"],"metadata":{"tenant":"application"},"verification":null})
        )
    );
    Ok(())
}
async fn oauth_token_exchanges_bound_code_and_revokes_on_replay<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "token-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none","skip_consent":true}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"token-state","code_challenge":challenge,"code_challenge_method":"S256"});
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
    assert_eq!(token["scope"], "email");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());
    assert!(token.get("id_token").is_none());
    let hashed =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(plaintext));
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hashed)
        .await?
        .unwrap();
    assert_eq!(stored.client_id, id);
    assert_eq!(stored.metadata["scopes"], json!(["email"]));
    assert_eq!(
        stored.expires_at.timestamp() - stored.created_at.timestamp(),
        3600
    );
    assert_eq!(
        stored.expires_at.timestamp(),
        token["expires_at"].as_i64().unwrap()
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, plaintext)
            .await?
            .is_none()
    );
    let replay = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        replay.body.unwrap().to_json_value()?,
        json!({"error":"invalid_grant","error_description":"invalid code"})
    );
    assert!(
        auth.store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hashed)
            .await?
            .is_none()
    );

    // This token owner, not registration, owns missing-verifier precedence and
    // whether rejection consumes a genuine grant or revokes issued authority.
    for (method, required) in [
        ("none", Some(false)),
        ("client_secret_post", None),
        ("client_secret_post", Some(true)),
        ("client_secret_post", Some(false)),
    ] {
        let public = method == "none";
        let mut metadata = json!({"client_name":"Precedence client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":method,"skip_consent":true});
        if let Some(required) = required {
            metadata["require_pkce"] = json!(required);
        }
        let created = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_create_oauth_client_endpoint(&metadata)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 201);
        let client = body(&created);
        let pkce_required = public || required != Some(false);
        for (case, bound) in [
            ("missing", true),
            ("empty", true),
            ("malformed", true),
            ("redirect", true),
            ("secret", true),
            ("code", true),
            ("success", true),
            ("missing", false),
            ("empty", false),
            ("malformed", false),
        ] {
            if (!bound && pkce_required) || (case == "secret" && public) {
                continue;
            }
            let mut query = query.clone();
            query["client_id"] = client["client_id"].clone();
            if !bound {
                _ = query.as_object_mut().unwrap().remove("code_challenge");
                _ = query
                    .as_object_mut()
                    .unwrap()
                    .remove("code_challenge_method");
            }
            let produced = Box::pin(
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
            let callback = url::Url::parse(body(&produced)["url"].as_str().unwrap())?;
            let code = callback
                .query_pairs()
                .find(|(key, _)| key == "code")
                .unwrap()
                .1
                .into_owned();
            let mut valid = json!({"grant_type":"authorization_code","client_id":client["client_id"],"code":code,"redirect_uri":"https://app.fixture.test/callback"});
            if !public {
                valid["client_secret"] = client["client_secret"].clone();
            }
            if bound {
                valid["code_verifier"] = json!(verifier);
            }
            let mut input = valid.clone();
            _ = input.as_object_mut().unwrap().remove("code_verifier");
            match case {
                "empty" => input["code_verifier"] = json!(""),
                "malformed" => input["code_verifier"] = json!("!"),
                "redirect" => input["redirect_uri"] = json!("https://app.fixture.test/other"),
                "secret" => input["client_secret"] = json!("wrong-secret"),
                "code" => input["code"] = json!("unknown-code"),
                "success" => input = valid.clone(),
                _ => {}
            }
            let public_request = |input: &Value| {
                let mut req = request("/oauth2/token", None, "");
                req.method = HttpMethod::Post;
                _ = req.headers.insert(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                );
                req.body = Some(
                    url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(
                            input
                                .as_object()
                                .unwrap()
                                .iter()
                                .map(|(key, value)| (key.as_str(), value.as_str().unwrap())),
                        )
                        .finish()
                        .into_bytes(),
                );
                req
            };
            let output = Box::pin(auth.handle_request(public_request(&input))).await?;
            let early = public && matches!(case, "missing" | "empty" | "redirect" | "code");
            let success = case == "success" || (!bound && case != "malformed");
            let (status, error, description) = if success {
                (200, "", "")
            } else if early {
                (
                    400,
                    "invalid_request",
                    "Either code_verifier or client_secret is required",
                )
            } else if case == "redirect" {
                (400, "invalid_grant", "redirect_uri mismatch")
            } else if case == "code" {
                (400, "invalid_grant", "invalid code")
            } else if case == "secret" {
                (400, "invalid_client", "invalid client_secret")
            } else if case == "malformed" {
                (
                    401,
                    "invalid_request",
                    if bound {
                        "code verification failed"
                    } else {
                        "code_verifier provided but PKCE was not used in authorization"
                    },
                )
            } else if pkce_required {
                (400, "invalid_request", "PKCE is required for this client")
            } else {
                (
                    401,
                    "invalid_request",
                    "code_verifier required because PKCE was used in authorization",
                )
            };
            assert_eq!(
                output.status,
                status,
                "{method}/{required:?}/{case}/{bound}: {}",
                body(&output)
            );
            assert_eq!(
                output.headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(
                output.headers.get("pragma").map(String::as_str),
                Some("no-cache")
            );
            assert_eq!(
                output.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(&code));
            let retained = early || case == "code";
            assert_eq!(
                auth.store()
                    .get_verification_by_identifier(&hash)
                    .await?
                    .is_some(),
                retained
            );
            if !success {
                assert_eq!(
                    body(&output),
                    json!({"error":error,"error_description":description})
                );
            }
            let mut token = if success { body(&output) } else { Value::Null };
            if !success {
                let retry = Box::pin(auth.handle_request(public_request(&valid))).await?;
                if retained {
                    assert_eq!(retry.status, 200);
                    token = body(&retry);
                } else {
                    assert_eq!(retry.status, 400);
                    assert_eq!(
                        body(&retry),
                        json!({"error":"invalid_grant","error_description":"invalid code"})
                    );
                }
            }
            if let Some(access) = token["access_token"].as_str() {
                let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(access));
                // A verifier-free replay is rejected before consumption for public
                // clients, but must reach replay revocation for confidential ones.
                let mut replay = valid.clone();
                _ = replay.as_object_mut().unwrap().remove("code_verifier");
                let replay = Box::pin(auth.handle_request(public_request(&replay))).await?;
                assert_eq!(replay.status, 400);
                assert_eq!(
                    body(&replay),
                    if public {
                        json!({"error":"invalid_request","error_description":"Either code_verifier or client_secret is required"})
                    } else {
                        json!({"error":"invalid_grant","error_description":"invalid code"})
                    }
                );
                assert_eq!(
                    auth.store()
                        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
                        .await?
                        .is_some(),
                    public
                );
                let _ = Box::pin(auth.handle_request(public_request(&valid))).await?;
                assert!(
                    auth.store()
                        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
                        .await?
                        .is_none()
                );
            }
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM \"oauthAccessToken\" WHERE \"clientId\" = $1",
                    &[client["client_id"].as_str().unwrap()]
                )
                .await?,
                0
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM \"oauthRefreshToken\" WHERE \"clientId\" = $1",
                    &[client["client_id"].as_str().unwrap()]
                )
                .await?,
                0
            );
        }
    }
    Ok(())
}
