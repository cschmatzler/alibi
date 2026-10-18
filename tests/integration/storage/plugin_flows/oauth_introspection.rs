//! Introspection authenticates real clients and reports issued token authority.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;

pub(super) struct LogicalTokenInput;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::endpoint::EndpointHook<S> for LogicalTokenInput {
    fn matches_before(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<bool> {
        Ok(
            matches!(call.operation_id(), "oauth2Introspect" | "oauth2Revoke")
                && call
                    .headers()
                    .is_some_and(|headers| headers.contains_key("x-logical-token")),
        )
    }
    async fn before(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<alibi::endpoint::BeforeEndpointAction>> {
        let headers = call.headers().unwrap();
        let mut body = call.body().unwrap().to_json_value()?;
        body["token"] = json!(headers["x-logical-token"]);
        body["client_id"] = json!("logical-client-is-not-authoritative");
        body["client_secret"] = json!(
            headers
                .get("x-logical-secret")
                .map_or("logical-secret-is-not-authoritative", String::as_str)
        );
        Ok(Some(alibi::endpoint::BeforeEndpointAction::Patch(
            Box::new(alibi::endpoint::EndpointContextPatch {
                body: Some(alibi::utils::json::JsValue::from(body)),
                ..Default::default()
            }),
        )))
    }
}

pub(super) async fn client_denials<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    id: &str,
    secret: &str,
    token: &str,
) -> TestResult {
    // The private control verifies the issued client's secret before exercising
    // the HTTP adapter; the denial must not merely be a lost-token parse error.
    let operation = if path.ends_with("introspect") {
        "oauth2Introspect"
    } else {
        "oauth2Revoke"
    };
    let wrong = json!({"client_id":id,"client_secret":"wrong","token":token});
    let denied = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&wrong)?,
        EndpointOptions {
            request: Some(request(path, Some(wrong.clone()), "")),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"invalid client_secret"})
    );
    let valid = json!({"client_id":id,"client_secret":secret,"token":token});
    for (field, value, description) in [
        ("client_secret", json!("wrong"), "invalid client_secret"),
        (
            "client_id",
            json!([id, id]),
            "client_id must not be repeated",
        ),
        (
            "client_secret",
            json!([secret, secret]),
            "client_secret must not be repeated",
        ),
        (
            "client_assertion",
            json!(["assertion", "assertion"]),
            "client_assertion must not be repeated",
        ),
        (
            "client_assertion_type",
            json!(["urn:assertion", "urn:assertion"]),
            "client_assertion_type must not be repeated",
        ),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        let response = call(auth, public_request(path, &input), 400).await;
        assert_eq!(
            body(&response),
            json!({"error":if field == "client_secret" && input[field].is_string() {"invalid_client"} else {"invalid_request"},"error_description":description})
        );
    }
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    );
    for (input, description) in [
        (
            valid.clone(),
            "A request must use only one client authentication method",
        ),
        (
            json!({"token":token}),
            "client registered for client_secret_post cannot use client_secret_basic",
        ),
    ] {
        let mut req = public_request(path, &input);
        _ = req.headers.insert("authorization".into(), basic.clone());
        let response = call(
            auth,
            req,
            if input.get("client_secret").is_some() {
                400
            } else {
                401
            },
        )
        .await;
        assert_eq!(body(&response)["error_description"], description);
    }
    // A logical patch cannot replace a wrong physical credential.
    let mut req = public_request(path, &wrong);
    req.headers.extend([
        ("x-logical-token".into(), token.into()),
        ("x-logical-secret".into(), secret.into()),
    ]);
    let response = call(auth, req, 400).await;
    assert_eq!(
        body(&response),
        json!({"error":"invalid_client","error_description":"invalid client_secret"})
    );
    Ok(())
}

pub(super) fn public_request(path: &str, input: &Value) -> AuthRequest {
    let mut req = request(path, None, "");
    req.method = HttpMethod::Post;
    _ = req.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    req.body = Some(
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(input.as_object().unwrap().iter().flat_map(|(key, value)| {
                let values = value
                    .as_array()
                    .map_or_else(|| vec![value], |values| values.iter().collect());
                values
                    .into_iter()
                    .map(move |value| (key.as_str(), value.as_str().unwrap()))
            }))
            .finish()
            .into_bytes(),
    );
    req
}
backend_tests!(oauth_introspection_reports_issued_tokens_and_session_liveness);
async fn oauth_introspection_reports_issued_tokens_and_session_liveness<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .endpoint_hook(LogicalTokenInput)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "introspection-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"client_secret_post","skip_consent":true,"grant_types":["authorization_code","refresh_token"]}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let secret = body(&created)["client_secret"].as_str().unwrap().to_owned();
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
    let input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
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

    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    client_denials(&auth, "/oauth2/introspect", &id, &secret, plaintext).await?;
    for (issued, hint, lifetime) in [
        (plaintext, "access_token", 3600),
        (refresh, "refresh_token", 2_592_000),
    ] {
        for hint in [Some(hint), None, Some("unknown_hint")] {
            let mut input = json!({"client_id":id,"client_secret":secret,"token":issued});
            if let Some(hint) = hint {
                input["token_type_hint"] = json!(hint);
            }
            let active = call(&auth, public_request("/oauth2/introspect", &input), 200).await;
            assert_eq!(active.status, 200);
            let payload = body(&active);
            assert_eq!(payload["active"], true);
            assert_eq!(payload["client_id"], id);
            assert_eq!(payload["sub"], body(&owner)["user"]["id"]);
            assert_eq!(payload["scope"], "email offline_access");
            assert_eq!(payload["token_type"], "Bearer");
            assert_eq!(
                payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
                lifetime
            );
            assert_eq!(payload["sid"], body(&observed)["session"]["id"]);
            assert_eq!(
                payload["iss"],
                format!(
                    "{}{}",
                    auth.context().config.base_url,
                    auth.context().config.base_path
                )
            );
            if lifetime == 3600 {
                assert_eq!(payload["azp"], id);
            } else {
                assert!(payload.get("azp").is_none());
            }
            assert!(payload.get("aud").is_none());
            if hint == Some("access_token") && lifetime == 3600 {
                let mut repeated = input.clone();
                repeated["token"] = json!(["unknown-token", issued]);
                repeated["token_type_hint"] = json!(["refresh_token", "access_token"]);
                repeated["client_id"] = json!(["", id]);
                repeated["client_secret"] = json!(["", secret]);
                let last = call(&auth, public_request("/oauth2/introspect", &repeated), 200).await;
                assert_eq!(body(&last), payload);
                input["token"] = json!("physical-token-is-not-the-logical-input");
                let mut req = public_request("/oauth2/introspect", &input);
                _ = req.headers.insert("x-logical-token".into(), issued.into());
                let patched = call(&auth, req, 200).await;
                assert_eq!(body(&patched), payload);
            }
        }
    }
    for (input, status, error, description) in [
        (
            json!({"token":plaintext}),
            401,
            "invalid_client",
            "missing required credentials",
        ),
        (
            json!({"client_id":id,"client_secret":"wrong","token":plaintext}),
            400,
            "invalid_client",
            "invalid client_secret",
        ),
        (
            json!({"client_id":id,"client_secret":secret,"token":""}),
            400,
            "invalid_request",
            "missing a required token for introspection",
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(input), "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
    }
    for (issued, hint) in [
        ("unknown-token", "access_token"),
        ("unknown-token", "refresh_token"),
        (plaintext, "refresh_token"),
        (refresh, "access_token"),
    ] {
        let input =
            json!({"client_id":id,"client_secret":secret,"token":issued,"token_type_hint":hint});
        let result = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&result), json!({"active":false}));
    }
    auth.store()
        .update_session_expiry(
            body(&observed)["session"]["token"].as_str().unwrap(),
            chrono::Utc::now() - chrono::Duration::seconds(1),
        )
        .await?;
    for (issued, hint, active) in [
        (plaintext, "access_token", false),
        (refresh, "refresh_token", true),
    ] {
        let input =
            json!({"client_id":id,"client_secret":secret,"token":issued,"token_type_hint":hint});
        let result = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let payload = body(&result);
        assert_eq!(payload["active"], active);
        assert!(payload.get("sid").is_none());
        if active {
            assert_eq!(payload["sub"], body(&observed)["user"]["id"]);
            assert_eq!(payload["scope"], "email offline_access");
            assert_eq!(payload["client_id"], id);
            assert_eq!(
                payload["iss"],
                format!(
                    "{}{}",
                    auth.context().config.base_url,
                    auth.context().config.base_path
                )
            );
            assert_eq!(
                payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
                2_592_000
            );
        } else {
            assert_eq!(payload, json!({"active":false}));
        }
    }
    Ok(())
}
