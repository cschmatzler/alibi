//! Dynamic registration gates anonymous admission and persists real client credentials.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
#[path = "../../../fixtures/oauth/initial-access-token.rs"]
mod initial_access_token;

const REGISTRATION_TABLES: &[&str] = &[
    "user",
    "account",
    "session",
    "verification",
    "jwks",
    "oauthClient",
];
backend_tests!(
    oauth_dynamic_registration_enforces_policy_and_persists_clients,
    oauth_registration_scope_capabilities_are_not_grants
);
async fn oauth_registration_scope_capabilities_are_not_grants<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (defaults, allowed, invalid) in [
        (Some(vec!["unknown"]), None, "unknown"),
        (None, Some(vec!["unknown"]), "unknown"),
        (Some(vec![""]), None, ""),
        (
            Some(vec![" email"]),
            Some(vec!["first-invalid"]),
            "first-invalid",
        ),
    ] {
        let result = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_registration_default_scopes: defaults
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                client_registration_allowed_scopes: allowed
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                ..Default::default()
            }))
            .build()
            .await;
        assert!(
            matches!(result, Err(alibi::AuthError::Config(message)) if message == format!("clientRegistrationAllowedScope {invalid} not found in scopes"))
        );
    }
    let mut owner = None;
    for (mode, defaults, allowed, expected) in [
        (
            "fallback",
            None,
            None,
            "openid profile email offline_access",
        ),
        (
            "allowed-empty",
            None,
            Some(vec![]),
            "openid profile email offline_access",
        ),
        ("custom-provider", None, None, "email profile openid"),
        ("empty", Some(vec![]), None, ""),
        ("both-empty", Some(vec![]), Some(vec![]), ""),
        (
            "allowed-only",
            Some(vec![]),
            Some(vec!["profile"]),
            "profile",
        ),
        ("default-only", Some(vec!["email"]), None, "email"),
        (
            "union",
            Some(vec!["email", "email"]),
            Some(vec!["profile", "email", "profile"]),
            "email profile",
        ),
        (
            "allowed-fallback",
            None,
            Some(vec!["email"]),
            "openid profile email offline_access",
        ),
    ] {
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: true,
                    allow_unauthenticated_client_registration: true,
                    scopes: if mode == "custom-provider" {
                        ["email", "profile", "openid", "email", ""]
                            .map(str::to_owned)
                            .into()
                    } else {
                        OAuthProviderConfig::default().scopes
                    },
                    client_registration_default_scopes: defaults
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    client_registration_allowed_scopes: allowed
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        if owner.is_none() {
            owner = Some(Box::pin(signup(&auth, "registration-scopes@example.test")).await);
        }
        let cookie = cookies(owner.as_ref().unwrap());
        for requested in [
            None,
            Some(""),
            Some(" "),
            Some("email"),
            Some("profile"),
            Some("openid"),
            Some("forbidden"),
        ] {
            let mut input = json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"});
            if let Some(scope) = requested {
                input["scope"] = json!(scope);
            }
            let before = db.tables(REGISTRATION_TABLES).await?;
            let output = auth
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                        .with_body(&input)?,
                    EndpointOptions {
                        headers: Some(Default::default()),
                        ..Default::default()
                    },
                )
                .await;
            if requested.is_some_and(|scope| {
                !scope.trim().is_empty() && !expected.split(' ').any(|allowed| allowed == scope)
            }) {
                let error = output.unwrap_err();
                assert_eq!(error.error.status_code(), 400, "{mode}:{requested:?}");
                assert_eq!(
                    error.body.as_deref(),
                    Some(&alibi::utils::json::JsValue::from(
                        json!({"error":"invalid_scope","error_description":format!("cannot request scope {}",requested.unwrap())})
                    ))
                );
                assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
                continue;
            }
            let output = output?.into_response()?;
            assert_eq!(output.status, 201);
            let value = body(&output);
            assert_eq!(value["scope"], expected, "{mode}:{requested:?}");
            let id = value["client_id"].as_str().unwrap();
            let row = auth.store().get_oauth_client(id).await?.unwrap();
            assert_eq!(row.metadata["scope"], expected);
            assert_eq!(db.count("oauthConsent").await?, 0);
            assert_eq!(db.count("oauthAccessToken").await?, 0);
            if mode == "union" && requested == Some("email") {
                // A later request can use the additional capability, but registration granted nothing.
                for (scope, path) in [("profile", "/consent"), ("openid", "/callback")] {
                    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":scope,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
                    let response = auth
                        .dispatch_endpoint(
                            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize")
                                .with_query(&query)?,
                            EndpointOptions {
                                headers: Some(
                                    [
                                        ("cookie".into(), cookie.clone()),
                                        ("accept".into(), "application/json".into()),
                                    ]
                                    .into_iter()
                                    .collect(),
                                ),
                                request: Some(request("/oauth2/authorize", None, "")),
                                ..Default::default()
                            },
                        )
                        .await?
                        .into_response()?;
                    let destination =
                        url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
                    assert_eq!(destination.path(), path);
                    assert_eq!(
                        destination
                            .query_pairs()
                            .find(|(key, _)| key == "error")
                            .map(|(_, v)| v.into_owned()),
                        (scope == "openid").then(|| "invalid_scope".into())
                    );
                }
            }
        }
        // Managed creation and owner updates use provider scopes, not DCR capability policy.
        let managed = auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"openid"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(body(&managed)["scope"], "openid");
        let id = body(&managed)["client_id"].as_str().unwrap().to_owned();
        for patch in [
            json!({"client_name":"Scopes unchanged"}),
            json!({"scope":""}),
            json!({"scope":"profile"}),
        ] {
            let updated = auth
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthClient")
                        .with_body(&json!({"client_id":id,"update":patch}))?,
                    EndpointOptions {
                        headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                        ..Default::default()
                    },
                )
                .await?
                .into_response()?;
            assert_eq!(
                body(&updated)["scope"],
                patch
                    .get("scope")
                    .cloned()
                    .unwrap_or_else(|| json!("openid"))
            );
        }
    }
    Ok(())
}
async fn oauth_dynamic_registration_enforces_policy_and_persists_clients<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = std::sync::Arc::new(initial_access_token::RegistrationPolicy::default());
    let mut auths = Vec::new();
    for mode in 0..5 {
        auths.push(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: mode != 0,
                    allow_unauthenticated_client_registration: matches!(mode, 2 | 4),
                    initial_access_token_validator: (mode >= 3).then(|| {
                        policy.clone()
                            as std::sync::Arc<dyn alibi::plugins::OAuthInitialAccessTokenValidator>
                    }),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
    }
    let owner = signup(&auths[0], "oauth-registration-owner@example.test").await;
    let before = db.tables(REGISTRATION_TABLES).await?;
    for (mode, input, cookie, status) in [
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"client_name":" \u{feff} "}),
            String::new(),
            400,
        ),
        (
            0,
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            403,
        ),
        (
            1,
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            401,
        ),
        (
            2,
            json!({"grant_types":["client_credentials"]}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"forbidden"}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"skip_consent":true}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"subject_type":"pairwise"}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"resources":42}),
            String::new(),
            400,
        ),
        (1, json!({"client_name":42}), cookies(&owner), 400),
    ] {
        let e = auths[mode]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.error.status_code(), status);
        assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
    }
    for mode in [2, 1] {
        for (authorization, status, error, description) in [
            (
                "bEaReR unconfigured",
                401,
                "invalid_token",
                "Invalid initial access token",
            ),
            (
                "Bearer",
                400,
                "invalid_request",
                "Malformed initial access token Authorization header",
            ),
            (
                "Bearer first second",
                400,
                "invalid_request",
                "Malformed initial access token Authorization header",
            ),
        ] {
            let denied = auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("authorization".into(),authorization.into())].into_iter().collect()),..Default::default()}).await.unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            assert_eq!(
                denied.body.as_deref(),
                Some(&alibi::utils::json::JsValue::from(
                    json!({"error":error,"error_description":description})
                ))
            );
            let headers = denied.headers.as_ref().unwrap();
            assert_eq!(
                headers.get("www-authenticate"),
                Some(&format!("Bearer error=\"{error}\""))
            );
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(headers.get("pragma").map(String::as_str), Some("no-cache"));
            assert!(!headers.contains_key("set-cookie"));
            assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
        }
    }
    for (mode, public, cookie) in [(1, false, cookies(&owner)), (2, true, String::new())] {
        let start = chrono::Utc::now().timestamp();
        let output=auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"client_name":if public{"\u{85}"}else{"Owned dynamic client"},"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":if public{"none"}else{"client_secret_basic"},"user_id":"forged","client_id":"forged"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie),("authorization".into(),if public{"Basic ignored"}else{"Bearer unconfigured"}.into())].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(output.status, 201);
        assert_eq!(
            output.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        let value = body(&output);
        assert_eq!(
            value["client_name"],
            if public {
                "\u{85}"
            } else {
                "Owned dynamic client"
            }
        );
        assert_eq!(value["scope"], "openid profile email offline_access");
        assert!(value["client_id_issued_at"].as_i64().unwrap() >= start);
        assert!(value["client_id_issued_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp());
        let id = value["client_id"].as_str().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|c| c.is_ascii_alphabetic()));
        let row = auths[mode].store().get_oauth_client(id).await?.unwrap();
        assert_eq!(row.metadata["scope"], value["scope"]);
        if public {
            assert!(value.get("user_id").is_none());
            assert!(value.get("client_secret").is_none());
            assert!(row.user_id.is_none());
            assert!(row.client_secret.is_none());
        } else {
            let secret = value["client_secret"].as_str().unwrap();
            assert_eq!(secret.len(), 32);
            assert!(secret.bytes().all(|c| c.is_ascii_alphabetic()));
            let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(secret.as_bytes()));
            assert_eq!(row.client_secret.as_deref(), Some(hash.as_str()));
            assert_eq!(value["user_id"], body(&owner)["user"]["id"]);
            assert_eq!(row.user_id.as_deref(), body(&owner)["user"]["id"].as_str());
        }
    }
    assert_eq!(db.count("oauthClient").await?, 2);
    let token_body = json!({
        "client_name":"Token client", "redirect_uris":[" https://app.fixture.test/callback "],
        "grant_types":[" client_credentials "], "token_endpoint_auth_method":" client_secret_basic ",
        "subject_type":"public", "resources":[], "user_id":"forged", "reference_id":"forged", "client_id":"forged",
    });
    let parsed_metadata = json!({
        "client_name":"Token client", "redirect_uris":["https://app.fixture.test/callback"],
        "grant_types":["client_credentials"], "token_endpoint_auth_method":"client_secret_basic",
        "subject_type":"public", "resources":[],
    });
    let before = db.tables(REGISTRATION_TABLES).await?;
    for mode in [3, 4] {
        for (authorization, status, expected_body, invoked) in [
            (
                "Bearer rejected",
                401,
                Some(
                    json!({"error":"invalid_token","error_description":"Invalid initial access token"}),
                ),
                true,
            ),
            (
                "Bearer",
                400,
                Some(
                    json!({"error":"invalid_request","error_description":"Malformed initial access token Authorization header"}),
                ),
                false,
            ),
            (
                "Bearer first second",
                400,
                Some(
                    json!({"error":"invalid_request","error_description":"Malformed initial access token Authorization header"}),
                ),
                false,
            ),
            (
                "Bearer ordinary-error",
                500,
                Some(
                    json!({"error":"server_error","error_description":"Initial access token validation failed"}),
                ),
                true,
            ),
            (
                "Bearer api-error",
                429,
                Some(
                    json!({"error":"slow_down","error_description":"Operator registration limit"}),
                ),
                true,
            ),
            ("Bearer forbidden", 403, None, true),
            ("Bearer api-empty", 307, None, true),
        ] {
            let calls_before = policy.calls.lock().unwrap().len();
            let denied = auths[mode]
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                        .with_body(&token_body)?,
                    EndpointOptions {
                        headers: Some(
                            [
                                ("authorization".into(), authorization.into()),
                                ("x-registration-caller".into(), "fixture".into()),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            let expected_body = expected_body.map(alibi::utils::json::JsValue::from);
            assert_eq!(denied.body.as_deref(), expected_body.as_ref());
            assert_eq!(denied.body_absent, status == 307);
            if status == 403 {
                assert_eq!(
                    denied.error.error_payload().2,
                    "Operator forbids registration"
                );
            }
            let headers = denied.headers.as_ref().unwrap();
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(headers.get("pragma").map(String::as_str), Some("no-cache"));
            assert!(!headers.contains_key("set-cookie"));
            if matches!(status, 400 | 401) {
                assert_eq!(
                    headers.get("www-authenticate"),
                    Some(&format!(
                        "Bearer error=\"{}\"",
                        if status == 400 {
                            "invalid_request"
                        } else {
                            "invalid_token"
                        }
                    ))
                );
            } else {
                assert!(!headers.contains_key("www-authenticate"));
            }
            if status == 429 {
                assert_eq!(headers.get("retry-after").map(String::as_str), Some("17"));
                assert_eq!(
                    headers.get("x-registration-policy").map(String::as_str),
                    Some("limited")
                );
            }
            if status == 307 {
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://operator.fixture.test/register")
                );
            }
            {
                let calls = policy.calls.lock().unwrap();
                assert_eq!(calls.len(), calls_before + usize::from(invoked));
                if invoked {
                    assert_eq!(
                        calls.last().unwrap(),
                        &json!({"token":authorization.strip_prefix("Bearer ").unwrap(),"authorization":authorization,"caller":"fixture","clientMetadata":parsed_metadata})
                    );
                }
            }
            assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
        }
    }
    // Validation and missing/non-Bearer authentication still precede admission and never call policy.
    for (input, authorization, expected) in [
        (json!({"client_name":42}), Some("Bearer accepted"), 400),
        (token_body.clone(), None, 401),
        (token_body.clone(), Some("Basic ignored"), 401),
    ] {
        let count = policy.calls.lock().unwrap().len();
        let denied = auths[3]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some(
                        authorization
                            .map(|header| ("authorization".into(), header.into()))
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), expected);
        assert_eq!(policy.calls.lock().unwrap().len(), count);
        assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
    }
    for (mode, token, reference) in [
        (3, "accepted", None),
        (4, "reference", Some("registration-reference")),
    ] {
        let authorization = format!("bEaReR {token}");
        let count = policy.calls.lock().unwrap().len();
        let output = auths[mode]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&token_body)?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("authorization".into(), authorization.clone()),
                            ("x-registration-caller".into(), "fixture".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(output.status, 201);
        assert_eq!(policy.calls.lock().unwrap().len(), count + 1);
        assert_eq!(
            policy.calls.lock().unwrap().last().unwrap(),
            &json!({"token":token,"authorization":authorization,"caller":"fixture","clientMetadata":parsed_metadata})
        );
        let value = body(&output);
        assert!(value.get("user_id").is_none());
        assert_eq!(value.get("reference_id").and_then(Value::as_str), reference);
        let row = auths[mode]
            .store()
            .get_oauth_client(value["client_id"].as_str().unwrap())
            .await?
            .unwrap();
        assert!(row.user_id.is_none());
        assert_eq!(
            row.metadata.get("reference_id").and_then(Value::as_str),
            reference
        );
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
            value["client_secret"].as_str().unwrap(),
        ));
        assert_eq!(row.client_secret.as_deref(), Some(hash.as_str()));
        let credential_headers = [(
            "authorization".into(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!(
                    "{}:{}",
                    value["client_id"].as_str().unwrap(),
                    value["client_secret"].as_str().unwrap()
                ))
            ),
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let mut request =
            alibi::AuthRequest::new(HttpMethod::Post, "/api/auth/fixture/authenticate-client");
        request.headers = credential_headers.clone();
        let call = EndpointCall::new(
            &EndpointDefinition {
                name: "registrationCredentials",
                operation_id: "registrationCredentials",
                path: Some("/fixture/authenticate-client".into()),
                method: HttpMethod::Post,
            },
            Some(alibi::utils::json::JsValue::from(
                json!({"client_id":value["client_id"]}),
            )),
            None,
            EndpointOptions {
                headers: Some(credential_headers),
                request: Some(request),
                ..Default::default()
            },
        );
        let authenticated = OAuthProviderPlugin::new()
            .authenticate_client(
                auths[mode].context(),
                &call,
                Some("client_credentials"),
                &Default::default(),
            )
            .await?;
        assert_eq!(authenticated.client_id, row.client_id);
        assert_eq!(
            authenticated
                .client
                .metadata
                .get("reference_id")
                .and_then(Value::as_str),
            reference
        );
    }
    // A real cookie bypasses even an erroring Bearer policy; open registration keeps its fallback.
    for (mode, authorization, cookie) in [
        (3, "Bearer ordinary-error", cookies(&owner)),
        (4, "Basic ignored", String::new()),
    ] {
        let count = policy.calls.lock().unwrap().len();
        let output=auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("authorization".into(),authorization.into()),("cookie".into(),cookie)].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(output.status, 201);
        let value = body(&output);
        let owner_body = body(&owner);
        assert_eq!(
            value.get("user_id"),
            (mode == 3).then_some(&owner_body["user"]["id"])
        );
        assert!(value.get("reference_id").is_none());
        assert_eq!(policy.calls.lock().unwrap().len(), count);
    }
    assert_eq!(db.count("oauthClient").await?, 6);
    Ok(())
}
