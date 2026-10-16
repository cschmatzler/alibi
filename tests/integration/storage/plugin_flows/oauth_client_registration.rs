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
backend_tests!(oauth_dynamic_registration_enforces_policy_and_persists_clients);
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
