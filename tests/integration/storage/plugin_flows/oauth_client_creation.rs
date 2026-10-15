//! Managed OAuth client creation owns persistence and the one-time plaintext secret.
use super::*;
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(
    oauth_client_creation_persists_owned_metadata_and_protected_secret,
    oauth_client_id_generator_controls_persisted_ids_and_preserves_empty_output,
    oauth_client_uri_hosts_follow_reference_public_routability
);
postgres_tests!(
    oauth_client_id_generator_controls_persisted_ids_and_preserves_empty_output,
    oauth_client_uri_hosts_follow_reference_public_routability
);
#[derive(Debug)]
struct OperatorClientIds {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    empty: bool,
}
impl alibi::plugins::OAuthClientIdGenerator for OperatorClientIds {
    fn generate(&self) -> alibi::AuthResult<String> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        Ok(if self.empty {
            String::new()
        } else {
            format!("operator-client-{call}")
        })
    }
}
async fn oauth_client_creation_persists_owned_metadata_and_protected_secret<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-client-owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
        ])
        .await?;
    for (input, cookie, status, code) in [
        (
            json!({"client_name":42}),
            cookies(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            401,
            "UNAUTHORIZED",
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"forbidden"}),
            cookies(&owner),
            400,
            "invalid_scope",
        ),
        (
            json!({"client_name":"No redirect"}),
            cookies(&owner),
            400,
            "invalid_redirect_uri",
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[{"kty":"OKP","crv":"Ed448","x":"unsupported-curve","alg":"EdDSA"}]}}),
            cookies(&owner),
            400,
            "invalid_client_metadata",
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback#fragment"]}),
            cookies(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"redirect_uris":["http://app.fixture.test/callback"]}),
            cookies(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"redirect_uris":["http://127.1:3000/callback"],"application_type":"native","token_endpoint_auth_method":"none"}),
            cookies(&owner),
            400,
            "invalid_redirect_uri",
        ),
    ] {
        let error = auth
            .dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new(
                    "oauth-provider",
                    "createOAuthClient",
                )
                .with_body(&input)?,
                alibi::endpoint::EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        let standard = error.error.error_payload().1;
        let protocol = error
            .body
            .as_ref()
            .and_then(|value| value.get("error"))
            .and_then(alibi::utils::json::JsValue::as_str);
        assert_eq!(standard.as_deref().or(protocol), Some(code));
        assert_eq!(
            db.tables(&[
                "user",
                "account",
                "session",
                "verification",
                "jwks",
                "oauthClient"
            ])
            .await?,
            before
        );
    }
    let creation_start = chrono::Utc::now().timestamp();
    let output=auth.dispatch_endpoint(
        OAuthProviderPlugin::create_oauth_client_endpoint(&alibi::plugins::oauth_provider::CreateOAuthClientInput{
            client_name:Some("Actual client".into()),redirect_uris:Some(vec!["https://app.fixture.test/callback".into()]),scope:Some("openid email".into()),..Default::default()
        })?
            .with_body(&json!({"client_name":"Actual client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email","user_id":"forged-owner","client_id":"forged-client","client_secret":"forged-secret"}))?,
        alibi::endpoint::EndpointOptions {headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()},
    ).await?.into_response()?;
    assert_eq!(output.status, 201);
    assert_eq!(
        output.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        output.headers.get("pragma").map(String::as_str),
        Some("no-cache")
    );
    let response = body(&output);
    assert!(response["client_id_issued_at"].as_i64().unwrap() >= creation_start);
    assert!(response["client_id_issued_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp());
    let client_id = response["client_id"].as_str().unwrap();
    let secret = response["client_secret"].as_str().unwrap();
    assert_eq!(client_id.len(), 32);
    assert!(client_id.bytes().all(|byte| byte.is_ascii_alphabetic()));
    assert_eq!(secret.len(), 32);
    assert_eq!(response["user_id"], owner_id);
    assert_eq!(response["client_name"], "Actual client");
    assert_eq!(
        response["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(response["grant_types"], json!(["authorization_code"]));
    let stored = auth.store().get_oauth_client(client_id).await?.unwrap();
    assert_eq!(stored.user_id.as_deref(), Some(owner_id.as_str()));
    assert_eq!(stored.metadata["client_name"], "Actual client");
    assert!(stored.metadata.get("client_secret").is_none());
    assert!(stored.metadata.get("user_id").is_none());
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(secret.as_bytes()));
    assert_eq!(stored.client_secret.as_deref(), Some(expected.as_str()));
    assert_eq!(db.count("oauthClient").await?, 1);
    let public_start = chrono::Utc::now().timestamp();
    let public = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::create_oauth_client_endpoint(
                &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                    client_name: Some("Native public client".into()),
                    redirect_uris: Some(vec!["com.fixture.app:/callback".into()]),
                    token_endpoint_auth_method: Some("none".into()),
                    application_type: Some("native".into()),
                    ..Default::default()
                },
            )?,
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(public.status, 201);
    let public = body(&public);
    assert!(public["client_id_issued_at"].as_i64().unwrap() >= public_start);
    assert!(public["client_id_issued_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp());
    assert!(public.get("client_secret").is_none());
    assert!(public.get("client_secret_expires_at").is_none());
    let stored = auth
        .store()
        .get_oauth_client(public["client_id"].as_str().unwrap())
        .await?
        .unwrap();
    assert!(stored.client_secret.is_none());
    assert_eq!(stored.user_id.as_deref(), Some(owner_id.as_str()));
    assert_eq!(
        stored.metadata["redirect_uris"],
        json!(["com.fixture.app:/callback"])
    );
    assert_eq!(db.count("oauthClient").await?, 2);
    B::close(connection).await
}

async fn oauth_client_id_generator_controls_persisted_ids_and_preserves_empty_output<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::endpoint::{EndpointOptions, ServerEndpoint};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for empty in [false, true] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    client_id_generator: Some(Arc::new(OperatorClientIds {
                        calls: calls.clone(),
                        empty,
                    })),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = signup(&auth, &format!("id-generator-{empty}@example.test")).await;
        let options = || EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        };
        let input = json!({"client_name":"Generated ID client","redirect_uris":["https://app.fixture.test/callback"],"client_id":"forged"});
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient")
                    .with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 401);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let response = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient")
                    .with_body(&input)?,
                options(),
            )
            .await?
            .into_response()?;
        assert_eq!(response.status, 201);
        let client = body(&response);
        let expected = if empty { "" } else { "operator-client-1" };
        assert_eq!(client["client_id"], expected);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let stored = auth.store().get_oauth_client(expected).await?.unwrap();
        assert_eq!(stored.client_id, expected);
        assert_eq!(
            stored.user_id.as_deref(),
            body(&owner)["user"]["id"].as_str()
        );
        assert_eq!(
            stored.client_secret.as_deref(),
            Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(
                        client["client_secret"].as_str().unwrap().as_bytes()
                    ))
                    .as_str()
            )
        );
        let read = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClient")
                    .with_query(&json!({"client_id":expected}))?,
                options(),
            )
            .await?
            .into_response()?;
        assert_eq!(read.status, 200);
        assert_eq!(body(&read)["client_id"], expected);
        assert!(body(&read).get("client_secret").is_none());
        if !empty {
            let public=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,options()).await?.into_response()?;
            assert_eq!(public.status, 201);
            assert_eq!(body(&public)["client_id"], "operator-client-2");
            assert!(body(&public).get("client_secret").is_none());
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }
    B::close(connection).await
}

async fn oauth_client_uri_hosts_follow_reference_public_routability<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
    let hosts = [
        "100.64.0.1",
        "198.18.0.1",
        "192.0.0.9",
        "192.88.99.1",
        "240.0.0.1",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "[::ffff:127.0.0.1]",
        "[64:ff9b::a00:1]",
        "[2002:a00:1::]",
        "[3fff::1]",
        "[5f00::1]",
        "8.8.8.8",
        "[2001:4860:4860::8888]",
        "keys.fixture.test",
        "external",
    ];
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin("https://*");
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "uri-host-owner@example.test").await;
    for (index, host) in hosts.iter().enumerate() {
        for field in ["jwks_uri", "backchannel_logout_uri"] {
            let uri = format!("https://{host}/keys");
            let mut input = json!({"client_name":"URI host","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":if field=="jwks_uri"{"private_key_jwt"}else{"none"}});
            input[field] = json!(uri);
            let before = db
                .tables(&[
                    "oauthClient",
                    "oauthClientAssertion",
                    "oauthAccessToken",
                    "oauthRefreshToken",
                ])
                .await?;
            let outcome = Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "createOAuthClient")
                        .with_body(&input)?,
                    EndpointOptions {
                        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                        ..Default::default()
                    },
                ),
            )
            .await;
            let response = match outcome {
                Ok(output) => output.into_response()?,
                Err(error) => {
                    let mut response = EndpointResponse::error(error.error);
                    if let Some(body) = error.body {
                        response = response.with_error_body(*body);
                    }
                    response.to_response()?
                }
            };
            let allowed = index >= 12;
            assert_eq!(
                response.status,
                if allowed { 201 } else { 400 },
                "{field}: {host}: {}",
                body(&response)
            );
            if allowed {
                let client = body(&response);
                assert_eq!(client[field], uri);
                assert!(client.get("client_secret").is_none());
                let row = auth
                    .store()
                    .get_oauth_client(client["client_id"].as_str().unwrap())
                    .await?
                    .unwrap();
                assert_eq!(row.metadata[field], uri);
            } else {
                assert_eq!(
                    body(&response),
                    json!({"error":"invalid_client_metadata","error_description":format!("{field} must not point to a private or reserved address")})
                );
                assert_eq!(
                    db.tables(&[
                        "oauthClient",
                        "oauthClientAssertion",
                        "oauthAccessToken",
                        "oauthRefreshToken"
                    ])
                    .await?,
                    before
                );
            }
        }
    }
    B::close(connection).await
}
