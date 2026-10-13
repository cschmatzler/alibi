//! Managed OAuth client creation owns persistence and the one-time plaintext secret.
use super::*;
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(oauth_client_creation_persists_owned_metadata_and_protected_secret);
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
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
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
                "users",
                "accounts",
                "sessions",
                "verifications",
                "jwks",
                "oauth_client"
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
    assert_eq!(db.count("oauth_client").await?, 1);
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
    assert_eq!(db.count("oauth_client").await?, 2);
    B::close(connection).await
}
