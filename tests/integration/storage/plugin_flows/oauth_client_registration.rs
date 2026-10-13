//! Dynamic registration gates anonymous admission and persists real client credentials.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(oauth_dynamic_registration_enforces_policy_and_persists_clients);
async fn oauth_dynamic_registration_enforces_policy_and_persists_clients<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut auths = Vec::new();
    for mode in 0..3 {
        auths.push(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: mode != 0,
                    allow_unauthenticated_client_registration: mode == 2,
                    ..Default::default()
                }))
                .build()
                .await?,
        );
    }
    let owner = signup(&auths[0], "oauth-registration-owner@example.test").await;
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
    for (mode, input, cookie, status) in [
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
    for (mode, public, cookie) in [(1, false, cookies(&owner)), (2, true, String::new())] {
        let start = chrono::Utc::now().timestamp();
        let output=auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"client_name":if public{"Anonymous client"}else{"Owned dynamic client"},"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":if public{"none"}else{"client_secret_basic"},"user_id":"forged","client_id":"forged"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie)].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(output.status, 201);
        assert_eq!(
            output.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        let value = body(&output);
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
    assert_eq!(db.count("oauth_client").await?, 2);
    Ok(())
}
