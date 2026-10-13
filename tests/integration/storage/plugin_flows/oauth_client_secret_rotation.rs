//! Secret rotation replaces the actual durable hash without changing client identity.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(oauth_client_secret_rotation_replaces_hash_and_enforces_owner);
async fn oauth_client_secret_rotation_replaces_hash_and_enforces_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-rotation-owner@example.test").await;
    let other = signup(&auth, "oauth-rotation-other@example.test").await;
    let mut clients = Vec::new();
    for public in [false, true] {
        let r = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::create_oauth_client_endpoint(
                    &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                        client_name: Some("Rotation client".into()),
                        redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
                        token_endpoint_auth_method: public.then(|| "none".into()),
                        ..Default::default()
                    },
                )?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        clients.push(body(&r));
    }
    let id = clients[0]["client_id"].as_str().unwrap();
    let public_id = clients[1]["client_id"].as_str().unwrap();
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
    for (id, cookie, status) in [
        (id, cookies(&other), 401),
        (id, String::new(), 401),
        (public_id, cookies(&owner), 400),
        ("missing-client", cookies(&owner), 404),
    ] {
        let e = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "rotateClientSecret")
                    .with_body(&json!({"client_id":id}))?,
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
    let old = auth.store().get_oauth_client(id).await?.unwrap();
    let unrelated = db
        .tables(&["users", "accounts", "sessions", "verifications", "jwks"])
        .await?;
    let start = chrono::Utc::now().timestamp();
    let r = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "rotateClientSecret")
                .with_body(&json!({"client_id":id}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        r.headers.get("pragma").map(String::as_str),
        Some("no-cache")
    );
    let rotated = body(&r);
    let secret = rotated["client_secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32);
    assert!(secret.bytes().all(|c| c.is_ascii_alphabetic()));
    assert_ne!(rotated["client_secret"], clients[0]["client_secret"]);
    let mut expected = clients[0].clone();
    expected["client_secret"] = json!(secret);
    assert_eq!(rotated, expected);
    let stored = auth.store().get_oauth_client(id).await?.unwrap();
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(secret.as_bytes()));
    assert_eq!(stored.client_secret.as_deref(), Some(hash.as_str()));
    assert_ne!(stored.client_secret, old.client_secret);
    assert_eq!(stored.id, old.id);
    assert_eq!(stored.user_id, old.user_id);
    assert_eq!(stored.metadata, old.metadata);
    assert_eq!(stored.created_at, old.created_at);
    assert!(stored.updated_at.timestamp() >= start);
    assert!(stored.updated_at.timestamp() <= chrono::Utc::now().timestamp());
    assert_eq!(db.count("oauth_client").await?, 2);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications", "jwks"])
            .await?,
        unrelated
    );
    let public = auth.store().get_oauth_client(public_id).await?.unwrap();
    assert!(public.client_secret.is_none());
    Ok(())
}
