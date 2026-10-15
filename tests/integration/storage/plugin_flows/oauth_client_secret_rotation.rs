//! Secret rotation replaces the actual durable hash without changing client identity.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthClientSecretHasher, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(
    oauth_client_secret_rotation_replaces_hash_and_enforces_owner,
    oauth_client_secret_policies_apply_to_creation_rotation_and_authentication
);
postgres_tests!(oauth_client_secret_policies_apply_to_creation_rotation_and_authentication);
#[derive(Debug)]
struct OperatorSecrets {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    empty: bool,
}
impl alibi::plugins::OAuthClientSecretGenerator for OperatorSecrets {
    fn generate(&self) -> alibi::AuthResult<String> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        Ok(if self.empty {
            String::new()
        } else {
            format!("operator-secret-{call}")
        })
    }
}
#[derive(Debug)]
struct CustomSecretHash;
#[async_trait::async_trait]
impl OAuthClientSecretHasher for CustomSecretHash {
    async fn hash(&self, secret: &str) -> alibi::AuthResult<String> {
        Ok(format!(
            "custom:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(secret.as_bytes()))
        ))
    }
}
#[derive(Debug)]
struct CustomSecretVerify;
#[async_trait::async_trait]
impl OAuthClientSecretHasher for CustomSecretVerify {
    async fn hash(&self, secret: &str) -> alibi::AuthResult<String> {
        CustomSecretHash.hash(secret).await
    }
    async fn verify(&self, secret: &str, stored: &str) -> alibi::AuthResult<bool> {
        Ok(CustomSecretHash
            .hash(secret.strip_suffix('!').unwrap_or(secret))
            .await?
            == stored)
    }
}
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
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
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
    let old = auth.store().get_oauth_client(id).await?.unwrap();
    let unrelated = db
        .tables(&["user", "account", "session", "verification", "jwks"])
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
    _ = expected
        .as_object_mut()
        .unwrap()
        .remove("client_credentials_scopes");
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
    assert!(stored.updated_at.expect("client timestamp").timestamp() >= start);
    assert!(
        stored.updated_at.expect("client timestamp").timestamp() <= chrono::Utc::now().timestamp()
    );
    assert_eq!(db.count("oauthClient").await?, 2);
    assert_eq!(
        db.tables(&["user", "account", "session", "verification", "jwks"])
            .await?,
        unrelated
    );
    let public = auth.store().get_oauth_client(public_id).await?.unwrap();
    assert!(public.client_secret.is_none());
    Ok(())
}

async fn oauth_client_secret_policies_apply_to_creation_rotation_and_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (empty, encrypted, prefixed, custom) in [
        (false, false, false, 0),
        (true, false, false, 0),
        (false, true, false, 0),
        (false, false, true, 0),
        (false, true, true, 0),
        (false, false, false, 1),
        (false, false, true, 2),
    ] {
        let prefix = if prefixed { "client_prefix_" } else { "" };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let builder = super::auth_probe::fast_builder::<B>(&connection);
        let builder = if encrypted {
            builder
        } else {
            builder.plugin(JwtPlugin::new())
        };
        let auth = builder
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    disable_jwt_plugin: encrypted,
                    client_secret_prefix: prefixed.then(|| prefix.into()),
                    client_secret_hasher: match custom {
                        1 => Some(Arc::new(CustomSecretHash)),
                        2 => Some(Arc::new(CustomSecretVerify)),
                        _ => None,
                    },
                    client_secret_generator: Some(Arc::new(OperatorSecrets {
                        calls: calls.clone(),
                        empty,
                    })),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = signup(
            &auth,
            &format!("generator-{empty}-{encrypted}-{prefixed}-{custom}@example.test"),
        )
        .await;
        let options = || EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        };
        let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Generated client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"client_secret_post"}))?,options()).await?.into_response()?;
        assert_eq!(created.status, 201);
        let client = body(&created);
        let id = client["client_id"].as_str().unwrap();
        let old_secret = client["client_secret"].as_str().unwrap();
        if empty {
            assert_eq!(old_secret.len(), 32);
            assert!(old_secret.bytes().all(|c| c.is_ascii_alphabetic()));
        } else {
            assert_eq!(old_secret, format!("{prefix}operator-secret-1"));
        }
        let public=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Public client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,options()).await?.into_response()?;
        let public = body(&public);
        assert!(public.get("client_secret").is_none());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        for (target, headers, status) in [
            (id, None, 401),
            (
                public["client_id"].as_str().unwrap(),
                options().headers,
                400,
            ),
        ] {
            let error = auth
                .dispatch_endpoint(
                    OAuthProviderPlugin::rotate_client_secret_endpoint(target)?,
                    EndpointOptions {
                        headers,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.error.status_code(), status);
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let old = auth.store().get_oauth_client(id).await?.unwrap();
        let rotated = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::rotate_client_secret_endpoint(id)?,
                options(),
            )
            .await?
            .into_response()?;
        assert_eq!(rotated.status, 200);
        let rotated = body(&rotated);
        let secret = rotated["client_secret"].as_str().unwrap();
        if empty {
            assert_eq!(secret.len(), 32);
            assert!(secret.bytes().all(|c| c.is_ascii_alphabetic()));
        } else {
            assert_eq!(secret, format!("{prefix}operator-secret-2"));
        }
        assert_ne!(secret, old_secret);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        let stored = auth.store().get_oauth_client(id).await?.unwrap();
        let raw_secret = secret.strip_prefix(prefix).unwrap();
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(raw_secret.as_bytes()));
        let hash = if custom > 0 {
            format!("custom:{hash}")
        } else {
            hash
        };
        if encrypted {
            let protected = stored.client_secret.as_deref().unwrap();
            assert!(!protected.is_empty());
            assert_ne!(protected, secret);
            assert_ne!(protected, hash);
        } else {
            assert_eq!(stored.client_secret.as_deref(), Some(hash.as_str()));
        }
        assert_ne!(stored.client_secret, old.client_secret);
        assert_eq!(stored.id, old.id);
        assert_eq!(stored.user_id, old.user_id);
        assert_eq!(stored.metadata, old.metadata);
        if prefixed {
            for invalid in [raw_secret.to_owned(), format!("WRONG_{raw_secret}")] {
                let error = auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","oauth2Introspect").with_body(&json!({"client_id":id,"client_secret":invalid,"token":"not-issued"}))?,EndpointOptions::default()).await.unwrap_err();
                assert_eq!(error.error.status_code(), 401);
                assert!(
                    error
                        .headers
                        .as_ref()
                        .is_none_or(|headers| { headers.get("www-authenticate").is_none() })
                );
            }
        }
        let alias = format!("{secret}!");
        for (credential, status) in [
            (old_secret, 400),
            (secret, 200),
            (alias.as_str(), if custom == 2 { 200 } else { 400 }),
        ] {
            let output = auth
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(
                        &json!({"client_id":id,"client_secret":credential,"token":"not-issued"}),
                    )?,
                    EndpointOptions::default(),
                )
                .await;
            assert_eq!(
                output
                    .as_ref()
                    .err()
                    .map_or(200, |error| error.error.status_code()),
                status
            );
            if status == 200 {
                let output = output?.into_response()?;
                assert_eq!(output.status, 200);
                assert_eq!(body(&output), json!({"active":false}));
            } else {
                assert_eq!(output.unwrap_err().error.status_code(), status);
            }
        }
    }
    let invalid = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(OAuthProviderPlugin::with_config(
            alibi::plugins::OAuthProviderConfig {
                disable_jwt_plugin: true,
                client_secret_hasher: Some(Arc::new(CustomSecretHash)),
                ..Default::default()
            },
        ))
        .build()
        .await;
    match invalid {
        Err(alibi::AuthError::Config(message)) => assert_eq!(
            message,
            "unable to store hashed secrets because id tokens will be signed with secret"
        ),
        _ => panic!("hashed client secrets must be rejected without the JWT plugin"),
    }
    B::close(connection).await
}
