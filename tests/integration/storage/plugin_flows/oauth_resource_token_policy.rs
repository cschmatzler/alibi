//! Resource overrides affect signed authority and retained refresh lifetimes.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams,
    jwt::{
        JwtAlgorithm, JwtAudience, JwtClaimsConfig, JwtExpiration, JwtKeyPairConfig, JwtPlugin,
        JwtPluginConfig,
    },
};
use alibi::store::OAuthClientStore as _;
use alibi::store::{CreateOAuthClientResource, CreateOAuthResource, OAuthTokenKind};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[path = "../../../fixtures/oauth/resource-identifiers.rs"]
mod resource_identifiers;
backend_tests!(oauth_resource_token_policy_controls_lifetimes_claims_and_signing);
postgres_tests!(oauth_resource_token_policy_controls_lifetimes_claims_and_signing);
async fn oauth_resource_token_policy_controls_lifetimes_claims_and_signing<B: Backend>(
    db: Db,
) -> TestResult {
    deferred_resource_lifecycle::<B>(&db).await?;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    configured_resource_lifecycle::<B>(&connection).await?;
    let jwt = JwtPlugin::with_config(JwtPluginConfig {
        additional_key_pairs: vec![JwtKeyPairConfig {
            algorithm: JwtAlgorithm::Es256,
            modulus_length: None,
        }],
        ..Default::default()
    });
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(jwt.clone())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "resource-policy-native@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Resource policy","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
    _ = jwt
        .sign_jwt(
            serde_json::Map::new(),
            &Default::default(),
            None,
            auth.context(),
        )
        .await?;
    let uri = |name: &str| format!("https://api.fixture.test/policy/{name}");
    for (name, access_ttl, refresh_ttl) in [("a", 120, 1800), ("b", 60, 900)] {
        _=auth.store().create_oauth_resource(CreateOAuthResource{identifier:uri(name),created_at:chrono::Utc::now(),metadata:json!({"name":name,"disabled":false,"allowedScopes":null,"accessTokenTtl":access_ttl,"refreshTokenTtl":refresh_ttl,"signingAlgorithm":"ES256","signingKeyId":null,"customClaims":{"role":format!("from-{name}"),name:true,"sub":"injected","iss":"injected","scope":"injected","cnf":{"jkt":"injected"},"auth_time":123},"dpopBoundAccessTokensRequired":false,"metadata":null,"policyVersion":1})}).await?;
        _ = auth
            .store()
            .create_oauth_client_resource(CreateOAuthClientResource {
                client_id: id.clone(),
                resource_id: uri(name),
                created_at: chrono::Utc::now(),
            })
            .await?;
    }
    let issuer = format!(
        "{}{}",
        auth.config().base_url.trim_end_matches('/'),
        auth.config().base_path
    );
    let verifier = JwtPlugin::with_config(JwtPluginConfig {
        claims: JwtClaimsConfig {
            issuer: Some(issuer.clone()),
            audience: Some(JwtAudience::One(uri("a"))),
            ..Default::default()
        },
        ..Default::default()
    });
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "resourcePolicyFixture",
            operation_id: "resourcePolicyFixture",
            path: Some("/fixture/resource-policy".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    for name in ["user", "machine", "reverse", "scope-cap", "key-pin"] {
        let with_user = name != "machine";
        let resources = if name == "reverse" {
            vec![uri("b"), uri("a")]
        } else {
            vec![uri("a"), uri("b")]
        };
        let mut params = OAuthTokenIssueParams::new(
            client.clone(),
            if with_user {
                vec!["openid".into(), "email".into(), "offline_access".into()]
            } else {
                vec!["email".into()]
            },
        );
        params.resources = Some(resources.clone());
        params.access_token_claims =
            Some(json!({"role":"per-request","requestOnly":true,"cnf":{"jkt":"injected"}}));
        if with_user {
            params.user = Some(auth.context().trusted_user_view(&user));
        }
        let mint = if name == "scope-cap" {
            OAuthProviderPlugin::with_config(OAuthProviderConfig {
                scope_expirations: std::collections::HashMap::from([(
                    "email".into(),
                    JwtExpiration::After(chrono::Duration::seconds(45)),
                )]),
                ..Default::default()
            })
        } else {
            provider.clone()
        };
        let issued = mint
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await?;
        let ttl = if name == "scope-cap" { 45 } else { 60 };
        assert_eq!(issued["expires_in"], ttl);
        let access = issued["access_token"].as_str().unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(access.split('.').next().unwrap())?)?;
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "at+jwt");
        let claims = verifier
            .verify_jwt(access, None, None, auth.context())
            .await?
            .unwrap();
        assert_eq!(
            claims["role"],
            if name == "reverse" {
                "from-a"
            } else {
                "from-b"
            }
        );
        assert_eq!(claims["requestOnly"], true);
        assert!(claims.get("cnf").is_none());
        assert!(claims.get("auth_time").is_none());
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            ttl
        );
        if with_user {
            let refresh = auth
                .store()
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &provider
                        .hash_token(issued["refresh_token"].as_str().unwrap(), "refresh_token")
                        .await?,
                )
                .await?
                .unwrap();
            assert_eq!((refresh.expires_at - refresh.created_at).num_seconds(), 900);
            let response=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"refresh_token","client_id":id,"refresh_token":issued["refresh_token"]}))?,EndpointOptions::default())).await?.into_response()?;
            assert_eq!(response.status, 200);
            let next = body(&response);
            assert_eq!(next["expires_in"], 60);
            let claims = verifier
                .verify_jwt(
                    next["access_token"].as_str().unwrap(),
                    None,
                    None,
                    auth.context(),
                )
                .await?
                .unwrap();
            assert_eq!(
                claims["role"],
                if name == "reverse" {
                    "from-a"
                } else {
                    "from-b"
                }
            );
            assert!(claims.get("requestOnly").is_none());
            let row = auth
                .store()
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &provider
                        .hash_token(next["refresh_token"].as_str().unwrap(), "refresh_token")
                        .await?,
                )
                .await?
                .unwrap();
            assert_eq!((row.expires_at - row.created_at).num_seconds(), 900);
        }
        if name == "scope-cap" {
            let keys = auth.store().list_jwks().await?;
            let key = keys
                .iter()
                .find(|key| key.alg.as_deref() == Some("ES256"))
                .unwrap();
            for identifier in resources {
                let row = auth.store().get_oauth_resource(&identifier).await?.unwrap();
                let mut metadata = row.metadata;
                metadata["signingAlgorithm"] = Value::Null;
                metadata["signingKeyId"] = json!(key.id);
                _ = auth
                    .store()
                    .update_oauth_resource(&identifier, metadata, chrono::Utc::now())
                    .await?;
            }
        }
    }
    Ok(())
}

async fn configured_resource_lifecycle<B: Backend>(connection: &B::Connection) -> TestResult {
    use alibi::plugins::OAuthResourceSeedMode;
    for mode in [
        OAuthResourceSeedMode::InsertOnly,
        OAuthResourceSeedMode::Merge,
        OAuthResourceSeedMode::Overwrite,
    ] {
        let identifier = format!("https://api.fixture.test/seed/{mode:?}");
        let config = |resources| OAuthProviderConfig {
            resources,
            resource_seed_mode: mode,
            enforce_per_client_resources: false,
            ..Default::default()
        };
        let extra = [
            format!("urn:fixture:{mode:?}"),
            format!("http://api.fixture.test/{mode:?}"),
            format!("javascript:seed-{mode:?}"),
            format!("{identifier}/empty-fragment#"),
        ];
        let mut resources = vec![
            json!({"identifier":identifier,"name":"Configured","accessTokenTtl":120,"allowedScopes":["email"],"customClaims":{"configured":true},"signingAlgorithm":"HS256","unknown":"ignored"}),
        ];
        let duplicate = format!("{identifier}/duplicate");
        resources.extend([
            json!({"identifier":duplicate,"name":"First","accessTokenTtl":10,"refreshTokenTtl":20,"signingAlgorithm":"RS256","signingKeyId":"configured-key","allowedScopes":["profile"],"customClaims":{"first":true},"dpopBoundAccessTokensRequired":true,"disabled":true,"metadata":{"first":true},"policyVersion":99}),
            json!({"identifier":duplicate,"name":"Last","allowedScopes":[],"customClaims":null,"metadata":null}),
        ]);
        resources.extend(extra.iter().map(|id| json!(id)));
        resources.extend([json!("relative"), json!(format!("{identifier}#fragment"))]);
        let provider = OAuthProviderPlugin::with_config(config(resources));
        let auth = super::auth_probe::fast_builder::<B>(connection)
            .plugin(JwtPlugin::new())
            .plugin(provider)
            .build()
            .await?;
        let initial = auth
            .store()
            .get_oauth_resource(&identifier)
            .await?
            .expect("provider init must persist configured resources");
        assert_eq!(initial.metadata["name"], "Configured");
        assert_eq!(initial.metadata["signingAlgorithm"], Value::Null);
        assert!(initial.metadata.get("unknown").is_none());
        let duplicate_row = auth.store().get_oauth_resource(&duplicate).await?.unwrap();
        assert_eq!(
            duplicate_row.metadata,
            json!({
                "name":if mode==OAuthResourceSeedMode::InsertOnly {"First"}else{"Last"},
                "accessTokenTtl":if mode==OAuthResourceSeedMode::Overwrite {Value::Null}else{json!(10)},
                "refreshTokenTtl":if mode==OAuthResourceSeedMode::Overwrite {Value::Null}else{json!(20)},
                "signingAlgorithm":if mode==OAuthResourceSeedMode::Overwrite {Value::Null}else{json!("RS256")},
                "signingKeyId":if mode==OAuthResourceSeedMode::Overwrite {Value::Null}else{json!("configured-key")},
                "allowedScopes":if mode==OAuthResourceSeedMode::InsertOnly {json!(["profile"])}else{json!([])},
                "customClaims":if mode==OAuthResourceSeedMode::InsertOnly {json!({"first":true})}else{Value::Null},
                "metadata":if mode==OAuthResourceSeedMode::InsertOnly {json!({"first":true})}else{Value::Null},
                "disabled":mode!=OAuthResourceSeedMode::Overwrite,"dpopBoundAccessTokensRequired":mode!=OAuthResourceSeedMode::Overwrite,"policyVersion":1,
            })
        );
        for id in extra {
            let row = auth.store().get_oauth_resource(&id).await?.unwrap();
            assert_eq!(row.metadata["name"], id);
            assert_eq!(row.metadata["policyVersion"], 1);
        }
        assert!(auth.store().get_oauth_resource("relative").await?.is_none());
        assert!(
            auth.store()
                .get_oauth_resource(&format!("{identifier}#fragment"))
                .await?
                .is_none()
        );
        let admin = json!({"name":"Admin","accessTokenTtl":45,"refreshTokenTtl":90,"allowedScopes":["profile"],"customClaims":{"admin":true},"signingAlgorithm":"EdDSA","signingKeyId":null,"dpopBoundAccessTokensRequired":false,"disabled":false,"policyVersion":7,"metadata":{"admin":true}});
        _ = auth
            .store()
            .update_oauth_resource(&identifier, admin.clone(), chrono::Utc::now())
            .await?;
        let provider = OAuthProviderPlugin::with_config(config(vec![
            json!({"identifier":identifier,"name":"Restart","accessTokenTtl":120,"allowedScopes":["email"],"customClaims":null,"metadata":null,"signingAlgorithm":"HS256","disabled":false}),
        ]));
        let auth = super::auth_probe::fast_builder::<B>(connection)
            .plugin(JwtPlugin::new())
            .plugin(provider.clone())
            .build()
            .await?;
        let restarted = auth.store().get_oauth_resource(&identifier).await?.unwrap();
        assert_eq!(
            auth.store()
                .get_oauth_resource(&duplicate)
                .await?
                .unwrap()
                .metadata,
            duplicate_row.metadata,
            "removing a configured input must not delete its persisted row"
        );
        assert_eq!(restarted.id, initial.id);
        assert_eq!(restarted.created_at, initial.created_at);
        let mut expected = admin;
        if mode != OAuthResourceSeedMode::InsertOnly {
            expected["name"] = json!("Restart");
            expected["accessTokenTtl"] = json!(120);
            expected["allowedScopes"] = json!(["email"]);
            expected["customClaims"] = Value::Null;
            expected["metadata"] = Value::Null;
        }
        if mode == OAuthResourceSeedMode::Overwrite {
            expected["refreshTokenTtl"] = Value::Null;
            expected["signingAlgorithm"] = Value::Null;
            expected["policyVersion"] = json!(1);
        }
        assert_eq!(restarted.metadata, expected);
        let mut changed = restarted.metadata;
        changed["disabled"] = json!(true);
        changed["accessTokenTtl"] = json!(33);
        _ = auth
            .store()
            .update_oauth_resource(&identifier, changed, chrono::Utc::now())
            .await?;
        let owner = signup(&auth, &format!("seed-{mode:?}@example.test")).await;
        let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Seed policy","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
        let client = provider
            .get_client(
                auth.context(),
                body(&created)["client_id"].as_str().unwrap(),
            )
            .await?
            .unwrap();
        let call = EndpointCall::new(
            &EndpointDefinition {
                name: "resourceSeed",
                operation_id: "resourceSeed",
                path: None,
                method: alibi::HttpMethod::Post,
            },
            None,
            None,
            EndpointOptions::default(),
        );
        let mut params = OAuthTokenIssueParams::new(client, vec!["email".into(), "profile".into()]);
        params.resources = Some(vec![identifier.clone()]);
        let first = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await;
        if mode == OAuthResourceSeedMode::InsertOnly {
            assert_eq!(
                first
                    .unwrap_err()
                    .body
                    .unwrap()
                    .get("error")
                    .unwrap()
                    .as_str(),
                Some("invalid_target")
            );
        } else {
            assert_eq!(first?["expires_in"], 120);
        }
        let mut row = auth.store().get_oauth_resource(&identifier).await?.unwrap();
        row.metadata["disabled"] = json!(true);
        _ = auth
            .store()
            .update_oauth_resource(&identifier, row.metadata.clone(), chrono::Utc::now())
            .await?;
        let denied = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await
            .unwrap_err();
        assert_eq!(
            denied.body.unwrap().get("error").unwrap().as_str(),
            Some("invalid_target")
        );
        row.metadata["disabled"] = json!(false);
        _ = auth
            .store()
            .update_oauth_resource(&identifier, row.metadata, chrono::Utc::now())
            .await?;
        let issued = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await?;
        assert_eq!(
            issued["scope"],
            if mode == OAuthResourceSeedMode::InsertOnly {
                "profile"
            } else {
                "email"
            }
        );
        assert_eq!(
            issued["expires_in"],
            if mode == OAuthResourceSeedMode::InsertOnly {
                33
            } else {
                120
            }
        );
    }
    Ok(())
}

async fn deferred_resource_lifecycle<B: Backend>(db: &Db) -> TestResult {
    use std::sync::atomic::Ordering;
    let connection = B::connect(&db.url, None).await?;
    let identifiers = Arc::new(resource_identifiers::Identifiers::default());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        resources: vec![json!("local-resource")],
        identifier_validator: Some(identifiers.clone()),
        enforce_per_client_resources: false,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let missing = auth
        .store()
        .get_oauth_resource("local-resource")
        .await
        .unwrap_err();
    // Real native adapter errors retain the underlying SQLite/Postgres text.
    assert!(
        missing.to_string().contains("no such table")
            || missing.to_string().contains("does not exist"),
        "{missing}"
    );
    let (_, store) = db.migrated::<B>(SECRET).await?;
    assert!(store.get_oauth_resource("local-resource").await?.is_none());
    let owner = signup(&auth, "seed-deferred@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Deferred seed","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let client = provider
        .get_client(
            auth.context(),
            body(&created)["client_id"].as_str().unwrap(),
        )
        .await?
        .unwrap();
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "resourceSeed",
            operation_id: "resourceSeed",
            path: None,
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let mut params = OAuthTokenIssueParams::new(client, vec!["email".into()]);
    params.resources = Some(vec!["local-resource".into()]);
    identifiers.fail_next.store(true, Ordering::SeqCst);
    let issue =
        || provider.issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params);
    let denied = issue().await.unwrap_err();
    assert!(alibi::endpoint::is_endpoint_api_error(&denied.error));
    assert_eq!(denied.error.status_code(), 403);
    assert!(store.get_oauth_resource("local-resource").await?.is_none());
    let (a, b, c) = tokio::join!(issue(), issue(), issue());
    for issued in [a?, b?, c?] {
        assert_eq!(issued["scope"], "email");
    }
    assert_eq!(identifiers.calls.load(Ordering::SeqCst), 3);
    let row = store.get_oauth_resource("local-resource").await?.unwrap();
    assert_eq!(row.metadata["name"], "local-resource");
    let peer = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    _ = provider
        .issue_tokens(peer.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert_eq!(
        identifiers.calls.load(Ordering::SeqCst),
        5,
        "a plugin clone must not suppress another initialized store's lazy seed"
    );
    Ok(())
}
