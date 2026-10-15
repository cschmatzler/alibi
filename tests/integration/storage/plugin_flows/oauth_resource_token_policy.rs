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
use alibi::store::{CreateOAuthClientResource, CreateOAuthResource, OAuthTokenKind};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
backend_tests!(oauth_resource_token_policy_controls_lifetimes_claims_and_signing);
postgres_tests!(oauth_resource_token_policy_controls_lifetimes_claims_and_signing);
async fn oauth_resource_token_policy_controls_lifetimes_claims_and_signing<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
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
