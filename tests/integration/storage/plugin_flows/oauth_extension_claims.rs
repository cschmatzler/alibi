use super::*;
use alibi::AuthUser as _;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[path = "../../../fixtures/oauth/extension-claims.rs"]
mod extension_claims;

backend_tests!(
    oauth_opaque_validation_rederives_live_access_claims,
    oauth_extension_claims_receive_live_trusted_issuance_context
);
postgres_tests!(
    oauth_opaque_validation_rederives_live_access_claims,
    oauth_extension_claims_receive_live_trusted_issuance_context
);

async fn oauth_opaque_validation_rederives_live_access_claims<B: Backend>(db: Db) -> TestResult {
    use alibi::store::{CreateOAuthClientResource, CreateOAuthResource, OAuthTokenKind};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let live = std::sync::Arc::new(extension_claims::LiveAccessClaims::default());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        disable_jwt_plugin: true,
        extensions: extension_claims::extensions_with_live(Some(live.clone())),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "opaque-claims@example.test").await;
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
            "client_name":"Live claims", "redirect_uris":["https://app.fixture.test/callback"],
            "scope":"email profile", "token_endpoint_auth_method":"none"
        }))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 201);
    let client_id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider
        .get_client(auth.context(), &client_id)
        .await?
        .unwrap();
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let user = auth.store().get_user_by_id(&user_id).await?.unwrap();
    let resource = "https://api.fixture.test/live-claims";
    let _ = auth.store().create_oauth_resource(CreateOAuthResource {
        identifier: resource.into(), created_at: chrono::Utc::now(),
        metadata: json!({
            "name":"Live claims","disabled":false,"allowedScopes":null,
            "accessTokenTtl":null,"refreshTokenTtl":null,"signingAlgorithm":null,"signingKeyId":null,
            "customClaims":{"resource_wins":"resource-before","cnf":{"jkt":"forged"}},
            "dpopBoundAccessTokensRequired":false,"metadata":null,"policyVersion":1
        }),
    }).await?;
    let _ = auth
        .store()
        .create_oauth_client_resource(CreateOAuthClientResource {
            client_id: client_id.clone(),
            resource_id: resource.into(),
            created_at: chrono::Utc::now(),
        })
        .await?;
    let mut params = OAuthTokenIssueParams::new(client, vec!["email".into(), "profile".into()]);
    params.user = Some(auth.context().trusted_user_view(&user));
    params.reference_id = Some("live-reference".into());
    params.resources = Some(vec![resource.into()]);
    params.access_token_claims = Some(json!({"per_request":"issuance-only"}));
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "nativeClaims",
            operation_id: "nativeClaims",
            path: None,
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let issued = provider
        .issue_tokens(auth.context(), &call, Some("urn:native:claims"), &params)
        .await?;
    let token = issued["access_token"].as_str().unwrap();
    assert_eq!(token.len(), 32);
    assert!(token.bytes().all(|byte| byte.is_ascii_alphabetic()));
    assert!(
        live.calls.lock().unwrap().is_empty(),
        "opaque issuance does not collect access claims"
    );
    for value in ["before", "after"] {
        *live.value.lock().unwrap() = value.into();
        if value == "after" {
            let _ = auth.store().update_oauth_resource(resource, json!({
                "name":"Live claims","disabled":true,"allowedScopes":["openid"],
                "accessTokenTtl":null,"refreshTokenTtl":null,"signingAlgorithm":null,"signingKeyId":null,
                "dpopBoundAccessTokensRequired":false,"metadata":null,"policyVersion":1,"customClaims":{
                    "resource_wins":"resource-after","cnf":{"jkt":"forged"},"auth_time":1,"jti":"forged"
                }
            }), chrono::Utc::now()).await?;
        }
        let payload = provider
            .validate_access_token(auth.context(), token, None)
            .await?;
        assert_eq!(payload["live_value"], value);
        assert_eq!(payload["resource_wins"], format!("resource-{value}"));
        assert_eq!(payload["extension_owner"], "first");
        assert_eq!(payload["per_request"], "first");
        assert_eq!(payload["active"], true);
        assert_eq!(payload["sub"], user_id);
        assert_eq!(payload["client_id"], client_id);
        assert_eq!(payload["azp"], client_id);
        assert_eq!(payload["scope"], "email profile");
        assert_eq!(payload["aud"], resource);
        assert_eq!(payload["iss"], format!("{ORIGIN}/api/auth"));
        assert_eq!(payload["token_type"], "Bearer");
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
            3600
        );
        for key in [
            "sid",
            "cnf",
            "jti",
            "auth_time",
            "acr",
            "amr",
            "constructor",
        ] {
            assert!(payload.get(key).is_none(), "reserved claim {key} leaked");
        }
    }
    let calls = live.calls.lock().unwrap().clone();
    assert_eq!(calls, ["first", "second", "first", "second"].map(|extension| json!({
        "extension":extension,"grant":null,"sessionId":null,"userId":user_id,"clientId":client_id,
        "referenceId":"live-reference","scopes":["email","profile"],"resources":[resource],"metadata":null,
    })));
    let hash = provider.hash_token(token, "access_token").await?;
    let row = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Access, &hash)
        .await?
        .unwrap();
    auth.store()
        .mark_oauth_token_revoked(OAuthTokenKind::Access, &row.id, chrono::Utc::now())
        .await?;
    *live.value.lock().unwrap() = "must-not-leak".into();
    assert_eq!(
        provider
            .validate_access_token(auth.context(), token, None)
            .await?,
        json!({"active":false})
    );
    assert_eq!(*live.calls.lock().unwrap(), calls);
    Ok(())
}

async fn oauth_extension_claims_receive_live_trusted_issuance_context<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        extensions: extension_claims::extensions(),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "extension-claims@example.test").await;
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
            "client_name":"Claims","redirect_uris":["https://app.fixture.test/callback"],
            "scope":"openid profile email","token_endpoint_auth_method":"none",
            "metadata":{"tenant":"application"}
        }))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 201);
    let client = provider
        .get_client(
            auth.context(),
            body(&created)["client_id"].as_str().unwrap(),
        )
        .await?
        .unwrap();
    let user = auth
        .store()
        .get_user_by_id(body(&owner)["user"]["id"].as_str().unwrap())
        .await?
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(
        client,
        vec!["openid".into(), "profile".into(), "email".into()],
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.reference_id = Some("native-reference".into());
    params.access_token_claims = Some(json!({"per_request":"native"}));
    params.id_token_claims = Some(json!({"per_request":"native"}));
    params.resources = Some(vec![format!("{ORIGIN}/api/auth/oauth2/userinfo")]);
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "nativeClaims",
            operation_id: "nativeClaims",
            path: Some("/native/claims".into()),
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions {
            headers: Some(
                [("x-claims-caller".into(), "native-caller".into())]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        },
    );
    let tokens = provider
        .issue_tokens(auth.context(), &call, Some("urn:native:claims"), &params)
        .await?;
    for key in ["access_token", "id_token"] {
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(tokens[key].as_str().unwrap().split('.').nth(1).unwrap())?,
        )?;
        assert_eq!(claims["extension_owner"], "first");
        assert_eq!(claims["per_request"], "native");
        assert_eq!(claims["extension_first"]["caller"], "native-caller");
        assert_eq!(claims["extension_second"]["caller"], "native-caller");
        assert_eq!(claims["extension_first"]["userId"], user.id().as_ref());
        assert_eq!(claims["extension_first"]["grant"], "urn:native:claims");
        assert_eq!(
            claims["extension_first"]["metadata"],
            json!({"tenant":"application"})
        );
        assert_eq!(claims["sub"], user.id().as_ref());
        assert!(claims.get("constructor").is_none());
    }
    Ok(())
}
