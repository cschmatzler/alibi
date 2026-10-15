//! Resource policy is rechecked by issuance before minting or consuming authority.
use super::*;
use alibi::AuthSession as _;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin};
use alibi::store::{CreateOAuthClientResource, CreateOAuthResource, OAuthTokenKind};
backend_tests!(oauth_resource_issuance_admission_rejects_without_changing_authority);
postgres_tests!(oauth_resource_issuance_admission_rejects_without_changing_authority);
async fn oauth_resource_issuance_admission_rejects_without_changing_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "resource-mint-native@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Resource mint","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let owner_id = client.user_id.as_deref().unwrap();
    let user = auth.store().get_user_by_id(owner_id).await?.unwrap();
    let session = auth
        .store()
        .get_user_sessions(owner_id)
        .await?
        .into_iter()
        .next()
        .unwrap();
    let uri = |name: &str| format!("https://api.fixture.test/mint/{name}");
    for (name, metadata) in [
        ("disabled", json!({"disabled":true})),
        ("unlinked", json!({})),
        ("empty", json!({"allowedScopes":[]})),
        ("alg-a", json!({"signingAlgorithm":"EdDSA"})),
        ("alg-b", json!({"signingAlgorithm":"ES256"})),
        ("key-a", json!({"signingKeyId":"key-a"})),
        ("key-b", json!({"signingKeyId":"key-b"})),
        (
            "allow-a",
            json!({"allowedScopes":["email","offline_access"]}),
        ),
        ("allow-b", json!({"allowedScopes":["email"]})),
    ] {
        let mut complete = json!({"name":name,"disabled":false,"allowedScopes":null,"accessTokenTtl":null,"refreshTokenTtl":null,"signingAlgorithm":null,"signingKeyId":null,"customClaims":null,"dpopBoundAccessTokensRequired":false,"metadata":null,"policyVersion":1});
        complete
            .as_object_mut()
            .unwrap()
            .extend(metadata.as_object().unwrap().clone());
        _ = auth
            .store()
            .create_oauth_resource(CreateOAuthResource {
                identifier: uri(name),
                metadata: complete,
                created_at: chrono::Utc::now(),
            })
            .await?;
        if name != "unlinked" {
            _ = auth
                .store()
                .create_oauth_client_resource(CreateOAuthClientResource {
                    client_id: id.clone(),
                    resource_id: uri(name),
                    created_at: chrono::Utc::now(),
                })
                .await?;
        }
    }
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "resourceFixture",
            operation_id: "resourceFixture",
            path: Some("/fixture/resource".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let mut params = OAuthTokenIssueParams::new(
        client,
        vec!["email".into(), "profile".into(), "offline_access".into()],
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.session_id = Some(session.id().as_ref().into());
    let seed = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    let before = db
        .tables(&["oauthAccessToken", "oauthRefreshToken"])
        .await?;
    for(resources,code,description)in [
  (vec![uri("missing")],"invalid_target",format!("requested resource {} is not configured",uri("missing"))),
  (vec![uri("disabled")],"invalid_target",format!("requested resource {} is disabled",uri("disabled"))),
  (vec![uri("unlinked")],"invalid_target",format!("client {id} is not linked to resource(s) {}",uri("unlinked"))),
  (vec![uri("empty")],"invalid_scope",format!("none of the requested scopes are allowed for resource {}",uri("empty"))),
  (vec![uri("alg-a"),uri("alg-b")],"invalid_request","multi-resource request has conflicting signingAlgorithm pins; a single JWS signature cannot satisfy multiple algorithms".into()),
  (vec![uri("key-a"),uri("key-b")],"invalid_request","multi-resource request has conflicting signingKeyId pins; a single JWS signature cannot satisfy multiple key ids".into()),
 ]{
  params.resources=Some(resources.clone());
  let denied=provider.issue_tokens(auth.context(),&call,Some("urn:fixture:server"),&params).await.unwrap_err();
  assert_eq!(denied.error.status_code(),400);
  assert_eq!(denied.body.unwrap().to_json_value()?,json!({"error":code,"error_description":description}));
  assert_eq!(db.tables(&["oauthAccessToken","oauthRefreshToken"]).await?,before);
  let denied=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"refresh_token","client_id":id,"refresh_token":seed["refresh_token"],"resource":resources}))?,EndpointOptions::default())).await.unwrap_err();
  assert_eq!(denied.error.status_code(),400);assert_eq!(denied.body.unwrap().to_json_value()?,json!({"error":code,"error_description":description}));
  assert_eq!(db.tables(&["oauthAccessToken","oauthRefreshToken"]).await?,before);
 }
    params.resources = Some(vec![
        "".into(),
        uri("allow-a"),
        uri("allow-b"),
        uri("allow-a"),
    ]);
    let issued = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert_eq!(issued["scope"], "email");
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
    assert_eq!(refresh.metadata["scopes"], json!(["email"]));
    let issuer = format!(
        "{}{}",
        auth.config().base_url.trim_end_matches('/'),
        auth.config().base_path
    );
    let verifier = JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
        claims: alibi::plugins::jwt::JwtClaimsConfig {
            issuer: Some(issuer),
            audience: Some(alibi::plugins::jwt::JwtAudience::One(uri("allow-a"))),
            ..Default::default()
        },
        ..Default::default()
    });
    let claims = verifier
        .verify_jwt(
            issued["access_token"].as_str().unwrap(),
            None,
            None,
            auth.context(),
        )
        .await?
        .unwrap();
    assert_eq!(claims["scope"], "email");
    assert_eq!(claims["aud"], json!([uri("allow-a"), uri("allow-b")]));
    let accepted=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"refresh_token","client_id":id,"refresh_token":seed["refresh_token"],"resource":[uri("allow-a"),uri("allow-b")]}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(accepted.status, 200);
    assert_eq!(body(&accepted)["scope"], "email");
    let rotated = body(&accepted);
    let refresh = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &provider
                .hash_token(rotated["refresh_token"].as_str().unwrap(), "refresh_token")
                .await?,
        )
        .await?
        .unwrap();
    assert_eq!(refresh.metadata["scopes"], json!(["email"]));
    assert_eq!(
        refresh.metadata["resources"],
        json!([uri("allow-a"), uri("allow-b")])
    );
    let claims = verifier
        .verify_jwt(
            rotated["access_token"].as_str().unwrap(),
            None,
            None,
            auth.context(),
        )
        .await?
        .unwrap();
    assert_eq!(claims["scope"], "email");
    let before = db
        .tables(&["oauthAccessToken", "oauthRefreshToken"])
        .await?;
    let denied=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"refresh_token","client_id":id,"refresh_token":rotated["refresh_token"],"resource":[uri("unlinked")]}))?,EndpointOptions::default())).await.unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_target","error_description":"requested resource invalid"})
    );
    assert_eq!(
        db.tables(&["oauthAccessToken", "oauthRefreshToken"])
            .await?,
        before
    );
    Ok(())
}
