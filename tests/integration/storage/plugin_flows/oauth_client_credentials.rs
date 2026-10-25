//! Machine grants create genuine access authority without a user or session.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
#[derive(Debug)]
struct MachinePrivileges;
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientPrivileges for MachinePrivileges {
    async fn allowed(
        &self,
        ctx: &alibi::plugins::OAuthClientPrivilegeContext,
    ) -> alibi::AuthResult<bool> {
        Ok(ctx.action == "configure-client-credentials-scopes"
            && ctx.headers.get("x-machine-operator").map(String::as_str) == Some("grant")
            && ctx
                .user
                .get("email")
                .and_then(Value::as_str)
                .is_some_and(|email| email.contains("machine-owner"))
            && ctx.session.get("userId") == ctx.user.get("id"))
    }
}
backend_tests!(oauth_client_credentials_issues_unbound_scope_limited_access);
async fn oauth_client_credentials_issues_unbound_scope_limited_access<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderConfig {
        scopes: vec!["api:read".into(), "api:write".into()],
        client_credentials_scope_privileges: Some(Arc::new(MachinePrivileges)),
        ..Default::default()
    };
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(provider))
        .build()
        .await?;
    let owner = signup(&auth, "machine-owner@example.test").await;
    let denied=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Machine client","scope":"api:read api:write","token_endpoint_auth_method":"client_secret_post","grant_types":["client_credentials"],"client_credentials_scopes":["api:read","api:write"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await.unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert!(denied.body_absent);
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Machine client","scope":"api:read api:write","token_endpoint_auth_method":"client_secret_post","grant_types":["client_credentials"],"client_credentials_scopes":["api:read","api:write"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner)),("x-machine-operator".into(),"grant".into())].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    let id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    for (input, error, description) in [
        (
            json!({"grant_type":"client_credentials"}),
            "invalid_request",
            "Missing required client_id",
        ),
        (
            json!({"grant_type":"client_credentials","client_id":"missing","client_secret":secret}),
            "invalid_client",
            "client not found",
        ),
        (
            json!({"grant_type":"client_credentials","client_id":id,"client_secret":"wrong"}),
            "invalid_client",
            "invalid client_secret",
        ),
        (
            json!({"grant_type":"client_credentials","client_id":id,"client_secret":secret,"scope":"openid"}),
            "invalid_scope",
            "The following scopes are invalid: openid",
        ),
        (
            json!({"grant_type":"client_credentials","client_id":id,"client_secret":secret,"resource":"https://api.fixture.test/missing-machine"}),
            "invalid_target",
            "requested resource https://api.fixture.test/missing-machine is not configured",
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
    }
    for scope in [None, Some("api:read")] {
        let mut input =
            json!({"grant_type":"client_credentials","client_id":id,"client_secret":secret});
        if let Some(scope) = scope {
            input["scope"] = json!(scope);
        }
        let issued = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/token", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(issued.status, 200);
        assert_eq!(
            issued.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        let token = body(&issued);
        assert_eq!(token["scope"], scope.unwrap_or("api:read api:write"));
        assert_eq!(token["expires_in"], 3600);
        assert_eq!(token["token_type"], "Bearer");
        assert!(token.get("refresh_token").is_none());
        assert!(token.get("id_token").is_none());
        let access = token["access_token"].as_str().unwrap();
        assert_eq!(access.len(), 32);
        assert!(access.bytes().all(|value| value.is_ascii_alphabetic()));
        let hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(access));
        let row = auth
            .store()
            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
            .await?
            .unwrap();
        assert_eq!(row.token, hash);
        assert_eq!(row.client_id, id);
        assert_eq!(row.user_id, None);
        assert_eq!(row.session_id, None);
        assert_eq!(row.authorization_code_id, None);
        assert_eq!(
            row.metadata["scopes"],
            json!(
                scope
                    .unwrap_or("api:read api:write")
                    .split(' ')
                    .collect::<Vec<_>>()
            )
        );
        assert_eq!(
            row.expires_at.timestamp() - row.created_at.timestamp(),
            3600
        );
        let input = json!({"client_id":id,"client_secret":secret,"token":access,"token_type_hint":"access_token"});
        let observed = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
            EndpointOptions {
                request: Some(request("/oauth2/introspect", Some(input), "")),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(observed.status, 200);
        let claims = body(&observed);
        assert_eq!(claims["active"], true);
        assert_eq!(claims["scope"], token["scope"]);
        assert!(claims.get("sub").is_none());
        assert!(claims.get("sid").is_none());
    }
    Ok(())
}
