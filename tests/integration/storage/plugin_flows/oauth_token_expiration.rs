//! Configured lifetimes are carried by persisted and rotating authority.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
use alibi::store::OAuthTokenKind;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
backend_tests!(oauth_configured_token_lifetimes_survive_refresh_rotation);
postgres_tests!(oauth_configured_token_lifetimes_survive_refresh_rotation);
async fn oauth_configured_token_lifetimes_survive_refresh_rotation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        access_token_expires_in: 120.0,
        m2m_access_token_expires_in: 30.0,
        id_token_expires_in: 600.0,
        refresh_token_expires_in: 900.0,
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "expiry-native@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Expiry","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "expiryFixture",
            operation_id: "expiryFixture",
            path: Some("/fixture/expiry".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    for with_user in [false, true] {
        let scopes = if with_user {
            vec!["openid".into(), "email".into(), "offline_access".into()]
        } else {
            vec!["email".into()]
        };
        let mut params = OAuthTokenIssueParams::new(client.clone(), scopes);
        if with_user {
            params.user = Some(auth.context().trusted_user_view(&user));
        }
        let issued = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await?;
        assert_eq!(issued["expires_in"], if with_user { 120 } else { 30 });
        let access = auth
            .store()
            .get_oauth_token(
                OAuthTokenKind::Access,
                &provider
                    .hash_token(issued["access_token"].as_str().unwrap(), "access_token")
                    .await?,
            )
            .await?
            .unwrap();
        assert_eq!(
            (access.expires_at - access.created_at).num_seconds(),
            if with_user { 120 } else { 30 }
        );
        if with_user {
            let parts = issued["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .collect::<Vec<_>>();
            let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
            assert_eq!(
                claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
                600
            );
            let refresh = issued["refresh_token"].as_str().unwrap();
            let retained = auth
                .store()
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &provider.hash_token(refresh, "refresh_token").await?,
                )
                .await?
                .unwrap();
            assert_eq!(
                (retained.expires_at - retained.created_at).num_seconds(),
                900
            );
            let rotated = Box::pin(auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_token_endpoint(
                    &json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh}),
                )?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(rotated.status, 200);
            let response = body(&rotated);
            assert_eq!(response["expires_in"], 120);
            let next = auth
                .store()
                .get_oauth_token(
                    OAuthTokenKind::Refresh,
                    &provider
                        .hash_token(response["refresh_token"].as_str().unwrap(), "refresh_token")
                        .await?,
                )
                .await?
                .unwrap();
            assert_eq!((next.expires_at - next.created_at).num_seconds(), 900);
        }
    }
    Ok(())
}
