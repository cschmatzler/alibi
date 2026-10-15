//! Scope policy controls both initial and rotated access authority, not refresh TTL.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams,
    jwt::{JwtExpiration, JwtPlugin},
};
use alibi::store::OAuthTokenKind;
backend_tests!(oauth_scope_expiration_preserves_absolute_numeric_zero_and_relative_bounds);
postgres_tests!(oauth_scope_expiration_preserves_absolute_numeric_zero_and_relative_bounds);
async fn oauth_scope_expiration_preserves_absolute_numeric_zero_and_relative_bounds<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (name, expiration, absolute, ttl) in [
        ("numeric", JwtExpiration::Numeric(1.0), Some(1), 3600),
        ("zero", JwtExpiration::Numeric(0.0), None, 3600),
        (
            "relative",
            JwtExpiration::After(chrono::Duration::seconds(45)),
            None,
            45,
        ),
        (
            "date",
            JwtExpiration::At(chrono::DateTime::from_timestamp(0, 0).unwrap()),
            Some(0),
            3600,
        ),
        (
            "ceiling",
            JwtExpiration::After(chrono::Duration::hours(2)),
            None,
            3600,
        ),
    ] {
        let mut expirations = std::collections::HashMap::from([("email".into(), expiration)]);
        if name == "relative" {
            _ = expirations.insert(
                "profile".into(),
                JwtExpiration::After(chrono::Duration::seconds(90)),
            );
        }
        let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
            scope_expirations: expirations,
            ..Default::default()
        });
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(provider.clone())
            .build()
            .await?;
        let owner = signup(&auth, &format!("scope-{name}@example.test")).await;
        let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Scope expiry","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
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
                name: "scopeExpiryFixture",
                operation_id: "scopeExpiryFixture",
                path: Some("/fixture/scope-expiry".into()),
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
        let issued = provider
            .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
            .await?;
        let row = auth
            .store()
            .get_oauth_token(
                OAuthTokenKind::Access,
                &provider
                    .hash_token(issued["access_token"].as_str().unwrap(), "access_token")
                    .await?,
            )
            .await?
            .unwrap();
        let expected = absolute.unwrap_or(row.created_at.timestamp() + ttl);
        assert_eq!(row.expires_at.timestamp(), expected);
        assert_eq!(issued["expires_at"], expected);
        assert_eq!(issued["expires_in"], expected - row.created_at.timestamp());
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
            2_592_000
        );
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_token_endpoint(
                &json!({"grant_type":"refresh_token","client_id":id,"refresh_token":refresh}),
            )?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let rotated = body(&response);
        let row = auth
            .store()
            .get_oauth_token(
                OAuthTokenKind::Access,
                &provider
                    .hash_token(rotated["access_token"].as_str().unwrap(), "access_token")
                    .await?,
            )
            .await?
            .unwrap();
        let expected = absolute.unwrap_or(row.created_at.timestamp() + ttl);
        assert_eq!(row.expires_at.timestamp(), expected);
        assert_eq!(rotated["expires_at"], expected);
        assert_eq!(rotated["expires_in"], expected - row.created_at.timestamp());
    }
    Ok(())
}
