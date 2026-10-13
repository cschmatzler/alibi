//! Public client display fields are available to authenticated non-owners only.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_public_client_read_projects_display_fields_for_non_owner);
async fn oauth_public_client_read_projects_display_fields_for_non_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-display-owner@example.test").await;
    let other = signup(&auth, "oauth-display-other@example.test").await;
    let created = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::create_oauth_client_endpoint(
                &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                    client_name: Some("Display client".into()),
                    client_uri: Some("https://app.fixture.test".into()),
                    logo_uri: Some("https://app.fixture.test/logo.png".into()),
                    contacts: Some(vec!["support@app.fixture.test".into()]),
                    tos_uri: Some("https://app.fixture.test/terms".into()),
                    policy_uri: Some("https://app.fixture.test/privacy".into()),
                    redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
                    scope: Some("openid email".into()),
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
    let client_id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let expected = json!({"client_id":client_id,"client_name":"Display client","client_uri":"https://app.fixture.test","logo_uri":"https://app.fixture.test/logo.png","contacts":["support@app.fixture.test"],"tos_uri":"https://app.fixture.test/terms","policy_uri":"https://app.fixture.test/privacy","redirect_uris":[]});
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
        (client_id.as_str(), cookies(&other), 200),
        (client_id.as_str(), cookies(&owner), 200),
        (client_id.as_str(), String::new(), 401),
        ("missing-client", cookies(&other), 404),
    ] {
        let result = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClientPublic")
                    .with_query(&json!({"client_id":id}))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await;
        if status == 200 {
            let response = result?.into_response()?;
            assert_eq!(response.status, 200);
            assert_eq!(body(&response), expected);
        } else {
            assert_eq!(result.unwrap_err().error.status_code(), status);
        }
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
    Ok(())
}
