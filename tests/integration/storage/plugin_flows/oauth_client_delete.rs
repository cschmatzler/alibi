//! Deletion removes only the authenticated owner's durable client.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_client_deletion_enforces_owner_and_removes_only_selected_client);
async fn oauth_client_deletion_enforces_owner_and_removes_only_selected_client<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-delete-owner@example.test").await;
    let other = signup(&auth, "oauth-delete-other@example.test").await;
    let mut ids = Vec::new();
    for response in [&owner, &owner, &other] {
        let created = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::create_oauth_client_endpoint(
                    &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                        redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
                        ..Default::default()
                    },
                )?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        ids.push(body(&created)["client_id"].as_str().unwrap().to_owned());
    }
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
        (ids[0].as_str(), cookies(&other), 401),
        (ids[0].as_str(), String::new(), 401),
        ("missing-client", cookies(&owner), 404),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "deleteOAuthClient")
                    .with_body(&json!({"client_id":id}))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
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
    let unrelated = db
        .tables(&["users", "accounts", "sessions", "verifications", "jwks"])
        .await?;
    let response = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::delete_oauth_client_endpoint(&ids[0])?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?;
    response.decode()?;
    let response = response.into_response()?;
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());
    assert!(auth.store().get_oauth_client(&ids[0]).await?.is_none());
    for id in &ids[1..] {
        assert!(auth.store().get_oauth_client(id).await?.is_some());
    }
    assert_eq!(db.count("oauth_client").await?, 2);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications", "jwks"])
            .await?,
        unrelated
    );
    let replay = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "deleteOAuthClient")
                .with_body(&json!({"client_id":ids[0]}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 404);
    assert_eq!(db.count("oauth_client").await?, 2);
    Ok(())
}
