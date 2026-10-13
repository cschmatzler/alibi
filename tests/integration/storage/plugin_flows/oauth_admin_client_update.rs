//! Server-only administrative patches retain ownership and replace opaque metadata.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_admin_update_replaces_operator_metadata_and_preserves_secret);
async fn oauth_admin_update_replaces_operator_metadata_and_preserves_secret<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-admin-update-owner@example.test").await;
    let other = signup(&auth, "oauth-admin-update-other@example.test").await;
    let created=auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"client_name":"Before operator update","redirect_uris":["https://app.fixture.test/callback"],"skip_consent":true,"enable_end_session":true,"metadata":{"old_label":"old"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let original = body(&created);
    let id = original["client_id"].as_str().unwrap();
    let old = auth.store().get_oauth_client(id).await?.unwrap();
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
    for (id, patch, cookie, status) in [
        (id, json!({"skip_consent":"yes"}), cookies(&owner), 400),
        (id, json!({"client_name":"foreign"}), cookies(&other), 401),
        (id, json!({"client_name":"guest"}), String::new(), 401),
        (
            id,
            json!({"client_credentials_scopes":["email"]}),
            cookies(&owner),
            400,
        ),
        ("missing-client", json!({}), cookies(&owner), 404),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthClient")
                    .with_body(&json!({"client_id":id,"update":patch}))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        }
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
    let unchanged=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminUpdateOAuthClient").with_body(&json!({"client_id":id,"update":{"user_id":"forged","token_endpoint_auth_method":"none"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let mut expected = original.clone();
    _ = expected.as_object_mut().unwrap().remove("client_secret");
    assert_eq!(body(&unchanged), expected);
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
    let patch = json!({"client_name":"After operator update","skip_consent":false,"enable_end_session":false,"dpop_bound_access_tokens":true,"client_secret_expires_at":"1893456000","metadata":{"new_label":"new","client_id":"forged","client_secret":"forged","user_id":"forged"}});
    let start = chrono::Utc::now().timestamp();
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminUpdateOAuthClient")
                .with_body(&json!({"client_id":id,"update":patch}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(output.status, 200);
    expected["client_name"] = json!("After operator update");
    expected["skip_consent"] = json!(false);
    expected["enable_end_session"] = json!(false);
    expected["dpop_bound_access_tokens"] = json!(true);
    expected["client_secret_expires_at"] = json!(0);
    _ = expected.as_object_mut().unwrap().remove("old_label");
    expected["new_label"] = json!("new");
    assert_eq!(body(&output), expected);
    let stored = auth.store().get_oauth_client(id).await?.unwrap();
    assert_eq!(stored.id, old.id);
    assert_eq!(stored.user_id, old.user_id);
    assert_eq!(stored.client_secret, old.client_secret);
    assert_eq!(stored.created_at, old.created_at);
    assert!(stored.updated_at.expect("client timestamp").timestamp() >= start);
    assert!(
        stored.updated_at.expect("client timestamp").timestamp() <= chrono::Utc::now().timestamp()
    );
    assert!(stored.metadata.get("old_label").is_none());
    assert_eq!(stored.metadata["new_label"], "new");
    assert_eq!(stored.metadata["skip_consent"], false);
    let mut physical = request(
        "/admin/oauth2/update-client",
        Some(json!({"client_id":id,"update":patch})),
        &cookies(&owner),
    );
    physical.method = HttpMethod::Patch;
    let denied = auth.handle_request(physical).await?;
    assert_eq!(denied.status, 404);
    assert_eq!(db.count("oauthClient").await?, 1);
    Ok(())
}
