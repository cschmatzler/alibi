//! Client updates change owned metadata without changing credentials or identity.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_client_update_persists_owned_metadata_and_preserves_credentials);
async fn oauth_client_update_persists_owned_metadata_and_preserves_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-update-owner@example.test").await;
    let other = signup(&auth, "oauth-update-other@example.test").await;
    let created = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::create_oauth_client_endpoint(
                &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                    client_name: Some("Before update".into()),
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
        (id, json!({"client_name":42}), cookies(&owner), 400),
        (id, json!({"scope":"forbidden"}), cookies(&owner), 400),
        (
            id,
            json!({"redirect_uris":["https://app.fixture.test/callback#fragment"]}),
            cookies(&owner),
            400,
        ),
        (
            id,
            json!({"client_name":"Foreign edit"}),
            cookies(&other),
            401,
        ),
        (id, json!({"client_name":"Guest edit"}), String::new(), 401),
        ("missing-client", json!({}), cookies(&owner), 404),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthClient")
                    .with_body(&json!({"client_id":id,"update":patch}))?,
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
    let unchanged=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","updateOAuthClient").with_body(&json!({"client_id":id,"update":{"user_id":"forged","token_endpoint_auth_method":"none"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let mut expected = original.clone();
    _ = expected.as_object_mut().unwrap().remove("client_secret");
    _ = expected
        .as_object_mut()
        .unwrap()
        .remove("client_credentials_scopes");
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
    let unrelated = db
        .tables(&["user", "account", "session", "verification", "jwks"])
        .await?;
    let start = chrono::Utc::now().timestamp();
    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","updateOAuthClient").with_body(&json!({"client_id":id,"update":{"client_name":"After update","scope":"email","redirect_uris":["\u{feff} HTTPS://NEW.fixture.test:443/a/../callback \u{a0}"],"post_logout_redirect_uris":["\u{2028}https://new.fixture.test/logout\u{feff}"],"backchannel_logout_uri":" \u{feff}https://new.fixture.test/backchannel\t ","client_uri":" https://new.fixture.test/about ","contacts":["support@fixture.test"],"client_secret":"forged","user_id":"forged"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    assert_eq!(output.status, 200);
    expected["client_name"] = json!("After update");
    expected["scope"] = json!("email");
    expected["redirect_uris"] = json!(["HTTPS://NEW.fixture.test:443/a/../callback"]);
    expected["post_logout_redirect_uris"] = json!(["https://new.fixture.test/logout"]);
    expected["backchannel_logout_uri"] = json!("https://new.fixture.test/backchannel");
    expected["client_uri"] = json!(" https://new.fixture.test/about ");
    expected["contacts"] = json!(["support@fixture.test"]);
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
    assert_eq!(stored.metadata["client_name"], "After update");
    assert_eq!(stored.metadata["scope"], "email");
    assert_eq!(
        stored.metadata["redirect_uris"],
        json!(["HTTPS://NEW.fixture.test:443/a/../callback"])
    );
    for field in [
        "post_logout_redirect_uris",
        "backchannel_logout_uri",
        "client_uri",
    ] {
        assert_eq!(stored.metadata[field], expected[field]);
    }
    assert_eq!(db.count("oauthClient").await?, 1);
    assert_eq!(
        db.tables(&["user", "account", "session", "verification", "jwks"])
            .await?,
        unrelated
    );
    Ok(())
}
