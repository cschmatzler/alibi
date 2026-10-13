//! Client lists isolate durable records by their authenticated owner.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_client_list_isolates_owner_and_redacts_secrets);
async fn oauth_client_list_isolates_owner_and_redacts_secrets<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-list-owner@example.test").await;
    let other = signup(&auth, "oauth-list-other@example.test").await;
    let list = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClients"),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(list.status, 200);
    assert_eq!(body(&list), json!([]));
    let mut expected = Vec::new();
    let mut other_expected = Vec::new();
    for (name, response) in [
        ("Owner one", &owner),
        ("Foreign", &other),
        ("Owner two", &owner),
    ] {
        let created = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::create_oauth_client_endpoint(
                    &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                        client_name: Some(name.into()),
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
        let mut value = body(&created);
        _ = value.as_object_mut().unwrap().remove("client_secret");
        _ = value
            .as_object_mut()
            .unwrap()
            .remove("client_credentials_scopes");
        if name == "Foreign" {
            other_expected.push(value);
        } else {
            expected.push(value);
        }
    }
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
    for (cookie, expected) in [
        (cookies(&owner), expected),
        (cookies(&other), other_expected),
    ] {
        let output = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClients"),
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(output.status, 200);
        assert_eq!(body(&output), json!(expected));
    }
    let error = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClients"),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 401);
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
    Ok(())
}
