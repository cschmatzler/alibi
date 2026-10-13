//! Owned client reads redact credentials and enforce session ownership.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_client_read_redacts_secret_and_enforces_owner);
async fn oauth_client_read_redacts_secret_and_enforces_owner<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-reader-owner@example.test").await;
    let other = signup(&auth, "oauth-reader-other@example.test").await;
    let created = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::create_oauth_client_endpoint(
                &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                    client_name: Some("Owned reader client".into()),
                    redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
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
    let mut expected = body(&created);
    let client_id = expected["client_id"].as_str().unwrap().to_owned();
    _ = expected.as_object_mut().unwrap().remove("client_secret");
    _ = expected
        .as_object_mut()
        .unwrap()
        .remove("client_credentials_scopes");
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
    for (id, cookie, status) in [
        (client_id.as_str(), cookies(&owner), 200),
        (client_id.as_str(), cookies(&other), 401),
        (client_id.as_str(), String::new(), 401),
        ("missing-client", cookies(&owner), 404),
        ("", cookies(&owner), 404),
    ] {
        let result = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "getOAuthClient")
                    .with_query(&json!({"client_id":id,"user_id":body(&owner)["user"]["id"]}))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await;
        if status == 200 {
            let response = result?.into_response()?;
            assert_eq!(response.status, 200);
            assert_eq!(body(&response), expected);
            assert!(body(&response).get("client_secret").is_none());
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.error.status_code(), status);
            if id == client_id && !cookie.is_empty() {
                assert!(error.body_absent);
                assert_eq!(
                    error
                        .headers
                        .as_ref()
                        .unwrap()
                        .get("content-type")
                        .map(String::as_str),
                    Some("application/json")
                );
            }
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
    Ok(())
}
