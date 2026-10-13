//! Global resource administration reads include disabled policy and do not mutate storage.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_list_returns_global_policy_for_authenticated_server_callers);
async fn oauth_resource_list_returns_global_policy_for_authenticated_server_callers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "resource-list-owner@example.test").await;
    let result = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_list_oauth_resources_endpoint(),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200, "resource listing must be registered");
    assert_eq!(body(&response), json!([]));
    let mut expected = Vec::new();
    for input in [
        json!({"identifier":"https://api.fixture.test/list-a","name":"Enabled","allowedScopes":["email"]}),
        json!({"identifier":"urn:fixture:list-b","disabled":true}),
    ] {
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_create_oauth_resource_endpoint(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        expected.push(body(&response));
    }
    let other = signup(&auth, "resource-list-other@example.test").await;
    let before = db
        .tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
            "oauth_resource",
            "oauth_client_resource",
        ])
        .await?;
    for cookie in [cookies(&owner), cookies(&other)] {
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_list_oauth_resources_endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        assert_eq!(body(&response), json!(expected));
    }
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_list_oauth_resources_endpoint(),
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert!(denied.body_absent);
    let response =
        Box::pin(auth.handle_request(request("/admin/oauth2/resources", None, &cookies(&owner))))
            .await?;
    assert_eq!(response.status, 404);
    assert_eq!(
        before,
        db.tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
            "oauth_resource",
            "oauth_client_resource"
        ])
        .await?
    );
    Ok(())
}
