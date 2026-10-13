//! Resource reads decode URI parameters and preserve raw malformed escapes.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_resource_read_decodes_identifier_and_preserves_catalog_policy);
async fn oauth_resource_read_decodes_identifier_and_preserves_catalog_policy<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "resource-read-owner@example.test").await;
    let other = signup(&auth, "resource-read-other@example.test").await;
    let mut expected = Vec::new();
    for input in [
        json!({"identifier":"https://api.fixture.test/read+a","name":"Read A","allowedScopes":["email"]}),
        json!({"identifier":"urn:fixture:%61%ZZ","disabled":true}),
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
    for (identifier, cookie, index) in [
        (
            "https://api.fixture.test/read+a".to_owned(),
            cookies(&owner),
            0,
        ),
        (
            url::form_urlencoded::byte_serialize(b"https://api.fixture.test/read+a")
                .collect::<String>(),
            cookies(&other),
            0,
        ),
        ("urn:fixture:%61%ZZ".to_owned(), cookies(&owner), 1),
    ] {
        let result = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_get_oauth_resource_endpoint(&identifier)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await;
        let response = match result {
            Ok(output) => output.into_response()?,
            Err(error) => error.error.to_auth_response(),
        };
        assert_eq!(
            response.status, 200,
            "single resource lookup must be registered"
        );
        assert_eq!(body(&response), expected[index]);
    }
    for (identifier, cookie, status, description) in [
        (
            "https%3A%2F%2Fapi.fixture.test%2Fmissing",
            cookies(&owner),
            404,
            "resource https://api.fixture.test/missing not found",
        ),
        ("https://api.fixture.test/read+a", String::new(), 401, ""),
        ("%E0%A4", cookies(&owner), 404, "resource %E0%A4 not found"),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_get_oauth_resource_endpoint(identifier)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if status == 404 {
            assert_eq!(
                denied
                    .body
                    .as_ref()
                    .unwrap()
                    .get("error_description")
                    .unwrap()
                    .as_str(),
                Some(description)
            );
        }
    }
    let http = Box::pin(auth.handle_request(request(
        "/admin/oauth2/resources/https%3A%2F%2Fapi.fixture.test%2Fread%2Ba",
        None,
        &cookies(&owner),
    )))
    .await?;
    assert_eq!(http.status, 404);
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
