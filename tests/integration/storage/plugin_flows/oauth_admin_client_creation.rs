//! Administrative creation persists operator fields through its server-only API.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
backend_tests!(oauth_admin_creation_persists_operator_fields_without_metadata_forgery);
async fn oauth_admin_creation_persists_operator_fields_without_metadata_forgery<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-admin-client-owner@example.test").await;
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
    for (input, cookie, status) in [
        (json!({"client_name":42}), cookies(&owner), 400),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            401,
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"],"client_credentials_scopes":["email"]}),
            cookies(&owner),
            400,
        ),
        (
            json!({"grant_types":["client_credentials"],"client_credentials_scopes":["email"]}),
            cookies(&owner),
            400,
        ),
        (
            json!({"redirect_uris":["https://app.fixture.test/callback"],"skip_consent":"yes"}),
            cookies(&owner),
            400,
        ),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthClient")
                    .with_body(&input)?,
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
            assert_eq!(
                error
                    .headers
                    .as_ref()
                    .unwrap()
                    .get("cache-control")
                    .map(String::as_str),
                Some("no-store")
            );
            assert_eq!(
                error
                    .headers
                    .as_ref()
                    .unwrap()
                    .get("pragma")
                    .map(String::as_str),
                Some("no-cache")
            );
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
    let input = json!({"client_name":"Operator client","redirect_uris":["https://app.fixture.test/callback"],"skip_consent":true,"enable_end_session":true,"require_pkce":false,"subject_type":"public","client_secret_expires_at":123,"client_credentials_scopes":[],"user_id":"forged","metadata":{"custom_label":"billing","client_id":"forged","client_secret":"forged","client_name":"forged","userId":"forged","resources":["forged"],"client_credentials_scopes":["forged"]}});
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "adminCreateOAuthClient")
                .with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(output.status, 201);
    assert_eq!(
        output.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    let value = body(&output);
    assert_eq!(value["user_id"], body(&owner)["user"]["id"]);
    assert_eq!(value["client_name"], "Operator client");
    assert_eq!(value["custom_label"], "billing");
    assert_eq!(value["skip_consent"], true);
    assert_eq!(value["enable_end_session"], true);
    assert_eq!(value["require_pkce"], false);
    assert_eq!(value["subject_type"], "public");
    assert_eq!(value["client_credentials_scopes"], json!([]));
    assert_eq!(value["client_secret_expires_at"], 0);
    assert!(value.get("userId").is_none());
    assert!(value.get("resources").is_none());
    let id = value["client_id"].as_str().unwrap();
    let secret = value["client_secret"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|c| c.is_ascii_alphabetic()));
    assert_eq!(secret.len(), 32);
    assert!(secret.bytes().all(|c| c.is_ascii_alphabetic()));
    let row = auth.store().get_oauth_client(id).await?.unwrap();
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(secret.as_bytes()));
    assert_eq!(row.client_secret.as_deref(), Some(hash.as_str()));
    assert_eq!(row.metadata["skip_consent"], true);
    assert_eq!(row.metadata["custom_label"], "billing");
    assert!(row.metadata.get("client_secret").is_none());
    let read = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::get_oauth_client_endpoint(id)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    let mut expected = value.clone();
    _ = expected.as_object_mut().unwrap().remove("client_secret");
    _ = expected
        .as_object_mut()
        .unwrap()
        .remove("client_credentials_scopes");
    assert_eq!(body(&read), expected);
    let response = auth
        .handle_request(request(
            "/admin/oauth2/create-client",
            Some(input),
            &cookies(&owner),
        ))
        .await?;
    assert_eq!(response.status, 404);
    assert_eq!(db.count("oauthClient").await?, 1);
    Ok(())
}
