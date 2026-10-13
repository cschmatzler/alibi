//! Consent listing isolates the current user and preserves durable grant rows.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_consent_list_returns_only_current_users_durable_grants);
async fn oauth_consent_list_returns_only_current_users_durable_grants<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "consent-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email profile","state":"consent-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let producer = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize").with_query(&query)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&producer)["url"].as_str().unwrap())?;
    let signed = url.query().unwrap();
    let start = chrono::Utc::now().timestamp_millis();
    let accepted = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::oauth2_consent_endpoint(true, Some("email"), Some(signed))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                request: Some(request("/oauth2/consent", None, "")),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(accepted.status, 200);
    let other = signup(&auth, "consent-list-other@example.test").await;
    let before = db
        .tables(&[
            "users",
            "accounts",
            "sessions",
            "verifications",
            "jwks",
            "oauth_client",
            "oauth_consent",
        ])
        .await?;
    for (cookie, count, status) in [
        (cookies(&owner), 1, 200),
        (cookies(&other), 0, 200),
        (String::new(), 0, 401),
    ] {
        let result = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::get_oauth_consents_endpoint(),
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await;
        if status == 200 {
            let response = match result {
                Ok(output) => output.into_response()?,
                Err(error) => error.error.to_auth_response(),
            };
            assert_eq!(
                response.status, 200,
                "owned consent listing must be registered"
            );
            let value = body(&response);
            let rows = value.as_array().unwrap();
            assert_eq!(rows.len(), count);
            if count == 1 {
                let row = &rows[0];
                assert_eq!(row["clientId"], id);
                assert_eq!(row["userId"], body(&owner)["user"]["id"]);
                assert_eq!(row["scopes"], json!(["email"]));
                assert_eq!(row["resources"], Value::Null);
                assert_eq!(row["referenceId"], Value::Null);
                assert_eq!(row["requestedUserInfoClaims"], json!([]));
                assert_eq!(row["createdAt"], row["updatedAt"]);
                let time =
                    chrono::DateTime::parse_from_rfc3339(row["createdAt"].as_str().unwrap())?
                        .timestamp_millis();
                assert!(time >= start / 1000 * 1000);
                assert!(time <= chrono::Utc::now().timestamp_millis());
                assert_eq!(row.as_object().unwrap().len(), 9);
            }
        } else {
            assert_eq!(result.unwrap_err().error.status_code(), status);
        }
        assert_eq!(
            before,
            db.tables(&[
                "users",
                "accounts",
                "sessions",
                "verifications",
                "jwks",
                "oauth_client",
                "oauth_consent"
            ])
            .await?
        );
    }
    Ok(())
}
