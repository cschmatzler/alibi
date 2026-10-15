//! Trusted refresh snapshots rotate by row ID without protocol grant admission.
use super::*;
use alibi::AuthSession as _;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin};
use alibi::store::OAuthTokenKind;
backend_tests!(oauth_trusted_refresh_issuance_uses_row_identity_and_caller_authorization);
postgres_tests!(oauth_trusted_refresh_issuance_uses_row_identity_and_caller_authorization);
async fn oauth_trusted_refresh_issuance_uses_row_identity_and_caller_authorization<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::new();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "trusted-refresh-native@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Trusted refresh","redirect_uris":["https://app.fixture.test/callback"],"scope":"email offline_access","token_endpoint_auth_method":"none","grant_types":["authorization_code"]}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth
        .store()
        .get_user_by_id(client.user_id.as_deref().unwrap())
        .await?
        .unwrap();
    let session = auth
        .store()
        .get_user_sessions(client.user_id.as_deref().unwrap())
        .await?
        .into_iter()
        .next()
        .unwrap();
    let userinfo = format!(
        "{}{}/oauth2/userinfo",
        auth.config().base_url.trim_end_matches('/'),
        auth.config().base_path
    );
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "trustedRefreshFixture",
            operation_id: "trustedRefreshFixture",
            path: Some("/fixture/trusted-refresh".into()),
            method: alibi::HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    let mut seed_params = OAuthTokenIssueParams::new(
        client.clone(),
        vec!["email".into(), "offline_access".into()],
    );
    seed_params.user = Some(auth.context().trusted_user_view(&user));
    seed_params.session_id = Some(session.id().as_ref().into());
    seed_params.auth_time = Some(session.created_at());
    seed_params.reference_id = Some("seed-ref".into());
    seed_params.requested_user_info_claims = Some(vec!["email".into()]);
    seed_params.resources = Some(vec![userinfo.clone()]);
    let seed = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:server"),
            &seed_params,
        )
        .await?;
    let protected = provider
        .hash_token(seed["refresh_token"].as_str().unwrap(), "refresh_token")
        .await?;
    let original = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &protected)
        .await?
        .unwrap();
    let mut params = OAuthTokenIssueParams::new(client, vec!["email".into()]);
    params.refresh_token = Some(original.clone());
    let machine = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert!(machine.get("refresh_token").is_none());
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Refresh, &protected)
            .await?
            .unwrap()
            .metadata
            .get("revoked")
            .is_none_or(Value::is_null)
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.reference_id = Some("next-ref".into());
    params.refresh_token.as_mut().unwrap().token = "snapshot-not-a-lookup-key".into();
    let issued = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert_eq!(issued["scope"], "email");
    assert_eq!(issued["access_token"].as_str().unwrap().len(), 32);
    let retained_key = provider
        .hash_token(issued["refresh_token"].as_str().unwrap(), "refresh_token")
        .await?;
    let retained = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &retained_key)
        .await?
        .unwrap();
    assert_ne!(retained.id, original.id);
    assert_eq!(retained.metadata["scopes"], json!(["email"]));
    assert_eq!(retained.metadata["resources"], json!([userinfo]));
    assert_eq!(
        retained.metadata["requestedUserInfoClaims"],
        json!(["email"])
    );
    assert_eq!(retained.metadata["referenceId"], "next-ref");
    assert!(retained.session_id.is_none());
    assert!(retained.metadata.get("authTime").is_none_or(Value::is_null));
    let old = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &protected)
        .await?
        .unwrap();
    assert!(old.metadata["revoked"].is_string());
    assert_eq!(old.metadata["rotatedAt"], old.metadata["revoked"]);
    let before = db
        .tables(&["oauthAccessToken", "oauthRefreshToken"])
        .await?;
    let denied = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_grant","error_description":"invalid refresh token"})
    );
    assert_eq!(
        db.tables(&["oauthAccessToken", "oauthRefreshToken"])
            .await?,
        before
    );
    params.refresh_token = Some(retained);
    let access_only = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert!(access_only.get("refresh_token").is_none());
    assert!(
        auth.store()
            .get_oauth_token(OAuthTokenKind::Refresh, &retained_key)
            .await?
            .unwrap()
            .metadata
            .get("revoked")
            .is_none_or(Value::is_null)
    );
    params.scopes.push("offline_access".into());
    let reauthorized = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    let row = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &provider
                .hash_token(
                    reauthorized["refresh_token"].as_str().unwrap(),
                    "refresh_token",
                )
                .await?,
        )
        .await?
        .unwrap();
    assert_eq!(row.metadata["scopes"], json!(["email", "offline_access"]));
    let mut bound_params = seed_params.clone();
    bound_params.resources = None;
    bound_params.confirmation = Some(json!({"jkt":"retained-key"}));
    let bound = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:server"),
            &bound_params,
        )
        .await?;
    let key = provider
        .hash_token(bound["refresh_token"].as_str().unwrap(), "refresh_token")
        .await?;
    params.refresh_token = auth
        .store()
        .get_oauth_token(OAuthTokenKind::Refresh, &key)
        .await?;
    params.confirmation = Some(Value::Null);
    let before = db
        .tables(&["oauthAccessToken", "oauthRefreshToken"])
        .await?;
    let denied = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await
        .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_dpop_proof","error_description":"DPoP proof header is required"})
    );
    assert_eq!(
        db.tables(&["oauthAccessToken", "oauthRefreshToken"])
            .await?,
        before
    );
    params.confirmation = Some(json!({"jkt":"replacement-key"}));
    let rebound = provider
        .issue_tokens(auth.context(), &call, Some("urn:fixture:server"), &params)
        .await?;
    assert_eq!(rebound["token_type"], "DPoP");
    let retained = auth
        .store()
        .get_oauth_token(
            OAuthTokenKind::Refresh,
            &provider
                .hash_token(rebound["refresh_token"].as_str().unwrap(), "refresh_token")
                .await?,
        )
        .await?
        .unwrap();
    assert_eq!(
        retained.metadata["confirmation"],
        json!({"jkt":"replacement-key"})
    );
    Ok(())
}
