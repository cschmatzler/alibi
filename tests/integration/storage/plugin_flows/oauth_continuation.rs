//! Continuation resumes a real signed authorization request using actual session authority.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_continuation_resumes_signed_authorization_for_authenticated_caller);
async fn oauth_continuation_resumes_signed_authorization_for_authenticated_caller<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
            select_account_page: Some("/select".into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "consent-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"continue-state","prompt":"select_account","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let produced = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&produced)["url"].as_str().unwrap())?;
    assert_eq!(url.path(), "/select");
    let signed = url.query().unwrap();
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
    for (input, cookie, attach, status, error, description) in [
        (
            json!({}),
            cookies(&owner),
            true,
            400,
            "invalid_request",
            "Missing parameters",
        ),
        (
            json!({"selected":true}),
            cookies(&owner),
            true,
            400,
            "invalid_request",
            "missing oauth query",
        ),
        (
            json!({"selected":true,"oauth_query":format!("{signed}&sig=duplicate")}),
            cookies(&owner),
            true,
            400,
            "invalid_signature",
            "",
        ),
        (
            json!({"selected":true,"oauth_query":signed}),
            String::new(),
            true,
            401,
            "",
            "",
        ),
        (
            json!({"selected":42,"oauth_query":signed}),
            cookies(&owner),
            true,
            400,
            "",
            "",
        ),
        (
            json!({"selected":true,"oauth_query":signed}),
            cookies(&owner),
            false,
            401,
            "invalid_request",
            "request not found",
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Continue").with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                request: attach.then(|| request("/oauth2/continue", Some(json!({})), &cookie)),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if !error.is_empty() {
            let body = denied.body.as_ref().unwrap();
            assert_eq!(body.get("error").unwrap().as_str(), Some(error));
            if !description.is_empty() {
                assert_eq!(
                    body.get("error_description").unwrap().as_str(),
                    Some(description)
                );
            }
        }
    }
    let selected = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_continue_endpoint(
            &json!({"selected":true,"oauth_query":signed}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request(
                "/oauth2/continue",
                Some(json!({})),
                &cookies(&owner),
            )),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(selected.status, 200);
    let target = url::Url::parse(ORIGIN)?.join(body(&selected)["url"].as_str().unwrap())?;
    assert_eq!(target.path(), "/consent");
    assert!(!target.query_pairs().any(|(key, _)| key == "prompt"));
    let mut creation = query.clone();
    creation["prompt"] = json!("create");
    let created = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&creation)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let created_url = url::Url::parse(ORIGIN)?.join(body(&created)["url"].as_str().unwrap())?;
    let creation_signed = created_url.query().unwrap();
    for (input, path) in [
        (
            json!({"created":true,"oauth_query":creation_signed}),
            "/consent",
        ),
        (
            json!({"selected":true,"created":true,"oauth_query":creation_signed}),
            "/login",
        ),
        (json!({"postLogin":true,"oauth_query":signed}), "/consent"),
    ] {
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_continue_endpoint(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                request: Some(request(
                    "/oauth2/continue",
                    Some(json!({})),
                    &cookies(&owner),
                )),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let url = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(url.path(), path);
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
            "oauth_consent",
            "oauth_resource",
            "oauth_client_resource"
        ])
        .await?
    );
    let consent_query = target.query().unwrap();
    let accepted = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, Some(consent_query))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request(
                "/oauth2/consent",
                Some(json!({})),
                &cookies(&owner),
            )),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(accepted.status, 200);
    let actual = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let current = body(&actual);
    let resumed = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_continue_endpoint(
            &json!({"selected":true,"oauth_query":signed}),
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request(
                "/oauth2/continue",
                Some(json!({})),
                &cookies(&owner),
            )),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(resumed.status, 200);
    let callback = url::Url::parse(body(&resumed)["url"].as_str().unwrap())?;
    assert_eq!(callback.host_str(), Some("app.fixture.test"));
    assert_eq!(
        callback
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1,
        "continue-state"
    );
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(code.as_bytes()));
    let proof = auth
        .store()
        .get_verification_by_identifier(&hash)
        .await?
        .unwrap();
    let value: Value = serde_json::from_str(proof.value())?;
    assert_eq!(value["type"], "authorization_code");
    assert_eq!(value["query"]["client_id"], id);
    assert_eq!(value["query"]["scope"], "email");
    assert_eq!(value["query"]["state"], "continue-state");
    assert_eq!(value["userId"], current["user"]["id"]);
    assert_eq!(value["sessionId"], current["session"]["id"]);
    assert_eq!(
        value["authTime"],
        chrono::DateTime::parse_from_rfc3339(current["session"]["createdAt"].as_str().unwrap())?
            .timestamp_millis()
    );
    assert_eq!(db.count("verifications").await?, 2);
    Ok(())
}
