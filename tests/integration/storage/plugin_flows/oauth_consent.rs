//! Consent processes the genuine signed request and persists the accepted grant.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_consent_persists_grant_and_issues_bound_code);
async fn oauth_consent_persists_grant_and_issues_bound_code<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::new())
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "consent-owner@example.test")).await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email profile","state":"consent-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let producer = Box::pin(
        auth.dispatch_endpoint(
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
        ),
    )
    .await?
    .into_response()?;
    let url = url::Url::parse(ORIGIN)?.join(body(&producer)["url"].as_str().unwrap())?;
    let signed = url.query().unwrap();
    let before = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
        ])
        .await?;
    let output = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Consent")
                .with_body(&json!({"accept":false,"oauth_query":signed}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                request: Some(request("/oauth2/consent", None, "")),
                ..Default::default()
            },
        ),
    )
    .await;
    let response = match output {
        Ok(value) => value.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(
        response.status, 200,
        "registered consent must deliver the denial redirect"
    );
    let callback = url::Url::parse(body(&response)["url"].as_str().unwrap())?;
    assert_eq!(callback.host_str(), Some("app.fixture.test"));
    assert_eq!(
        callback
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "access_denied"
    );
    assert_eq!(
        before,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent"
        ])
        .await?
    );
    for (input, cookie, status, error) in [
        (
            json!({"accept":true}),
            cookies(&owner),
            400,
            "invalid_request",
        ),
        (
            json!({"accept":true,"oauth_query":signed,"scope":"openid"}),
            cookies(&owner),
            400,
            "invalid_request",
        ),
        (
            json!({"accept":true,"oauth_query":format!("{signed}&sig=duplicate")}),
            cookies(&owner),
            400,
            "invalid_signature",
        ),
        (
            json!({"accept":true,"oauth_query":signed}),
            String::new(),
            401,
            "",
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Consent").with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                request: Some(request("/oauth2/consent", None, "")),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if !error.is_empty() {
            assert_eq!(
                denied.body.as_ref().unwrap().get("error").unwrap().as_str(),
                Some(error)
            );
        }
    }
    assert_eq!(
        before,
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent"
        ])
        .await?
    );
    let session_response = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let current = body(&session_response);
    let accepted = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, Some("email"), Some(signed))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request("/oauth2/consent", None, "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(accepted.status, 200);
    let callback = url::Url::parse(body(&accepted)["url"].as_str().unwrap())?;
    let code = callback
        .query_pairs()
        .find(|(name, _)| name == "code")
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
    let payload: Value = serde_json::from_str(proof.value())?;
    assert_eq!(payload["type"], "authorization_code");
    assert_eq!(payload["query"]["scope"], "email");
    assert_eq!(payload["query"]["client_id"], id);
    assert_eq!(payload["userId"], current["user"]["id"]);
    assert_eq!(payload["sessionId"], current["session"]["id"]);
    assert_eq!(
        payload["authTime"],
        chrono::DateTime::parse_from_rfc3339(current["session"]["createdAt"].as_str().unwrap())?
            .timestamp_millis()
    );
    assert_eq!(
        callback
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1,
        "consent-state"
    );
    let user_id = current["user"]["id"].as_str().unwrap();
    let rows = auth.store().list_oauth_consents_by_user(user_id).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].client_id, id);
    assert_eq!(rows[0].metadata["scopes"], json!(["email"]));
    let row_id = rows[0].id.clone();
    let replay = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, Some(signed))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request("/oauth2/consent", None, "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(replay.status, 200);
    let rows = auth.store().list_oauth_consents_by_user(user_id).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, row_id);
    assert_eq!(db.count("oauthConsent").await?, 1);
    assert_eq!(db.count("verification").await?, 2);
    assert_eq!(rows[0].metadata["resources"], Value::Null);

    // A new resource needs consent even when every requested scope is remembered.
    let resource = format!("{ORIGIN}/api/auth/oauth2/userinfo");
    let other = Box::pin(signup(&auth, "consent-foreign@example.test")).await;
    let tables = [
        "user",
        "account",
        "session",
        "verification",
        "jwks",
        "oauthClient",
        "oauthConsent",
    ];
    let before_resource = db.tables(&tables).await?;
    let mut expanded_query = query.clone();
    expanded_query["resource"] = json!(resource);
    let mut silent_query = expanded_query.clone();
    silent_query["prompt"] = json!("none");
    let silent = Box::pin(authorize_http(&auth, &silent_query, &cookies(&owner))).await?;
    assert!(
        silent
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "consent_required")
    );
    assert!(
        silent
            .query_pairs()
            .any(|(key, value)| key == "state" && value == "consent-state")
    );
    assert!(!silent.query_pairs().any(|(key, _)| key == "code"));
    let expanded = Box::pin(authorize_http(&auth, &expanded_query, &cookies(&owner))).await?;
    assert_eq!(expanded.path(), "/consent");
    assert!(
        expanded
            .query_pairs()
            .any(|(key, value)| key == "resource" && value == resource)
    );
    assert!(
        expanded
            .query_pairs()
            .any(|(key, value)| key == "sig" && !value.is_empty())
    );
    assert!(!expanded.query_pairs().any(|(key, _)| key == "code"));
    assert_eq!(before_resource, db.tables(&tables).await?);

    let accepted_resource = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, expanded.query())?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            request: Some(request("/oauth2/consent", None, "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(accepted_resource.status, 200);
    let accepted_url = url::Url::parse(body(&accepted_resource)["url"].as_str().unwrap())?;
    let remembered = Box::pin(authorize_http(&auth, &silent_query, &cookies(&owner))).await?;
    for callback in [accepted_url, remembered] {
        assert_eq!(callback.host_str(), Some("app.fixture.test"));
        assert!(!callback.query_pairs().any(|(key, _)| key == "error"));
        assert!(
            callback
                .query_pairs()
                .any(|(key, value)| key == "state" && value == "consent-state")
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
        let payload: Value = serde_json::from_str(proof.value())?;
        assert_eq!(payload["type"], "authorization_code");
        for field in ["client_id", "scope", "redirect_uri", "code_challenge"] {
            assert_eq!(payload["query"][field], query[field]);
        }
        assert_eq!(payload["resource"], json!([resource]));
        assert_eq!(payload["userId"], current["user"]["id"]);
        assert_eq!(payload["sessionId"], current["session"]["id"]);
        assert_eq!(
            payload["authTime"],
            chrono::DateTime::parse_from_rfc3339(
                current["session"]["createdAt"].as_str().unwrap()
            )?
            .timestamp_millis()
        );
    }
    let resource_rows = auth.store().list_oauth_consents_by_user(user_id).await?;
    assert_eq!(resource_rows.len(), 1);
    assert_eq!(resource_rows[0].id, row_id);
    assert_eq!(resource_rows[0].created_at, rows[0].created_at);
    assert_eq!(resource_rows[0].client_id, id);
    assert_eq!(resource_rows[0].user_id.as_deref(), Some(user_id));
    assert_eq!(
        resource_rows[0].metadata["scopes"],
        json!(["email", "profile"])
    );
    assert_eq!(resource_rows[0].metadata["resources"], json!([resource]));
    assert_eq!(db.count("oauthConsent").await?, 1);
    assert_eq!(db.count("verification").await?, 4);

    let before_foreign = db.tables(&tables).await?;
    let foreign = Box::pin(authorize_http(&auth, &silent_query, &cookies(&other))).await?;
    assert!(
        foreign
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "consent_required")
    );
    assert!(!foreign.query_pairs().any(|(key, _)| key == "code"));
    let foreign_consent =
        Box::pin(authorize_http(&auth, &expanded_query, &cookies(&other))).await?;
    assert_eq!(foreign_consent.path(), "/consent");
    assert!(!foreign_consent.query_pairs().any(|(key, _)| key == "code"));
    assert_eq!(before_foreign, db.tables(&tables).await?);
    Ok(())
}

async fn authorize_http<S: AuthSchema>(
    auth: &Alibi<S>,
    query: &Value,
    cookie: &str,
) -> TestResult<url::Url> {
    let mut req = request("/oauth2/authorize", None, cookie);
    _ = req
        .headers
        .insert("accept".into(), "application/json".into());
    req.set_query_pairs(
        query
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(key, value)| {
                let values = value
                    .as_array()
                    .cloned()
                    .unwrap_or_else(|| vec![value.clone()]);
                values
                    .into_iter()
                    .map(move |value| (key.clone(), value.as_str().unwrap().to_owned()))
            })
            .collect::<Vec<_>>(),
    );
    let response = Box::pin(call(auth, req, 200)).await;
    Ok(url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?)
}
