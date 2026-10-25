//! Consent processes the genuine signed request and persists the accepted grant.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/consent-reference.rs"]
mod consent_reference;
backend_tests!(oauth_consent_persists_grant_and_issues_bound_code);
async fn oauth_consent_persists_grant_and_issues_bound_code<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let references = Arc::new(consent_reference::ConsentReferencePolicy::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    disable_jwt_plugin: true,
                    post_login: Some(alibi::plugins::OAuthPostLoginConfig {
                        page: "/post-login".into(),
                        should_redirect: references.clone(),
                        consent_reference_id: Some(references.clone()),
                    }),
                    ..Default::default()
                },
            ))
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "consent-owner@example.test")).await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile offline_access","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
        "consent-reference-verifier-with-at-least-43-characters",
    ));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email profile","state":"consent-state","code_challenge":challenge,"code_challenge_method":"S256"});
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
    _ = references.references.lock().unwrap().insert(
        current["session"]["id"].as_str().unwrap().into(),
        "team-a".into(),
    );
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
    assert_eq!(payload["referenceId"], "team-a");
    let calls = std::mem::take(&mut *references.reference_calls.lock().unwrap());
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["scopes"], json!(["email"]));
    assert_eq!(calls[1]["scopes"], json!(["email"]));
    for call in calls {
        assert_eq!(call["user"]["id"], current["user"]["id"]);
        assert_eq!(call["session"]["id"], current["session"]["id"]);
    }
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
    assert_eq!(rows[0].metadata["referenceId"], "team-a");
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
    Box::pin(assert_reference_partitions(
        &auth,
        &references,
        &owner,
        &other,
        &expanded_query,
    ))
    .await?;
    Ok(())
}

async fn assert_reference_partitions<S: AuthSchema>(
    auth: &Alibi<S>,
    references: &consent_reference::ConsentReferencePolicy,
    owner: &AuthResponse,
    other: &AuthResponse,
    query: &Value,
) -> TestResult {
    let user_id = body(owner)["user"]["id"].as_str().unwrap().to_owned();
    let session = Box::pin(reference_call(
        auth,
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        &cookies(owner),
        "/get-session",
    ))
    .await?;
    let session_id = body(&session)["session"]["id"].as_str().unwrap().to_owned();
    let choose = |choice: Option<&str>| {
        let mut choices = references.references.lock().unwrap();
        if let Some(choice) = choice {
            _ = choices.insert(session_id.clone(), choice.into());
        } else {
            _ = choices.remove(&session_id);
        }
    };
    let mut silent = query.clone();
    silent["prompt"] = json!("none");
    choose(Some("team-b"));
    let denied = Box::pin(authorize_http(auth, &silent, &cookies(owner))).await?;
    assert!(
        denied
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "consent_required")
    );
    let mut partition_query = query.clone();
    partition_query["scope"] = json!("email profile offline_access");
    let consent = Box::pin(authorize_http(auth, &partition_query, &cookies(owner))).await?;
    assert_eq!(consent.path(), "/consent");
    let accepted = Box::pin(reference_call(
        auth,
        OAuthProviderPlugin::oauth2_consent_endpoint(
            true,
            Some("email offline_access"),
            consent.query(),
        )?,
        &cookies(owner),
        "/oauth2/consent",
    ))
    .await?;
    assert!(body(&accepted)["url"].as_str().unwrap().contains("code="));
    let rows = auth.store().list_oauth_consents_by_user(&user_id).await?;
    assert_eq!(rows.len(), 2);
    let a = rows
        .iter()
        .find(|row| row.metadata["referenceId"] == "team-a")
        .unwrap();
    let b = rows
        .iter()
        .find(|row| row.metadata["referenceId"] == "team-b")
        .unwrap();
    assert_ne!(a.id, b.id);
    assert_eq!(a.metadata["scopes"], json!(["email", "profile"]));
    assert_eq!(b.metadata["scopes"], json!(["email", "offline_access"]));
    // Same user, a genuine new session: choices do not leak between sessions.
    let signed_in = Box::pin(call(
        auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"consent-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    ))
    .await;
    let second = Box::pin(reference_call(
        auth,
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        &cookies(&signed_in),
        "/get-session",
    ))
    .await?;
    let second_id = body(&second)["session"]["id"].as_str().unwrap().to_owned();
    assert_ne!(second_id, session_id);
    _ = references
        .references
        .lock()
        .unwrap()
        .insert(second_id.clone(), "team-a".into());
    let reused = Box::pin(authorize_http(auth, &silent, &cookies(&signed_in))).await?;
    assert!(reused.query_pairs().any(|(key, _)| key == "code"));
    // Empty and undefined match only consent given without a reference.
    for fallback in [Some(""), None] {
        choose(fallback);
        let denied = Box::pin(authorize_http(auth, &silent, &cookies(owner))).await?;
        assert!(
            denied
                .query_pairs()
                .any(|(key, value)| key == "error" && value == "consent_required")
        );
    }
    // Management remains user-scoped even while a different reference is selected.
    choose(Some("team-b"));
    _ = Box::pin(reference_call(
        auth,
        OAuthProviderPlugin::update_oauth_consent_endpoint(
            &b.id,
            &["email".into(), "profile".into()],
        )?,
        &cookies(owner),
        "/oauth2/update-consent",
    ))
    .await?;
    let updated = Box::pin(reference_call(
        auth,
        OAuthProviderPlugin::update_oauth_consent_endpoint(&a.id, &["email".into()])?,
        &cookies(owner),
        "/oauth2/update-consent",
    ))
    .await?;
    assert_eq!(body(&updated)["referenceId"], "team-a");
    for endpoint in [
        OAuthProviderPlugin::get_oauth_consent_endpoint(&a.id)?,
        ServerEndpoint::<Value>::new("oauth-provider", "deleteOAuthConsent")
            .with_body(&json!({"id":a.id}))?,
    ] {
        let denied = Box::pin(reference_call(
            auth,
            endpoint,
            &cookies(other),
            "/oauth2/get-consent",
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.status_code(), 401);
    }
    // A later matching row must not hide insufficient authority in the first row.
    choose(None);
    let denied = Box::pin(authorize_http(auth, &silent, &cookies(owner))).await?;
    assert!(
        denied
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "consent_required")
    );
    for (choice, status) in [
        ("ordinary-error", 500),
        ("native-error", 403),
        ("api-error", 403),
        ("upstream-error", 503),
    ] {
        choose(Some(choice));
        for endpoint in [
            OAuthProviderPlugin::oauth2_authorize_endpoint(query)?,
            OAuthProviderPlugin::oauth2_consent_endpoint(true, None, consent.query())?,
        ] {
            let failed = Box::pin(reference_call(
                auth,
                endpoint,
                &cookies(owner),
                "/oauth2/authorize",
            ))
            .await
            .unwrap_err();
            assert_eq!(failed.status_code(), status);
            if choice == "ordinary-error" {
                assert!(failed.to_auth_response().body.is_empty());
            }
        }
    }
    assert_eq!(
        auth.store()
            .list_oauth_consents_by_user(&user_id)
            .await?
            .len(),
        2
    );
    let callback = url::Url::parse(body(&accepted)["url"].as_str().unwrap())?;
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let token=Box::pin(reference_call(auth,OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"authorization_code","client_id":query["client_id"],"code":code,"redirect_uri":query["redirect_uri"],"code_verifier":"consent-reference-verifier-with-at-least-43-characters"}))?,"","/oauth2/token")).await?;
    let access = body(&token)["access_token"].as_str().unwrap().to_owned();
    let hash =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(access));
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
        .await?
        .unwrap();
    assert_eq!(stored.metadata["referenceId"], "team-b");
    assert_eq!(stored.user_id.as_deref(), Some(user_id.as_str()));
    assert_eq!(stored.session_id.as_deref(), Some(session_id.as_str()));
    assert_eq!(
        stored.metadata["scopes"],
        json!(["email", "offline_access"])
    );
    let refresh = body(&token)["refresh_token"].as_str().unwrap().to_owned();
    let hash =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(refresh));
    let stored = auth
        .store()
        .get_oauth_token(alibi::store::OAuthTokenKind::Refresh, &hash)
        .await?
        .unwrap();
    assert_eq!(stored.metadata["referenceId"], "team-b");
    assert_eq!(stored.user_id.as_deref(), Some(user_id.as_str()));
    assert_eq!(stored.session_id.as_deref(), Some(session_id.as_str()));
    assert_eq!(
        stored.metadata["scopes"],
        json!(["email", "offline_access"])
    );
    Box::pin(assert_reference_claims(
        auth, references, owner, other, query,
    ))
    .await?;
    Ok(())
}

async fn assert_reference_claims<S: AuthSchema>(
    auth: &Alibi<S>,
    references: &consent_reference::ConsentReferencePolicy,
    owner: &AuthResponse,
    other: &AuthResponse,
    query: &Value,
) -> TestResult {
    let session = Box::pin(reference_call(
        auth,
        ServerEndpoint::new("session-management", "getSession"),
        &cookies(owner),
        "/get-session",
    ))
    .await?;
    let session_id = body(&session)["session"]["id"].as_str().unwrap().to_owned();
    let user_id = body(&session)["user"]["id"].as_str().unwrap().to_owned();
    let rows = auth.store().list_oauth_consents_by_user(&user_id).await?;
    let a = rows
        .iter()
        .find(|row| row.metadata["referenceId"] == "team-a")
        .unwrap();
    let b = rows
        .iter()
        .find(|row| row.metadata["referenceId"] == "team-b")
        .unwrap();
    // Empty/undefined consent is stored apart from referenced rows, which keep
    // their reference and scopes.
    let mut forced = query.clone();
    forced["prompt"] = json!("consent");
    let consent = Box::pin(authorize_http(auth, &forced, &cookies(owner))).await?;
    for choice in [Some(""), None] {
        {
            let mut choices = references.references.lock().unwrap();
            if let Some(choice) = choice {
                _ = choices.insert(session_id.clone(), choice.into());
            } else {
                _ = choices.remove(&session_id);
            }
        }
        _ = Box::pin(reference_call(
            auth,
            OAuthProviderPlugin::oauth2_consent_endpoint(true, None, consent.query())?,
            &cookies(owner),
            "/oauth2/consent",
        ))
        .await?;
        let updated = auth.store().get_oauth_consent(&a.id).await?.unwrap();
        assert_eq!(updated.metadata["referenceId"], "team-a");
        assert_eq!(updated.metadata["scopes"], a.metadata["scopes"]);
        let rows = auth.store().list_oauth_consents_by_user(&user_id).await?;
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter()
                .filter(|row| row.metadata["referenceId"].is_null())
                .count(),
            1
        );
    }
    _ = references
        .references
        .lock()
        .unwrap()
        .insert(session_id, "team-b".into());
    let mut claims = query.clone();
    claims["scope"] = json!("openid email");
    claims["claims"] = json!(r#"{"userinfo":{"email":null,"name":null}}"#);
    let consent = Box::pin(authorize_http(auth, &claims, &cookies(owner))).await?;
    assert_eq!(consent.path(), "/consent");
    _ = Box::pin(reference_call(auth,ServerEndpoint::new("oauth-provider","oauth2Consent").with_body(&json!({"accept":true,"claims":{"userinfo":{"email":null}},"oauth_query":consent.query()}))?,&cookies(owner),"/oauth2/consent")).await?;
    let updated = auth.store().get_oauth_consent(&b.id).await?.unwrap();
    assert_eq!(
        updated.metadata["requestedUserInfoClaims"],
        json!(["email"])
    );
    assert_eq!(updated.metadata["referenceId"], "team-b");
    assert_eq!(
        auth.store()
            .get_oauth_consent(&a.id)
            .await?
            .unwrap()
            .metadata["requestedUserInfoClaims"],
        json!([])
    );
    claims["prompt"] = json!("none");
    for (claim, allowed) in [("email", true), ("name", false)] {
        claims["claims"] = json!(format!(r#"{{"userinfo":{{"{claim}":null}}}}"#));
        let target = Box::pin(authorize_http(auth, &claims, &cookies(owner))).await?;
        assert_eq!(target.query_pairs().any(|(key, _)| key == "code"), allowed);
        if !allowed {
            assert!(
                target
                    .query_pairs()
                    .any(|(key, value)| key == "error" && value == "consent_required")
            );
        }
    }
    let foreign = Box::pin(reference_call(
        auth,
        ServerEndpoint::new("session-management", "getSession"),
        &cookies(other),
        "/get-session",
    ))
    .await?;
    let foreign_session = body(&foreign)["session"]["id"].as_str().unwrap().to_owned();
    _ = references
        .references
        .lock()
        .unwrap()
        .insert(foreign_session.clone(), "team-a".into());
    let mut silent = query.clone();
    silent["prompt"] = json!("none");
    assert!(
        Box::pin(authorize_http(auth, &silent, &cookies(other)))
            .await?
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "consent_required")
    );
    _ = references
        .references
        .lock()
        .unwrap()
        .insert(foreign_session, String::new());
    _ = Box::pin(reference_call(
        auth,
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, consent.query())?,
        &cookies(other),
        "/oauth2/consent",
    ))
    .await?;
    let foreign_rows = auth
        .store()
        .list_oauth_consents_by_user(body(&foreign)["user"]["id"].as_str().unwrap())
        .await?;
    assert_eq!(foreign_rows.len(), 1);
    assert!(foreign_rows[0].metadata["referenceId"].is_null());
    // A user's selected reference does not restrict their own revocation authority.
    _ = Box::pin(reference_call(
        auth,
        ServerEndpoint::new("oauth-provider", "deleteOAuthConsent")
            .with_body(&json!({"id":a.id}))?,
        &cookies(owner),
        "/oauth2/delete-consent",
    ))
    .await?;
    let rows = auth.store().list_oauth_consents_by_user(&user_id).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row.id == b.id));
    assert!(rows.iter().all(|row| row.id != a.id));
    Ok(())
}

async fn reference_call<S: AuthSchema>(
    auth: &Alibi<S>,
    endpoint: ServerEndpoint<Value>,
    cookie: &str,
    path: &str,
) -> alibi::AuthResult<AuthResponse> {
    Box::pin(
        auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookie.into()),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(request(path, None, cookie)),
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|error| error.error)?
    .into_response()
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
