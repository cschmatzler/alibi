//! Continuation resumes a real signed authorization request using actual session authority.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthPostLoginConfig, OAuthProviderConfig, OAuthProviderPlugin, OAuthSelectAccountConfig,
    OAuthSignupConfig, jwt::JwtPlugin,
};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/select-account-policy.rs"]
mod select_account_policy;
backend_tests!(oauth_continuation_resumes_signed_authorization_for_authenticated_caller);
async fn oauth_continuation_resumes_signed_authorization_for_authenticated_caller<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(select_account_policy::SelectAccountPolicy::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                select_account_page: Some("/select".into()),
                select_account: Some(OAuthSelectAccountConfig {
                    page: None,
                    should_redirect: policy.clone(),
                }),
                signup: Some(OAuthSignupConfig {
                    page: Some("/signup".into()),
                    should_redirect: Some(policy.clone()),
                }),
                post_login: Some(OAuthPostLoginConfig {
                    page: "/post-login".into(),
                    should_redirect: policy.clone(),
                    consent_reference_id: None,
                }),
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    let owner = signup(&auth, "consent-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Consent client","client_uri":"https://app.fixture.test","redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"continue-state","prompt":"select_account","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    Box::pin(assert_selection_cases(&auth, &policy, &owner, &query)).await?;
    for page in [None, Some(String::new())] {
        let fallback = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    select_account: Some(OAuthSelectAccountConfig {
                        page: page.clone(),
                        should_redirect: policy.clone(),
                    }),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        let mut automatic = query.clone();
        _ = automatic.as_object_mut().unwrap().remove("prompt");
        let response = Box::pin(selection_invoke(
            &fallback,
            "/oauth2/authorize",
            automatic,
            &cookies(&owner),
            "true",
            false,
            false,
        ))
        .await?;
        let value = body(&response);
        let raw = value["url"].as_str().unwrap();
        assert!(raw.starts_with(if page.is_none() { "/login?" } else { "?" }));
        let calls = std::mem::take(&mut *policy.calls.lock().unwrap());
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["stage"], "selectAccount");
        let response = Box::pin(selection_invoke(
            &fallback,
            "/oauth2/authorize",
            query.clone(),
            &cookies(&owner),
            "ordinary-error",
            false,
            false,
        ))
        .await?;
        assert!(
            selection_target(&response)
                .query_pairs()
                .any(|(k, v)| k == "error" && v == "unsupported_prompt_select_account")
        );
        assert!(policy.calls.lock().unwrap().is_empty());
    }
    let mut automatic = query.clone();
    _ = automatic.as_object_mut().unwrap().remove("prompt");
    let produced = Box::pin(selection_invoke(
        &auth,
        "/oauth2/authorize",
        automatic,
        &cookies(&owner),
        "true",
        false,
        false,
    ))
    .await?;
    let url = url::Url::parse(ORIGIN)?.join(body(&produced)["url"].as_str().unwrap())?;
    assert_eq!(url.path(), "/select");
    assert_eq!(std::mem::take(&mut *policy.calls.lock().unwrap()).len(), 1);
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
            "oauthResource",
            "oauthClientResource",
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
            "/signup",
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
            "user",
            "account",
            "session",
            "verification",
            "jwks",
            "oauthClient",
            "oauthConsent",
            "oauthResource",
            "oauthClientResource"
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
    assert_eq!(db.count("verification").await?, 2);
    assert!(
        policy
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call["stage"] != "selectAccount"),
        "continuation and consent must not re-enter initial policy"
    );
    Ok(())
}

fn selection_target(response: &AuthResponse) -> url::Url {
    url::Url::parse(ORIGIN)
        .unwrap()
        .join(body(response)["url"].as_str().unwrap())
        .unwrap()
}

async fn selection_invoke<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    input: Value,
    cookie: &str,
    decision: &str,
    signup: bool,
    post_login: bool,
) -> alibi::AuthResult<AuthResponse> {
    let mut physical = request(path, Some(input.clone()), cookie);
    for (key, value) in [
        ("x-selection-decision", decision),
        ("x-policy-caller", "physical"),
        ("x-signup-decision", if signup { "true" } else { "false" }),
        (
            "x-postlogin-decision",
            if post_login { "true" } else { "false" },
        ),
    ] {
        _ = physical.headers.insert(key.into(), value.into());
    }
    let endpoint = if path == "/oauth2/authorize" {
        OAuthProviderPlugin::oauth2_authorize_endpoint(&input)?
    } else if path == "/sign-in/email" {
        ServerEndpoint::<Value>::new("email-password", "signInEmail").with_body(&input)?
    } else {
        OAuthProviderPlugin::oauth2_continue_endpoint(&input)?
    };
    auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers: Some(
                [
                    ("cookie".into(), cookie.into()),
                    ("accept".into(), "application/json".into()),
                    ("x-selection-decision".into(), "ordinary-error".into()),
                    ("x-policy-caller".into(), "logical".into()),
                ]
                .into_iter()
                .collect(),
            ),
            request: Some(physical),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| e.error)?
    .into_response()
}

async fn assert_selection_cases<S: AuthSchema>(
    auth: &Alibi<S>,
    policy: &select_account_policy::SelectAccountPolicy,
    owner: &AuthResponse,
    original: &Value,
) -> TestResult {
    let actual = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let current = body(&actual);
    let mut base = original.clone();
    let cookie = cookies(owner);
    _ = base.as_object_mut().unwrap().remove("prompt");
    base["scope"] = json!("email  email profile");
    for (decision, patch, authenticated, signup, post_login, expected, stages) in [
        (
            "true",
            json!({}),
            true,
            true,
            true,
            "/select",
            vec!["selectAccount"],
        ),
        (
            "true",
            json!({"max_age":3600}),
            true,
            false,
            false,
            "/select",
            vec!["selectAccount"],
        ),
        (
            "true",
            json!({"prompt":"consent"}),
            true,
            true,
            true,
            "/select",
            vec!["selectAccount"],
        ),
        (
            "ordinary-error",
            json!({"prompt":"select_account"}),
            true,
            true,
            true,
            "/select",
            vec![],
        ),
        (
            "true",
            json!({"prompt":"none"}),
            true,
            true,
            true,
            "account_selection_required",
            vec!["selectAccount"],
        ),
        (
            "false",
            json!({}),
            true,
            true,
            true,
            "/signup",
            vec!["selectAccount", "signup"],
        ),
        (
            "false",
            json!({}),
            true,
            false,
            true,
            "/post-login",
            vec!["selectAccount", "signup", "postLogin"],
        ),
        (
            "false",
            json!({}),
            true,
            false,
            false,
            "/consent",
            vec!["selectAccount", "signup", "postLogin"],
        ),
        (
            "ordinary-error",
            json!({"scope":"forbidden"}),
            true,
            false,
            false,
            "invalid_scope",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"client_id":"missing"}),
            true,
            false,
            false,
            "invalid_client",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"redirect_uri":"https://evil.fixture.test/callback"}),
            true,
            false,
            false,
            "invalid_redirect",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"code_challenge":""}),
            true,
            false,
            false,
            "invalid_request",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"max_age":0}),
            true,
            false,
            false,
            "/login",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"prompt":"login"}),
            true,
            false,
            false,
            "/login",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"prompt":"create"}),
            true,
            false,
            false,
            "/signup",
            vec![],
        ),
        (
            "ordinary-error",
            json!({"prompt":"none"}),
            false,
            false,
            false,
            "login_required",
            vec![],
        ),
        (
            "ordinary-error",
            json!({}),
            false,
            false,
            false,
            "/login",
            vec![],
        ),
        (
            "ordinary-error",
            json!({}),
            true,
            false,
            false,
            "ordinary-error",
            vec!["selectAccount"],
        ),
        (
            "native-error",
            json!({}),
            true,
            false,
            false,
            "native-error",
            vec!["selectAccount"],
        ),
        (
            "api-error",
            json!({}),
            true,
            false,
            false,
            "api-error",
            vec!["selectAccount"],
        ),
        (
            "upstream-error",
            json!({}),
            true,
            false,
            false,
            "upstream-error",
            vec!["selectAccount"],
        ),
    ] {
        policy.calls.lock().unwrap().clear();
        let mut query = base.clone();
        query
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let response = Box::pin(selection_invoke(
            auth,
            "/oauth2/authorize",
            query,
            if authenticated { &cookie } else { "" },
            decision,
            signup,
            post_login,
        ))
        .await;
        if expected.ends_with("-error") {
            let error = response.unwrap_err();
            match expected {
                "ordinary-error" => assert!(matches!(error, alibi::AuthError::CallbackFailure(_))),
                "native-error" => assert!(matches!(error, alibi::AuthError::Forbidden(_))),
                "api-error" => assert!(matches!(error, alibi::AuthError::Api { status: 403, .. })),
                _ => assert!(matches!(
                    error,
                    alibi::AuthError::Upstream { status: 503, .. }
                )),
            }
        } else {
            let target = selection_target(&response?);
            if expected.starts_with('/') {
                assert_eq!(target.path(), expected);
                if expected == "/select" {
                    assert!(
                        !target
                            .query_pairs()
                            .any(|(k, _)| k == "ba_pl" || k == "max_age")
                    );
                }
            } else {
                assert!(
                    target
                        .query_pairs()
                        .any(|(k, v)| k == "error" && v == expected),
                    "{target}"
                );
                if expected == "invalid_request" {
                    assert!(target.query_pairs().any(|(k, v)| k == "error_description"
                        && v == "pkce is required for public clients"));
                }
            }
        }
        let calls = policy.calls.lock().unwrap().clone();
        assert_eq!(
            calls
                .iter()
                .map(|v| v["stage"].as_str().unwrap())
                .collect::<Vec<_>>(),
            stages
        );
        if stages.first() == Some(&"selectAccount") {
            assert_eq!(
                calls[0],
                json!({"stage":"selectAccount","caller":"physical","decision":decision,"user":{"id":current["user"]["id"],"email":current["user"]["email"],"name":current["user"]["name"]},"session":{"id":current["session"]["id"],"userId":current["session"]["userId"],"token":current["session"]["token"]},"scopes":["email","email","profile"]})
            );
        }
    }
    // A policy-produced signed request must resume without rerunning the policy,
    // even when the physical request would make it throw.
    let mut default_scope = base.clone();
    _ = default_scope.as_object_mut().unwrap().remove("scope");
    policy.calls.lock().unwrap().clear();
    let response = Box::pin(selection_invoke(
        auth,
        "/oauth2/authorize",
        default_scope,
        &cookie,
        "true",
        false,
        false,
    ))
    .await?;
    assert_eq!(selection_target(&response).path(), "/select");
    assert_eq!(
        std::mem::take(&mut *policy.calls.lock().unwrap())[0]["scopes"],
        json!(["email", "profile"])
    );
    let response = Box::pin(selection_invoke(
        auth,
        "/oauth2/authorize",
        base.clone(),
        &cookies(owner),
        "true",
        false,
        false,
    ))
    .await?;
    let target = selection_target(&response);
    let signed = target.query().unwrap();
    for flag in ["selected", "created", "postLogin"] {
        policy.calls.lock().unwrap().clear();
        let mut input = json!({"oauth_query":signed});
        input[flag] = json!(true);
        let resumed = Box::pin(selection_invoke(
            auth,
            "/oauth2/continue",
            input,
            &cookies(owner),
            "ordinary-error",
            false,
            false,
        ))
        .await?;
        assert_eq!(selection_target(&resumed).path(), "/consent");
        assert!(
            policy
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|v| v["stage"] != "selectAccount")
        );
    }
    policy.calls.lock().unwrap().clear();
    let signin = Box::pin(selection_invoke(
        auth,
        "/sign-in/email",
        json!({"email":body(owner)["user"]["email"],"password":PASSWORD,"oauth_query":signed}),
        "",
        "ordinary-error",
        false,
        false,
    ))
    .await?;
    assert_eq!(selection_target(&signin).path(), "/consent");
    assert!(
        policy
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|v| v["stage"] != "selectAccount")
    );
    policy.calls.lock().unwrap().clear();
    Ok(())
}
