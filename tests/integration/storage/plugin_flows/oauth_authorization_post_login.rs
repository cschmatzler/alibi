//! Post-login policy extends the real authorization/signin/consent owner journey.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{
    OAuthPostLoginConfig, OAuthProviderConfig, OAuthProviderPlugin, OAuthSignupConfig,
    jwt::JwtPlugin,
};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/post-login-policy.rs"]
mod post_login_policy;

pub(super) async fn assert_post_login_policy<B: Backend>(
    connection: &B::Connection,
    owner: &AuthResponse,
    managed: &AuthResponse,
    session_id: &str,
    public_id: &str,
) -> TestResult {
    let policy = Arc::new(post_login_policy::PostLoginPolicy::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                signup: Some(OAuthSignupConfig {
                    page: Some("/signup".into()),
                    should_redirect: Some(policy.clone()),
                }),
                post_login: Some(OAuthPostLoginConfig {
                    page: "/post-login".into(),
                    should_redirect: policy.clone(),
                }),
                ..Default::default()
            }))
            .build(),
    )
    .await?;
    Box::pin(assert_cases(&auth, &policy, owner, managed, session_id)).await?;
    Box::pin(assert_lifecycle(&auth, &policy, owner, public_id)).await
}

async fn invoke<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    input: Value,
    cookie: &str,
    decision: &str,
) -> alibi::AuthResult<AuthResponse> {
    let mut physical = request(path, Some(input.clone()), cookie);
    _ = physical
        .headers
        .insert("x-postlogin-decision".into(), decision.into());
    _ = physical
        .headers
        .insert("x-policy-caller".into(), "physical".into());
    let endpoint = if path == "/oauth2/authorize" {
        OAuthProviderPlugin::oauth2_authorize_endpoint(&input)?
    } else if path == "/oauth2/continue" {
        OAuthProviderPlugin::oauth2_continue_endpoint(&input)?
    } else {
        alibi::endpoint::ServerEndpoint::<Value>::new("oauth-provider", "oauth2Consent")
            .with_body(&input)?
    };
    auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers: Some(
                [
                    ("cookie".into(), cookie.into()),
                    ("accept".into(), "application/json".into()),
                    ("x-postlogin-decision".into(), "false".into()),
                ]
                .into_iter()
                .collect(),
            ),
            request: Some(physical),
            ..Default::default()
        },
    )
    .await
    .map_err(|error| error.error)?
    .into_response()
}

fn target(response: &AuthResponse) -> url::Url {
    url::Url::parse(ORIGIN)
        .unwrap()
        .join(body(response)["url"].as_str().unwrap())
        .unwrap()
}

async fn assert_cases<S: AuthSchema>(
    auth: &Alibi<S>,
    policy: &post_login_policy::PostLoginPolicy,
    owner: &AuthResponse,
    managed: &AuthResponse,
    session_id: &str,
) -> TestResult {
    let cookie = cookies(owner);
    for (decision, patch, expected) in [
        ("true", json!({}), "/post-login"),
        ("false", json!({}), "code"),
        ("true", json!({"prompt":"consent"}), "/post-login"),
        ("true", json!({"prompt":"none"}), "interaction_required"),
        ("true", json!({"ba_pl":session_id}), "/post-login"),
        ("true", json!({"scope":"forbidden"}), "invalid_scope"),
        ("ordinary-error", json!({}), "ordinary-error"),
        ("native-error", json!({}), "native-error"),
        ("api-error", json!({}), "api-error"),
        ("upstream-error", json!({}), "upstream-error"),
    ] {
        policy.calls.lock().unwrap().clear();
        let mut query = json!({"client_id":body(managed)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email  email","state":"post-login-state"});
        query
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let response = Box::pin(invoke(auth, "/oauth2/authorize", query, &cookie, decision)).await;
        if expected.ends_with("-error") {
            let error = response.unwrap_err();
            assert_eq!(
                error.status_code(),
                if expected == "ordinary-error" {
                    500
                } else if expected == "upstream-error" {
                    503
                } else {
                    403
                }
            );
            if expected == "ordinary-error" {
                assert!(matches!(error, alibi::AuthError::CallbackFailure(_)));
            }
        } else {
            let url = target(&response?);
            if expected.starts_with('/') {
                assert_eq!(url.path(), expected);
                assert!(!url.query_pairs().any(|(key, _)| key == "ba_pl"));
            } else {
                assert!(url.query_pairs().any(|(key, value)| if expected == "code" {
                    key == "code"
                } else {
                    key == "error" && value == expected
                }));
            }
        }
        let calls = policy.calls.lock().unwrap().clone();
        if expected == "invalid_scope" {
            assert!(calls.is_empty());
        } else {
            assert_eq!(
                calls,
                vec![
                    json!({"stage":"signup","sessionId":session_id}),
                    json!({"stage":"postLogin","caller":"physical","decision":decision,"user":{"id":body(owner)["user"]["id"],"email":body(owner)["user"]["email"],"name":body(owner)["user"]["name"]},"session":{"id":session_id,"userId":body(owner)["user"]["id"],"token":body(owner)["token"]},"scopes":["email","email"]})
                ]
            );
        }
    }
    Ok(())
}

async fn assert_lifecycle<S: AuthSchema>(
    auth: &Alibi<S>,
    policy: &post_login_policy::PostLoginPolicy,
    owner: &AuthResponse,
    public_id: &str,
) -> TestResult {
    policy.calls.lock().unwrap().clear();
    let query = json!({"client_id":public_id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"post-login-lifecycle","prompt":"login consent","max_age":"0","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
    let login = Box::pin(invoke(auth, "/oauth2/authorize", query, "", "true")).await?;
    assert_eq!(target(&login).path(), "/login");
    assert!(policy.calls.lock().unwrap().is_empty());
    let mut signin = request(
        "/sign-in/email",
        Some(
            json!({"email":body(owner)["user"]["email"],"password":PASSWORD,"oauth_query":target(&login).query().unwrap()}),
        ),
        &cookies(owner),
    );
    _ = signin
        .headers
        .insert("accept".into(), "application/json".into());
    let signed_in = Box::pin(call(auth, signin, 200)).await;
    let post = target(&signed_in);
    assert_eq!(post.path(), "/post-login");
    let cookie = cookies(&signed_in);
    let current = Box::pin(call(auth, request("/get-session", None, &cookie), 200)).await;
    let session_id = body(&current)["session"]["id"].as_str().unwrap().to_owned();
    let calls = std::mem::take(&mut *policy.calls.lock().unwrap());
    assert_eq!(calls[0], json!({"stage":"signup","sessionId":session_id}));
    assert_eq!(calls[1]["session"]["id"], session_id);
    assert_ne!(calls[1]["session"]["token"], body(owner)["token"]);
    assert_eq!(calls[1]["user"]["id"], body(owner)["user"]["id"]);
    let continued = json!({"postLogin":true,"oauth_query":post.query().unwrap()});
    assert_eq!(
        target(
            &Box::pin(invoke(
                auth,
                "/oauth2/continue",
                continued.clone(),
                &cookie,
                "true"
            ))
            .await?
        )
        .path(),
        "/post-login"
    );
    let consent = target(
        &Box::pin(invoke(
            auth,
            "/oauth2/continue",
            continued,
            &cookie,
            "false",
        ))
        .await?,
    );
    assert_eq!(consent.path(), "/consent");
    assert!(
        consent
            .query_pairs()
            .any(|(key, value)| key == "ba_pl" && value == session_id)
    );
    assert!(
        consent
            .query_pairs()
            .any(|(key, value)| key == "ba_param" && value == "ba_pl")
    );
    policy.calls.lock().unwrap().clear();
    // Same user, different actual session: a valid signed flag must not bypass policy.
    let switched = Box::pin(invoke(
        auth,
        "/oauth2/continue",
        json!({"postLogin":true,"oauth_query":consent.query().unwrap()}),
        &cookies(owner),
        "true",
    ))
    .await?;
    assert_eq!(target(&switched).path(), "/post-login");
    assert_eq!(policy.calls.lock().unwrap().len(), 2);
    policy.calls.lock().unwrap().clear();
    let switched_consent = Box::pin(invoke(
        auth,
        "/oauth2/consent",
        json!({"accept":true,"oauth_query":consent.query().unwrap()}),
        &cookies(owner),
        "true",
    ))
    .await?;
    assert_eq!(target(&switched_consent).path(), "/post-login");
    assert_eq!(policy.calls.lock().unwrap().len(), 2);
    policy.calls.lock().unwrap().clear();
    let forged = Box::pin(invoke(
        auth,
        "/oauth2/continue",
        json!({"postLogin":true,"oauth_query":format!("{}&ba_pl=forged",consent.query().unwrap())}),
        &cookie,
        "true",
    ))
    .await
    .unwrap_err();
    assert_eq!(forged.status_code(), 400);
    assert!(policy.calls.lock().unwrap().is_empty());
    let accepted = Box::pin(invoke(
        auth,
        "/oauth2/consent",
        json!({"accept":true,"oauth_query":consent.query().unwrap()}),
        &cookie,
        "true",
    ))
    .await?;
    assert_eq!(
        policy.calls.lock().unwrap().as_slice(),
        &[json!({"stage":"signup","sessionId":session_id})]
    );
    let code = target(&accepted)
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(code));
    let grant = auth
        .store()
        .get_verification_by_identifier(&hash)
        .await?
        .unwrap();
    let grant: Value = serde_json::from_str(grant.value())?;
    assert_eq!(grant["sessionId"], session_id);
    assert_eq!(grant["userId"], body(owner)["user"]["id"]);
    assert_eq!(grant["query"]["client_id"], public_id);
    assert!(grant["query"].get("ba_pl").is_none());
    Ok(())
}
