//! Signup policy is owned by the authenticated authorization journey, not a mock grant.
use super::*;
use alibi::AuthVerification as _;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, OAuthSignupConfig, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
#[path = "../../../fixtures/oauth/signup-policy.rs"]
mod signup_policy;

pub(super) async fn assert_signup_policy<B: Backend>(
    connection: &B::Connection,
    owner: &AuthResponse,
    managed: &AuthResponse,
    session_id: &str,
) -> TestResult {
    let policy = Arc::new(signup_policy::SignupPolicy::default());
    for (page, with_policy) in [
        (Some("/signup"), true),
        (None, true),
        (Some(""), true),
        (Some("/signup"), false),
    ] {
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    signup: Some(OAuthSignupConfig {
                        page: page.map(str::to_owned),
                        should_redirect: with_policy
                            .then(|| policy.clone() as Arc<dyn alibi::plugins::OAuthSignupPolicy>),
                    }),
                    select_account_page: Some("/select".into()),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        Box::pin(assert_cases(
            &auth,
            &policy,
            owner,
            managed,
            session_id,
            page,
            with_policy,
        ))
        .await?;
    }
    Ok(())
}

async fn assert_cases<S: AuthSchema>(
    auth: &Alibi<S>,
    policy: &signup_policy::SignupPolicy,
    owner: &AuthResponse,
    managed: &AuthResponse,
    session_id: &str,
    page: Option<&str>,
    with_policy: bool,
) -> TestResult {
    let cookie = cookies(owner);
    let session = json!({"id":session_id});
    let cases = if with_policy && page == Some("/signup") {
        vec![
            ("true", json!({}), true, page.unwrap_or("/login"), true),
            ("page", json!({}), true, "/registration/step", true),
            (
                "fragment",
                json!({}),
                true,
                "/registration/step#fragment",
                true,
            ),
            ("false", json!({"prompt":"none"}), true, "code", true),
            ("empty", json!({}), true, "code", true),
            (
                "true",
                json!({"prompt":"none"}),
                true,
                "interaction_required",
                true,
            ),
            (
                "true",
                json!({"prompt":"consent"}),
                true,
                page.unwrap_or("/login"),
                true,
            ),
            ("true", json!({}), false, "/login", false),
            (
                "true",
                json!({"prompt":"none"}),
                false,
                "login_required",
                false,
            ),
            ("true", json!({"prompt":"login"}), true, "/login", false),
            ("true", json!({"max_age":"0"}), true, "/login", false),
            (
                "true",
                json!({"max_age":"3600"}),
                true,
                page.unwrap_or("/login"),
                true,
            ),
            (
                "true",
                json!({"prompt":"create"}),
                true,
                page.unwrap_or("/login"),
                false,
            ),
            (
                "true",
                json!({"prompt":"select_account"}),
                true,
                "/select",
                false,
            ),
            (
                "true",
                json!({"scope":"forbidden"}),
                true,
                "invalid_scope",
                false,
            ),
            (
                "true",
                json!({"code_challenge":"incomplete"}),
                true,
                "invalid_request",
                false,
            ),
            ("ordinary-error", json!({}), true, "ordinary-error", true),
            ("api-error", json!({}), true, "api-error", true),
            ("native-error", json!({}), true, "native-error", true),
            ("upstream-error", json!({}), true, "upstream-error", true),
        ]
    } else if with_policy {
        vec![
            ("true", json!({}), true, page.unwrap_or("/login"), true),
            ("page", json!({}), true, "/registration/step", true),
            (
                "true",
                json!({"prompt":"create"}),
                true,
                page.unwrap_or("/login"),
                false,
            ),
        ]
    } else {
        vec![
            ("true", json!({"prompt":"create"}), true, "/signup", false),
            ("true", json!({}), true, "code", false),
        ]
    };
    for (decision, patch, authenticated, expected, called) in cases {
        policy.calls.lock().unwrap().clear();
        let mut query = json!({"client_id":body(managed)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email  email","state":"signup-state","extension":"bound"});
        query
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let mut physical = request(
            "/oauth2/authorize",
            None,
            if authenticated { &cookie } else { "" },
        );
        _ = physical
            .headers
            .insert("x-signup-decision".into(), decision.into());
        _ = physical
            .headers
            .insert("x-signup-caller".into(), "physical".into());
        let output = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
                EndpointOptions {
                    headers: Some(
                        [
                            (
                                "cookie".into(),
                                if authenticated {
                                    cookie.clone()
                                } else {
                                    String::new()
                                },
                            ),
                            ("accept".into(), "application/json".into()),
                            ("x-signup-decision".into(), "false".into()),
                            ("x-signup-caller".into(), "logical".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    request: Some(physical),
                    ..Default::default()
                },
            ),
        )
        .await;
        if expected.ends_with("-error") {
            let error = output.unwrap_err();
            if expected == "ordinary-error" {
                assert_eq!(error.error.status_code(), 500);
                assert!(matches!(error.error, alibi::AuthError::CallbackFailure(_)));
            } else {
                assert_eq!(
                    error.error.status_code(),
                    if expected == "upstream-error" {
                        503
                    } else {
                        403
                    }
                );
                assert_eq!(
                    body(&error.error.to_auth_response()),
                    match expected {
                        "native-error" => json!({"message":"Signup denied by native policy"}),
                        "upstream-error" =>
                            json!({"code":"SIGNUP_UNAVAILABLE","message":"Signup policy unavailable"}),
                        _ =>
                            json!({"code":"SIGNUP_DENIED","message":"Signup denied by application"}),
                    }
                );
            }
            assert_eq!(policy.calls.lock().unwrap().len(), 1);
            continue;
        }
        let output = output?.into_response()?;
        let target = body(&output)["url"].as_str().unwrap().to_owned();
        let calls = policy.calls.lock().unwrap().clone();
        if called {
            assert_eq!(
                calls,
                vec![
                    json!({"caller":"physical","decision":decision,"user":{"id":body(owner)["user"]["id"],"email":body(owner)["user"]["email"],"name":body(owner)["user"]["name"]},"session":{"id":session["id"],"userId":body(owner)["user"]["id"],"token":body(owner)["token"]},"scopes":["email","email"]})
                ]
            );
        } else {
            assert!(calls.is_empty(), "{query}");
        }
        if expected == "code" {
            let callback = url::Url::parse(&target)?;
            let code = callback
                .query_pairs()
                .find(|(key, _)| key == "code")
                .unwrap()
                .1
                .into_owned();
            let identifier = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(code.as_bytes()));
            let grant = Box::pin(auth.store().get_verification_by_identifier(&identifier))
                .await?
                .unwrap();
            let value: Value = serde_json::from_str(grant.value())?;
            assert_eq!(value["userId"], body(owner)["user"]["id"]);
            assert_eq!(value["sessionId"], session["id"]);
            assert_eq!(value["query"]["client_id"], body(managed)["client_id"]);
            assert_eq!(value["query"]["scope"], "email  email");
        } else if expected.ends_with("required")
            || matches!(expected, "invalid_scope" | "invalid_request")
        {
            let target = url::Url::parse(&target)?;
            assert_eq!(
                target
                    .query_pairs()
                    .find(|(key, _)| key == "error")
                    .unwrap()
                    .1,
                expected
            );
        } else {
            let signed = target
                .strip_prefix(&format!("{expected}?"))
                .unwrap_or_else(|| panic!("{target} != {expected}"));
            let params: std::collections::HashMap<_, _> =
                url::form_urlencoded::parse(signed.as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(params["client_id"], body(managed)["client_id"]);
            assert_eq!(params["state"], "signup-state");
            if patch["max_age"] == "3600" {
                assert!(!params.contains_key("max_age"));
            }
            if page == Some("/signup") && decision == "true" && patch == json!({}) && authenticated
            {
                let rejected = Box::pin(auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "oauth2Continue").with_body(
                        &json!({"created":true,"oauth_query":format!("{signed}&extension=forged")}),
                    )?,
                    EndpointOptions::default(),
                ))
                .await
                .unwrap_err();
                assert_eq!(rejected.error.status_code(), 400);
                assert_eq!(
                    rejected.body.unwrap().get("error").unwrap().as_str(),
                    Some("invalid_signature")
                );
                let mut physical = request("/oauth2/continue", Some(json!({})), &cookie);
                _ = physical
                    .headers
                    .insert("x-signup-decision".into(), "false".into());
                let resumed = Box::pin(
                    auth.dispatch_endpoint(
                        OAuthProviderPlugin::oauth2_continue_endpoint(
                            &json!({"created":true,"oauth_query":signed}),
                        )?,
                        EndpointOptions {
                            headers: Some(
                                [
                                    ("cookie".into(), cookie.clone()),
                                    ("accept".into(), "application/json".into()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                            request: Some(physical),
                            ..Default::default()
                        },
                    ),
                )
                .await?
                .into_response()?;
                let target = url::Url::parse(body(&resumed)["url"].as_str().unwrap())?;
                let code = target
                    .query_pairs()
                    .find(|(key, _)| key == "code")
                    .unwrap()
                    .1
                    .into_owned();
                let identifier = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(code.as_bytes()));
                let grant = Box::pin(auth.store().get_verification_by_identifier(&identifier))
                    .await?
                    .unwrap();
                let grant: Value = serde_json::from_str(grant.value())?;
                assert_eq!(grant["userId"], body(owner)["user"]["id"]);
                assert_eq!(grant["sessionId"], session["id"]);
                assert_eq!(grant["query"]["client_id"], body(managed)["client_id"]);
                assert_eq!(grant["query"]["extension"], "bound");
            }
        }
    }
    Ok(())
}
