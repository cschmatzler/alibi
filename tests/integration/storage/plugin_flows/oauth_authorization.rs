//! Authorization emits a bounded signed login query after real client admission.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use alibi::{AuthSession as _, AuthVerification as _};
use base64::Engine;
use sha2::Digest;
backend_tests!(oauth_authorization_admits_client_and_produces_signed_login_redirect);
async fn oauth_authorization_admits_client_and_produces_signed_login_redirect<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "oauth-authorization-owner@example.test").await;
    let created = auth
        .dispatch_endpoint(
            OAuthProviderPlugin::create_oauth_client_endpoint(
                &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                    client_name: Some("Authorization client".into()),
                    redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
                    scope: Some("openid email".into()),
                    token_endpoint_auth_method: Some("none".into()),
                    ..Default::default()
                },
            )?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let input = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"caller-state","extension_zero":0,"extension_large":1e21,"extension_object":{"label":"value"},"extension_list":["literal",false,null,{"nested":1},["a","b"]],"extension_null":null,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
    let start = chrono::Utc::now().timestamp_millis();
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize").with_query(&input)?,
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
    assert_eq!(output.status, 200);
    let value = body(&output);
    assert_eq!(value["redirect"], true);
    let url = url::Url::parse(&format!("{ORIGIN}{}", value["url"].as_str().unwrap()))?;
    assert_eq!(url.path(), "/login");
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let field = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap()
    };
    assert_eq!(field("client_id"), id);
    assert_eq!(field("redirect_uri"), "https://app.fixture.test/callback");
    assert_eq!(field("scope"), "email");
    assert_eq!(field("state"), "caller-state");
    assert_eq!(field("extension_zero"), "0");
    assert_eq!(field("extension_large"), "1e+21");
    assert_eq!(field("extension_object"), "[object Object]");
    assert_eq!(
        pairs
            .iter()
            .filter(|(key, _)| key == "extension_list")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>(),
        ["literal", "false", "null", "[object Object]", "a,b"]
    );
    assert!(!pairs.iter().any(|(key, _)| key == "extension_null"));
    let issued: i64 = field("ba_iat").parse()?;
    assert!(issued >= start);
    assert!(issued <= chrono::Utc::now().timestamp_millis());
    assert_eq!(field("exp").parse::<i64>()?, issued / 1000 + 600);
    let mut canonical = pairs
        .iter()
        .filter(|(name, _)| name != "sig")
        .cloned()
        .collect::<Vec<_>>();
    canonical.sort();
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in &canonical {
        _ = encoded.append_pair(name, value);
    }
    let canonical = encoded.finish();
    let mut inner = [0x36_u8; 64];
    let mut outer = [0x5c_u8; 64];
    for (index, byte) in SECRET.bytes().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    let digest = sha2::Sha256::digest([inner.as_slice(), canonical.as_bytes()].concat());
    let expected = sha2::Sha256::digest([outer.as_slice(), digest.as_slice()].concat());
    assert_eq!(
        field("sig"),
        base64::engine::general_purpose::STANDARD.encode(expected)
    );
    for (query, error) in [
        (
            json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":42,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"}),
            "invalid_request",
        ),
        (
            json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":"https://unknown.fixture.test","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"}),
            "invalid_target",
        ),
        (
            json!({"client_id":"missing-client","response_type":"code","redirect_uri":"https://app.fixture.test/callback"}),
            "invalid_client",
        ),
        (
            json!({"client_id":id,"response_type":"code","redirect_uri":"https://evil.fixture.test/callback"}),
            "invalid_redirect",
        ),
        (
            json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"forbidden","state":"caller-state"}),
            "invalid_scope",
        ),
        (
            json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email"}),
            "invalid_request",
        ),
    ] {
        let r = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize")
                    .with_query(&query)?,
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
        assert_eq!(r.status, 200);
        let url = url::Url::parse(ORIGIN)?.join(body(&r)["url"].as_str().unwrap())?;
        assert_eq!(
            url.query_pairs()
                .find(|(name, _)| name == "error")
                .unwrap()
                .1,
            error
        );
    }
    let missing = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize").with_query(&input)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 401);
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

    let signed = url.query().unwrap();
    let protected = db
        .tables(&["user", "account", "session", "verification", "oauthClient"])
        .await?;
    for (path, operation, email) in [
        (
            "/sign-in/email",
            "signInEmail",
            "oauth-authorization-owner@example.test",
        ),
        (
            "/sign-up/email",
            "signUpEmail",
            "forged-interaction-signup@example.test",
        ),
    ] {
        let input = json!({"email":email,"name":"Forged interaction","password":PASSWORD,"oauth_query":format!("{signed}&sig=duplicate")});
        let rejected = call(&auth, request(path, Some(input.clone()), ""), 400).await;
        assert_eq!(body(&rejected), json!({"error":"invalid_signature"}));
        assert!(!rejected.headers.contains_key("set-cookie"));
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("email-password", operation).with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400);
        assert_eq!(
            rejected.body.as_deref(),
            Some(&alibi::utils::json::JsValue::from(
                json!({"error":"invalid_signature"})
            ))
        );
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?,
            protected
        );
    }
    let pairs = url
        .query_pairs()
        .map(|(key, value)| json!([key, value]))
        .collect::<Vec<_>>();
    for query in [json!(signed), json!(pairs)] {
        let input = json!({"email":"oauth-authorization-owner@example.test","password":"wrong-password","oauth_query":query});
        let rejected = call(
            &auth,
            request("/sign-in/email", Some(input.clone()), ""),
            401,
        )
        .await;
        assert_eq!(body(&rejected)["code"], "INVALID_EMAIL_OR_PASSWORD");
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("email-password", "signInEmail").with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 401);
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?,
            protected
        );
    }

    let managed=auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"client_name":"Code client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","skip_consent":true,"require_pkce":false}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    let code_start = chrono::Utc::now().timestamp();
    let code_output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","oauth2Authorize").with_query(&json!({"client_id":body(&managed)["client_id"],"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"code-state"}))?,EndpointOptions{headers:Some([("accept".into(),"application/json".into()),("cookie".into(),cookies(&owner))].into_iter().collect()),request:Some(request("/oauth2/authorize",None,&cookies(&owner))),..Default::default()}).await?.into_response()?;
    let callback = url::Url::parse(ORIGIN)?.join(body(&code_output)["url"].as_str().unwrap())?;
    assert_eq!(callback.host_str(), Some("app.fixture.test"));
    let code = callback
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(code.len(), 32);
    assert!(code.bytes().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(
        callback
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1,
        "code-state"
    );
    let identifier = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(code.as_bytes()));
    let proof = auth
        .store()
        .get_verification_by_identifier(&identifier)
        .await?
        .unwrap();
    let payload: Value = serde_json::from_str(proof.value())?;
    assert_eq!(payload["type"], "authorization_code");
    assert_eq!(payload["userId"], body(&owner)["user"]["id"]);
    let session = auth
        .store()
        .get_session(body(&owner)["token"].as_str().unwrap())
        .await?
        .unwrap();
    assert_eq!(payload["sessionId"], session.id().as_ref());
    assert_eq!(payload["authTime"], session.created_at().timestamp_millis());
    assert_eq!(payload["query"]["client_id"], body(&managed)["client_id"]);
    assert_eq!(payload["query"]["state"], "code-state");
    assert_eq!(payload["resource"], json!([]));
    assert!(proof.created_at().timestamp() >= code_start);
    assert!(proof.created_at().timestamp() <= chrono::Utc::now().timestamp());
    assert_eq!(
        proof.expires_at().timestamp() - proof.created_at().timestamp(),
        600
    );
    assert_eq!(db.count("verification").await?, 1);
    Box::pin(assert_authorization_admission(
        &auth,
        &db,
        &cookies(&owner),
        body(&managed)["client_id"].as_str().unwrap(),
    ))
    .await?;
    Box::pin(assert_signed_login_resumes(
        &auth, &owner, &managed, &signed, &id,
    ))
    .await?;
    Ok(())
}

async fn assert_signed_login_resumes<S: AuthSchema>(
    auth: &Alibi<S>,
    owner: &AuthResponse,
    managed: &AuthResponse,
    signed: &str,
    id: &str,
) -> TestResult {
    let mut login_request = request(
        "/sign-in/email",
        Some(json!({
            "email":"oauth-authorization-owner@example.test","password":PASSWORD,"oauth_query":signed,
        })),
        "",
    );
    _ = login_request
        .headers
        .insert("accept".into(), "application/json".into());
    let resumed = Box::pin(call(auth, login_request, 200)).await;
    assert_eq!(body(&resumed)["redirect"], true);
    let consent = url::Url::parse(ORIGIN)?.join(body(&resumed)["url"].as_str().unwrap())?;
    assert_eq!(consent.path(), "/consent");
    assert_eq!(
        consent
            .query_pairs()
            .find(|(key, _)| key == "client_id")
            .unwrap()
            .1,
        id
    );
    let authenticated = Box::pin(call(
        auth,
        request("/get-session", None, &cookies(&resumed)),
        200,
    ))
    .await;
    assert_eq!(
        body(&authenticated)["user"]["id"],
        body(&owner)["user"]["id"]
    );
    assert_ne!(
        body(&authenticated)["session"]["token"],
        body(&owner)["token"]
    );
    let other = Box::pin(signup(auth, "oauth-authorization-other@example.test")).await;
    let managed_login = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&json!({
                "client_id":body(&managed)["client_id"],"response_type":"code",
                "redirect_uri":"https://app.fixture.test/callback","scope":"email","prompt":"login",
            }))?,
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
    let managed_query = url::Url::parse(ORIGIN)?
        .join(body(&managed_login)["url"].as_str().unwrap())?
        .query()
        .unwrap()
        .to_owned();
    let issued=Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("email-password","signInEmail").with_body(&json!({
            "email":"oauth-authorization-owner@example.test","password":PASSWORD,"oauth_query":managed_query,
        }))?,
        EndpointOptions{headers:Some([
            ("accept".into(),"application/json".into()),("cookie".into(),cookies(&other)),
            ("origin".into(),ORIGIN.into()),
        ].into_iter().collect()),request:Some(request("/sign-in/email",None,&cookies(&other))),..Default::default()},
    )).await?.into_response()?;
    let callback = url::Url::parse(ORIGIN)?.join(body(&issued)["url"].as_str().unwrap())?;
    assert_eq!(callback.host_str(), Some("app.fixture.test"));
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let identifier = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(code.as_bytes()));
    let proof = auth
        .store()
        .get_verification_by_identifier(&identifier)
        .await?
        .unwrap();
    let payload: Value = serde_json::from_str(proof.value())?;
    let current = Box::pin(call(
        auth,
        request("/get-session", None, &cookies(&issued)),
        200,
    ))
    .await;
    assert_eq!(payload["userId"], body(&owner)["user"]["id"]);
    assert_ne!(payload["userId"], body(&other)["user"]["id"]);
    assert_eq!(payload["sessionId"], body(&current)["session"]["id"]);
    assert_ne!(payload["sessionId"], body(&authenticated)["session"]["id"]);
    Ok(())
}

async fn assert_authorization_admission<S: AuthSchema>(
    auth: &alibi::Alibi<S>,
    db: &Db,
    cookie: &str,
    client: &str,
) -> TestResult {
    for http in [false, true] {
        for (name, value, expected) in [
            (
                "request",
                json!(["first", "second"]),
                Some((
                    "invalid_request",
                    "request must not appear more than once",
                    false,
                )),
            ),
            (
                "request_uri",
                json!(["first", "second"]),
                Some((
                    "invalid_request",
                    "request_uri must not appear more than once",
                    false,
                )),
            ),
            (
                "prompt",
                json!(""),
                Some((
                    "invalid_request",
                    "prompt: prompt must include at least one value",
                    false,
                )),
            ),
            (
                "prompt",
                json!("surprise"),
                Some((
                    "invalid_request",
                    "prompt: unsupported prompt value: surprise",
                    false,
                )),
            ),
            ("prompt", json!("\u{feff}login\u{a0}"), None),
            (
                "code_challenge_method",
                json!(""),
                Some((
                    "invalid_request",
                    "code_challenge_method must be one of: S256",
                    false,
                )),
            ),
            (
                "dpop_jkt",
                json!("bad-value"),
                Some((
                    "invalid_request",
                    "dpop_jkt: dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint",
                    false,
                )),
            ),
            (
                "response_type",
                json!("token"),
                Some((
                    "unsupported_response_type",
                    "response_type must be one of: code",
                    true,
                )),
            ),
        ] {
            let before = db
                .tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?;
            let mut input = json!({"client_id":client,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"prompt-state"});
            input[name] = value.clone();
            let mut physical = request("/oauth2/authorize", None, cookie);
            _ = physical
                .headers
                .insert("accept".into(), "application/json".into());
            let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
            assert_eq!(
                db.tables(&["user", "account", "session", "verification", "oauthClient"])
                    .await?,
                before,
                "http={http}, {name}={value:?}"
            );
            assert_eq!(response.status, 200);
            assert!(!response.headers.contains_key("set-cookie"));
            let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
            let fragment = expected.is_some_and(|(_, _, fragment)| fragment);
            let parameters = if fragment {
                assert!(target.query().is_none());
                target.fragment().expect("fragment error parameters")
            } else {
                assert!(target.fragment().is_none());
                target.query().unwrap_or_default()
            };
            let fields = url::form_urlencoded::parse(parameters.as_bytes())
                .collect::<std::collections::HashMap<_, _>>();
            assert!(!fields.contains_key("code"));
            if let Some((error, description, _)) = expected {
                assert_eq!(target.host_str(), Some("app.fixture.test"));
                assert_eq!(fields.get("error").map(|value| value.as_ref()), Some(error));
                assert_eq!(
                    fields.get("error_description").map(|value| value.as_ref()),
                    Some(description)
                );
                assert_eq!(
                    fields.get("state").map(|value| value.as_ref()),
                    Some("prompt-state")
                );
            } else {
                assert_eq!(target.path(), "/login");
                assert_eq!(fields.get(name).map(|value| value.as_ref()), value.as_str());
            }
        }
        for (mode, destination, status) in [
            ("cors", None, 200),
            ("cors", Some("document"), 200),
            ("same-origin", Some("empty"), 302),
            ("navigate", Some("empty"), 302),
        ] {
            let before = db
                .tables(&["session", "verification", "oauthClient"])
                .await?;
            let input = json!({"client_id":client,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email"});
            let mut physical = request("/oauth2/authorize", None, "");
            _ = physical.headers.insert("accept".into(), "text/html".into());
            _ = physical
                .headers
                .insert("sec-fetch-mode".into(), mode.into());
            if let Some(destination) = destination {
                _ = physical
                    .headers
                    .insert("sec-fetch-dest".into(), destination.into());
            }
            let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
            assert_eq!(
                response.status, status,
                "http={http}, mode={mode}, destination={destination:?}"
            );
            assert!(!response.headers.contains_key("set-cookie"));
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let location = if status == 200 {
                body(&response)["url"].as_str().unwrap().to_owned()
            } else {
                response.headers["location"].clone()
            };
            assert_eq!(url::Url::parse(ORIGIN)?.join(&location)?.path(), "/login");
            assert_eq!(
                db.tables(&["session", "verification", "oauthClient"])
                    .await?,
                before
            );
        }
    }
    Ok(())
}

async fn authorization_response<S: AuthSchema>(
    auth: &Alibi<S>,
    input: &Value,
    mut physical: AuthRequest,
    http: bool,
) -> TestResult<AuthResponse> {
    if http {
        let pairs = input
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
                    .map(|value| (key.clone(), value.as_str().unwrap().to_owned()))
            })
            .collect::<Vec<_>>();
        let mut url = url::Url::parse(&format!("{ORIGIN}/api/auth/oauth2/authorize"))?;
        _ = url.query_pairs_mut().extend_pairs(pairs.clone());
        physical = physical.with_url(url);
        physical.set_query_pairs(pairs);
        return Ok(Box::pin(auth.handle_request(physical)).await?);
    }
    let output = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_authorize_endpoint(input)?,
        EndpointOptions {
            headers: Some(physical.headers.clone()),
            request: Some(physical),
            ..Default::default()
        },
    ))
    .await;
    Ok(match output {
        Ok(output) => output.into_response()?,
        Err(error) => {
            let mut response = alibi::endpoint::EndpointResponse::error(error.error);
            if error.body_absent {
                response = response.without_error_body();
            } else if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()?
        }
    })
}
