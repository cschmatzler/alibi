//! Authorization emits a bounded signed login query after real client admission.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use alibi::{AuthSession as _, AuthVerification as _};
use base64::Engine;
use sha2::Digest;
const RESERVED_CALLBACK: &str = "https://app.fixture.test/callback?code=stale&keep=first&code=duplicate&state=stale&iss=stale&keep=second";
#[path = "../../../fixtures/oauth/redirect-policy.rs"]
mod redirect_policy;
#[path = "../../../fixtures/oauth/request-uri.rs"]
mod request_uri;
backend_tests!(
    oauth_authorization_resolves_request_uri_before_validation,
    oauth_authorization_admits_client_and_produces_signed_login_redirect
);
async fn oauth_authorization_resolves_request_uri_before_validation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let registry = std::sync::Arc::new(request_uri::RequestRegistry::default());
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    request_uri_resolver: Some(registry.clone()),
                    validate_redirect_uri: Some(registry.clone()),
                    client_discoveries: vec![registry.clone()],
                    ..Default::default()
                },
            ))
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "request-uri-owner@example.test")).await;
    let created = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::create_oauth_client_endpoint(
            &alibi::plugins::oauth_provider::CreateOAuthClientInput {
                client_name: Some("Request registry client".into()),
                redirect_uris: Some(vec!["https://app.fixture.test/callback".into()]),
                scope: Some("email".into()),
                token_endpoint_auth_method: Some("none".into()),
                ..Default::default()
            },
        )?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "request-uri-fixture-verifier-abcdefghijklmnopqrstuvwxyz";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let parameters = json!({
        "client_id":"malicious-client","response_type":"code",
        "redirect_uri":" https://app.fixture.test/callback ","scope":"email","state":"resolved-state",
        "code_challenge":challenge,"code_challenge_method":"S256", "extension_scalar":7
    });
    *registry.parameters.lock().unwrap() = parameters.clone().into();
    let query = json!({"client_id":id,"request_uri":"urn:fixture:valid"});
    let mut physical = request("/oauth2/authorize", None, "");
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    _ = physical
        .headers
        .insert("x-request-uri".into(), "physical".into());
    let response = Box::pin(authorization_response(&auth, &query, physical, false)).await?;
    let login = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
    assert_eq!(login.path(), "/login");
    assert!(
        login
            .query_pairs()
            .any(|(name, value)| name == "client_id" && value == id)
    );
    assert!(
        login
            .query_pairs()
            .any(|(name, value)| name == "state" && value == "resolved-state")
    );
    let calls = registry.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["query"], query);
    assert_eq!(calls[0]["requestHeader"], "physical");
    assert_eq!(
        registry.redirect_calls.lock().unwrap().as_slice(),
        &[json!({
            "uri":"https://app.fixture.test/callback","registered":["https://app.fixture.test/callback"],"defaultResult":true
        })]
    );

    // The signed interaction is produced by authorization, then consumed by
    // genuine login and consent. No grants or sessions are seeded.
    let mut signin = request(
        "/sign-in/email",
        Some(json!({
            "email":"request-uri-owner@example.test","password":PASSWORD,"oauth_query":login.query().unwrap()
        })),
        "",
    );
    _ = signin
        .headers
        .insert("accept".into(), "application/json".into());
    let signed_in = Box::pin(call(&auth, signin, 200)).await;
    let consent = url::Url::parse(ORIGIN)?.join(body(&signed_in)["url"].as_str().unwrap())?;
    assert_eq!(consent.path(), "/consent");
    let cookie = cookies(&signed_in);
    let accepted = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, consent.query())?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
            request: Some(request("/oauth2/consent", None, &cookie)),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let callback = url::Url::parse(body(&accepted)["url"].as_str().unwrap())?;
    assert_eq!(callback.host_str(), Some("app.fixture.test"));
    assert!(
        callback
            .query_pairs()
            .any(|(name, value)| name == "state" && value == "resolved-state")
    );
    let code = callback
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&code));
    let stored = auth
        .store()
        .get_verification_by_identifier(&hash)
        .await?
        .unwrap();
    let grant: Value = serde_json::from_str(stored.value())?;
    let current = Box::pin(call(&auth, request("/get-session", None, &cookie), 200)).await;
    assert_eq!(grant["query"]["client_id"], id);
    assert_eq!(grant["query"]["scope"], "email");
    assert_eq!(grant["query"]["state"], "resolved-state");
    assert_eq!(
        grant["query"]["redirect_uri"],
        "https://app.fixture.test/callback"
    );
    assert_eq!(grant["userId"], body(&owner)["user"]["id"]);
    assert_eq!(grant["sessionId"], body(&current)["session"]["id"]);
    assert_eq!(
        registry.calls.lock().unwrap().len(),
        1,
        "signed continuation must not repeat lookup"
    );

    let other=Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Other registered client","redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"}))?,
        EndpointOptions {headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()},
    )).await?.into_response()?;
    let other_id = body(&other)["client_id"].as_str().unwrap().to_owned();
    let mut different = parameters.clone();
    different["client_id"] = json!(other_id);
    *registry.parameters.lock().unwrap() = different.into();
    for http in [false, true] {
        let mut physical = request("/oauth2/authorize", None, "");
        _ = physical
            .headers
            .insert("accept".into(), "application/json".into());
        let response = Box::pin(authorization_response(&auth, &query, physical, http)).await?;
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        assert!(
            target
                .query_pairs()
                .any(|(name, value)| name == "client_id" && value == id)
        );
    }
    *registry.parameters.lock().unwrap() = parameters.clone().into();

    let protected = db
        .tables(&[
            "user",
            "account",
            "session",
            "verification",
            "oauthClient",
            "oauthConsent",
        ])
        .await?;
    // Original unknown values and max_age must be discarded, including the
    // separately preserved nonfinite extension values used by signed queries.
    let poisoned = alibi::utils::json::parse_value(&format!(
        r#"{{"client_id":{},"request_uri":"urn:fixture:valid","max_age":1e400,"scope":42,"redirect_uri":"https://evil.fixture.test","state":"outer","extension_scalar":1e400,"outer_only":true}}"#,
        serde_json::to_string(&id)?
    ))?;
    let clean = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize")
                .with_query_value(poisoned),
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
    let clean = url::Url::parse(ORIGIN)?.join(body(&clean)["url"].as_str().unwrap())?;
    assert_eq!(clean.path(), "/login");
    assert!(
        clean
            .query_pairs()
            .any(|(name, value)| name == "extension_scalar" && value == "7")
    );
    assert!(
        !clean
            .query_pairs()
            .any(|(name, _)| matches!(name.as_ref(), "outer_only" | "max_age" | "request_uri"))
    );
    let mut physical = request("/oauth2/authorize", None, "");
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    let nonfinite = Box::pin(authorization_response(
        &auth,
        &json!({"client_id":id,"request_uri":"urn:fixture:nonfinite","extension_scalar":"outer"}),
        physical,
        false,
    ))
    .await?;
    let nonfinite = url::Url::parse(ORIGIN)?.join(body(&nonfinite)["url"].as_str().unwrap())?;
    assert_eq!(nonfinite.path(), "/login");
    assert!(
        nonfinite
            .query_pairs()
            .any(|(name, value)| name == "extension_scalar" && value == "Infinity")
    );
    assert!(
        nonfinite
            .query_pairs()
            .any(|(name, value)| name == "extension_array" && value == "-Infinity")
    );

    for http in [false, true] {
        for (input, resolved, error, state, host, calls) in [
            (
                json!({"client_id":id,"request_uri":"urn:fixture:expired","redirect_uri":"https://app.fixture.test/callback","state":"original","response_mode":"fragment"}),
                parameters.clone(),
                "invalid_request_uri",
                Some("original"),
                "app.fixture.test",
                1,
            ),
            (
                json!({"client_id":id,"request_uri":"urn:fixture:expired","redirect_uri":" https://app.fixture.test/callback ","state":"original"}),
                parameters.clone(),
                "invalid_request_uri",
                None,
                "localhost",
                1,
            ),
            (
                json!({"client_id":id,"request_uri":"urn:fixture:valid","request":""}),
                parameters.clone(),
                "invalid_request",
                None,
                "localhost",
                0,
            ),
            (
                json!({"client_id":id,"request":""}),
                parameters.clone(),
                "request_not_supported",
                None,
                "localhost",
                0,
            ),
            (
                json!({"request_uri":"urn:fixture:valid"}),
                parameters.clone(),
                "invalid_request",
                None,
                "localhost",
                0,
            ),
            (
                json!({"client_id":"","request_uri":"urn:fixture:valid"}),
                parameters.clone(),
                "invalid_request",
                None,
                "localhost",
                0,
            ),
            (
                json!({"client_id":id,"request_uri":["one","two"]}),
                parameters.clone(),
                "invalid_request",
                None,
                "localhost",
                0,
            ),
            (
                query.clone(),
                json!({"scope":42,"state":"resolved-error","redirect_uri":"https://app.fixture.test/callback"}),
                "invalid_request",
                Some("resolved-error"),
                "app.fixture.test",
                1,
            ),
            (
                query.clone(),
                json!({"scope":42,"state":"resolved-error","redirect_uri":" https://app.fixture.test/callback "}),
                "invalid_request",
                None,
                "localhost",
                1,
            ),
            (
                query.clone(),
                json!({"max_age":"bad","state":"resolved-max-age","redirect_uri":"https://app.fixture.test/callback"}),
                "invalid_request",
                Some("resolved-max-age"),
                "app.fixture.test",
                1,
            ),
            (
                json!({"client_id":id,"request_uri":"urn:fixture:invalid-max-age","max_age":"0"}),
                json!({"response_type":"code","scope":"email","state":"resolved-state","redirect_uri":"https://app.fixture.test/callback"}),
                "invalid_request",
                Some("resolved-state"),
                "app.fixture.test",
                1,
            ),
        ] {
            *registry.parameters.lock().unwrap() = resolved.into();
            registry.calls.lock().unwrap().clear();
            let mut physical = request("/oauth2/authorize", None, &cookie);
            _ = physical
                .headers
                .insert("accept".into(), "application/json".into());
            let response = Box::pin(authorization_response(&auth, &input, physical, http)).await?;
            let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
            assert_eq!(target.host_str(), Some(host), "{input}, http={http}");
            let fields = url::form_urlencoded::parse(
                target
                    .fragment()
                    .or(target.query())
                    .unwrap_or_default()
                    .as_bytes(),
            )
            .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(fields.get("error").map(|value| value.as_ref()), Some(error));
            assert_eq!(fields.get("state").map(|value| value.as_ref()), state);
            assert_eq!(registry.calls.lock().unwrap().len(), calls);
            assert_eq!(
                db.tables(&[
                    "user",
                    "account",
                    "session",
                    "verification",
                    "oauthClient",
                    "oauthConsent"
                ])
                .await?,
                protected
            );
        }
    }
    for input in [
        json!({"client_id":42,"request_uri":"urn:fixture:valid"}),
        json!({"client_id":id,"request_uri":42}),
        json!({"client_id":id,"request":42}),
    ] {
        registry.calls.lock().unwrap().clear();
        let mut physical = request("/oauth2/authorize", None, "");
        _ = physical
            .headers
            .insert("accept".into(), "application/json".into());
        let response = Box::pin(authorization_response(&auth, &input, physical, false)).await?;
        assert!(
            body(&response)["url"]
                .as_str()
                .unwrap()
                .contains("invalid_request")
        );
        assert!(registry.calls.lock().unwrap().is_empty());
    }
    *registry.parameters.lock().unwrap() = parameters.clone().into();
    for (uri, status) in [("urn:fixture:throw", 500), ("urn:fixture:api-error", 429)] {
        let failure=Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider","oauth2Authorize").with_query(&json!({"client_id":id,"request_uri":uri,"redirect_uri":"https://app.fixture.test/callback"}))?,
            EndpointOptions { request:Some(request("/oauth2/authorize",None,&cookie)),..Default::default() },
        )).await.unwrap_err();
        assert_eq!(failure.error.status_code(), status);
        let wire = failure.error.to_auth_response();
        assert_eq!(wire.body.is_empty(), status == 500);
        if status == 429 {
            assert_eq!(
                body(&wire),
                json!({"code":"REQUEST_LOOKUP_LIMIT","message":"Request lookup limited"})
            );
        }
        assert!(
            failure
                .headers
                .as_ref()
                .is_none_or(|headers| !headers.contains_key("location"))
        );
        assert_eq!(
            db.tables(&[
                "user",
                "account",
                "session",
                "verification",
                "oauthClient",
                "oauthConsent"
            ])
            .await?,
            protected
        );
    }
    // Resolved reserved fields are schema data, not a second dispatch.
    let mut reserved = parameters.clone();
    reserved["request"] = json!("");
    reserved["request_uri"] = json!("urn:fixture:throw");
    *registry.parameters.lock().unwrap() = reserved.into();
    registry.calls.lock().unwrap().clear();
    let mut physical = request("/oauth2/authorize", None, "");
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    let response = Box::pin(authorization_response(&auth, &query, physical, false)).await?;
    assert_eq!(
        url::Url::parse(ORIGIN)?
            .join(body(&response)["url"].as_str().unwrap())?
            .path(),
        "/login"
    );
    assert_eq!(registry.calls.lock().unwrap().len(), 1);

    // Discovery receives parsed effective data but the genuine physical URL.
    *registry.parameters.lock().unwrap() = parameters.clone().into();
    registry.calls.lock().unwrap().clear();
    let mut physical = request("/oauth2/authorize", None, "").with_url(url::Url::parse(&format!(
        "{ORIGIN}/api/auth/oauth2/authorize?physical=original"
    ))?);
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    let response = Box::pin(authorization_response(
        &auth,
        &json!({"client_id":"resolver-unknown","request_uri":"urn:fixture:valid"}),
        physical,
        false,
    ))
    .await?;
    assert!(
        body(&response)["url"]
            .as_str()
            .unwrap()
            .contains("invalid_client")
    );
    let events = registry.calls.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["stage"], "discovery");
    assert_eq!(events[1]["query"]["client_id"], "resolver-unknown");
    assert_eq!(
        events[1]["query"]["redirect_uri"],
        "https://app.fixture.test/callback"
    );
    assert_eq!(events[1]["query"]["state"], "resolved-state");
    assert!(
        events[1]["requestURL"]
            .as_str()
            .unwrap()
            .ends_with("?physical=original")
    );

    let unsupported = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::new())
            .build(),
    )
    .await?;
    let mut physical = request("/oauth2/authorize", None, "");
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    let rejected=Box::pin(authorization_response(&unsupported,&json!({"client_id":id,"request_uri":"urn:fixture:valid","redirect_uri":"https://app.fixture.test/callback"}),physical,false)).await?;
    assert!(
        body(&rejected)["url"]
            .as_str()
            .unwrap()
            .contains("request_uri_not_supported")
    );
    assert_eq!(
        db.tables(&[
            "user",
            "account",
            "session",
            "verification",
            "oauthClient",
            "oauthConsent"
        ])
        .await?,
        protected
    );

    // A genuine token exchange consumes the code after every rejected request
    // has been shown not to mutate its session/client/grant bindings.
    let token_input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"redirect_uri":"https://app.fixture.test/callback","code_verifier":verifier});
    let token = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&token_input)?,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(token_input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(token.status, 200);
    assert_eq!(body(&token)["scope"], "email");
    assert!(
        body(&token)["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        auth.store()
            .get_verification_by_identifier(&hash)
            .await?
            .is_none()
    );
    Ok(())
}
async fn oauth_authorization_admits_client_and_produces_signed_login_redirect<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = Box::pin(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::new())
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "oauth-authorization-owner@example.test")).await;
    let created = Box::pin(auth.dispatch_endpoint(
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
    ))
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
    let output = Box::pin(
        auth.dispatch_endpoint(
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
        ),
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
        let r = Box::pin(
            auth.dispatch_endpoint(
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
            ),
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
    let missing = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize").with_query(&input)?,
            EndpointOptions {
                headers: Some(
                    [("accept".into(), "application/json".into())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
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
        let rejected = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("email-password", operation).with_body(&input)?,
            EndpointOptions::default(),
        ))
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
        let rejected = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("email-password", "signInEmail").with_body(&input)?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 401);
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?,
            protected
        );
    }

    let managed=auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"client_name":"Code client","redirect_uris":["https://app.fixture.test/callback",RESERVED_CALLBACK],"scope":"email","skip_consent":true,"require_pkce":false}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
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
    Box::pin(assert_loopback_authorization(&auth, &db, &cookies(&owner))).await?;
    Box::pin(assert_authorization_schema(
        &auth,
        &db,
        &cookies(&owner),
        body(&managed)["client_id"].as_str().unwrap(),
    ))
    .await?;
    Box::pin(assert_nonfinite_authorization(
        &auth,
        &cookies(&owner),
        body(&managed)["client_id"].as_str().unwrap(),
        body(&owner)["user"]["id"].as_str().unwrap(),
    ))
    .await?;
    Box::pin(assert_signed_login_resumes(
        &auth, &owner, &managed, &signed, &id,
    ))
    .await?;
    let (policy_auth, policy) = Box::pin(configured_redirect_policy::<B>(&connection)).await?;
    let (variants, session_id) = Box::pin(redirect_policy_controls(&policy_auth, &owner)).await?;
    Box::pin(assert_redirect_policy(
        &policy_auth,
        &db,
        &owner,
        &managed,
        &policy,
        &variants,
        &session_id,
    ))
    .await?;
    Box::pin(
        super::oauth_authorization_signup::assert_signup_policy::<B>(
            &connection,
            &owner,
            &managed,
            &session_id,
        ),
    )
    .await?;
    Box::pin(
        super::oauth_authorization_post_login::assert_post_login_policy::<B>(
            &connection,
            &owner,
            &managed,
            &session_id,
            &id,
        ),
    )
    .await?;
    Ok(())
}

async fn configured_redirect_policy<B: Backend>(
    connection: &B::Connection,
) -> TestResult<(Alibi<B::Schema>, Arc<redirect_policy::RedirectPolicy>)> {
    let policy = Arc::new(redirect_policy::RedirectPolicy::default());
    let policy_auth = Box::pin(
        super::auth_probe::fast_builder::<B>(connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    validate_redirect_uri: Some(policy.clone()),
                    ..Default::default()
                },
            ))
            .build(),
    )
    .await?;
    Ok((policy_auth, policy))
}

async fn redirect_policy_controls<S: AuthSchema>(
    auth: &Alibi<S>,
    owner: &AuthResponse,
) -> TestResult<(Vec<String>, String)> {
    let cookie = cookies(owner);
    let registered = json!(["https://app.fixture.test/callback", RESERVED_CALLBACK]);
    let mut variants = Vec::new();
    for patch in [
        json!({"disabled":true}),
        json!({"grant_types":["refresh_token"],"response_types":[]}),
    ] {
        let mut input = json!({"client_name":"Redirect control","redirect_uris":registered,"scope":"email","skip_consent":true,"require_pkce":false});
        input
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        let created = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::admin_create_oauth_client_endpoint(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 201);
        let id = body(&created)["client_id"].as_str().unwrap().to_owned();
        if patch["disabled"] == true {
            // Disabled state is persisted by the operator, not create input.
            let mut stored = Box::pin(auth.store().get_oauth_client(&id)).await?.unwrap();
            stored.metadata["disabled"] = json!(true);
            _ = Box::pin(auth.store().update_oauth_client_metadata(
                &id,
                stored.metadata,
                chrono::Utc::now(),
            ))
            .await?;
        }
        variants.push(id);
    }
    let session = Box::pin(
        auth.store()
            .get_session(body(owner)["token"].as_str().unwrap()),
    )
    .await?
    .unwrap();
    Ok((variants, session.id().as_ref().to_owned()))
}

async fn assert_redirect_policy<S: AuthSchema>(
    auth: &Alibi<S>,
    db: &Db,
    owner: &AuthResponse,
    managed: &AuthResponse,
    policy: &redirect_policy::RedirectPolicy,
    variants: &[String],
    session_id: &str,
) -> TestResult {
    let cookie = cookies(owner);
    let client = body(managed)["client_id"].as_str().unwrap().to_owned();
    let registered = json!(["https://app.fixture.test/callback", RESERVED_CALLBACK]);
    let preview = "https://preview.fixture.test/callback";
    for http in [false, true] {
        // (patch, raw URI, error or code, trusted error, fragment, callback, built-in result)
        for (patch, uri, error, trusted, fragment, called, default_result) in [
            (json!({}), preview, None, false, false, true, false),
            (
                json!({}),
                "\u{feff} https://preview.fixture.test/callback \u{a0}",
                None,
                false,
                false,
                true,
                false,
            ),
            (
                json!({}),
                "https://preview.fixture.test/a/../callback",
                None,
                false,
                false,
                true,
                false,
            ),
            (json!({}), RESERVED_CALLBACK, None, false, false, true, true),
            (
                json!({}),
                "https://app.fixture.test/callback",
                Some("invalid_redirect"),
                false,
                false,
                true,
                true,
            ),
            (
                json!({}),
                "https://throw.fixture.test/callback",
                Some("invalid_redirect"),
                false,
                false,
                true,
                false,
            ),
            (
                json!({}),
                "https://user:pass@preview.fixture.test/callback",
                Some("invalid_redirect"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                preview,
                Some("unsupported_response_type"),
                true,
                true,
                true,
                false,
            ),
            (
                json!({"prompt":"surprise","response_mode":"query"}),
                preview,
                Some("invalid_request"),
                true,
                false,
                true,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "https://app.fixture.test/callback",
                Some("unsupported_response_type"),
                false,
                false,
                true,
                true,
            ),
            (
                json!({"response_type":"token"}),
                "https://throw.fixture.test/callback",
                Some("unsupported_response_type"),
                false,
                false,
                true,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "https://:pass@preview.fixture.test/callback",
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                " https://preview.fixture.test/callback",
                Some("unsupported_response_type"),
                true,
                true,
                true,
                false,
            ),
            (
                json!({"request":"","response_mode":"fragment"}),
                preview,
                Some("request_not_supported"),
                true,
                true,
                true,
                false,
            ),
            (
                json!({"client_id":variants[1]}),
                preview,
                Some("unauthorized_client"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"client_id":variants[1],"response_type":"token"}),
                preview,
                Some("unsupported_response_type"),
                true,
                true,
                true,
                false,
            ),
            (
                json!({"client_id":variants[0]}),
                preview,
                Some("client_disabled"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"client_id":variants[0],"response_type":"token"}),
                preview,
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"client_id":"unknown-redirect-client"}),
                preview,
                Some("invalid_client"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"client_id":format!(" {client}"),"response_type":"token"}),
                preview,
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"prompt":"select_account"}),
                preview,
                Some("unsupported_prompt_select_account"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "https://user:pass@preview.fixture.test/callback",
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "https://preview.fixture.test/callback#",
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "javascript:preview.fixture.test",
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "http://preview.fixture.test/callback",
                Some("unsupported_response_type"),
                false,
                false,
                false,
                false,
            ),
            (
                json!({"response_type":"token"}),
                "\u{feff}https://preview.fixture.test/callback",
                Some("raw_url_error"),
                false,
                false,
                false,
                false,
            ),
        ] {
            let before = db
                .tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?;
            let mut input = json!({"client_id":client,"response_type":"code","redirect_uri":uri,"scope":"email","state":"policy-state"});
            input
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let mut physical = request("/oauth2/authorize", None, &cookie);
            _ = physical
                .headers
                .insert("accept".into(), "application/json".into());
            let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
            let callback_uri = if error.is_none() && uri.starts_with('\u{feff}') {
                preview
            } else {
                uri
            };
            let calls = std::mem::take(&mut *policy.calls.lock().unwrap());
            assert_eq!(
                calls,
                if called {
                    vec![
                        json!({"uri":callback_uri,"registered":registered,"defaultResult":default_result}),
                    ]
                } else {
                    vec![]
                },
                "http={http}, input={input}"
            );
            assert!(!response.headers.contains_key("set-cookie"));
            if error == Some("raw_url_error") {
                assert_eq!(response.status, 500);
                assert_eq!(
                    db.tables(&["user", "account", "session", "verification", "oauthClient"])
                        .await?,
                    before
                );
                continue;
            }
            assert_eq!(response.status, 200);
            let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
            if let Some(error) = error {
                assert_eq!(target.fragment().is_some(), fragment);
                let fields = url::form_urlencoded::parse(
                    if fragment {
                        target.fragment().unwrap()
                    } else {
                        target.query().unwrap()
                    }
                    .as_bytes(),
                )
                .collect::<std::collections::HashMap<_, _>>();
                assert_eq!(fields["error"], error);
                assert!(!fields.contains_key("code"));
                if trusted {
                    assert_eq!(target.host_str(), Some("preview.fixture.test"));
                    assert_eq!(fields["state"], "policy-state");
                    assert_eq!(fields["iss"], format!("{ORIGIN}/api/auth"));
                } else {
                    assert_eq!(target.path(), "/api/auth/error");
                    assert!(!fields.contains_key("state"));
                    assert!(!fields.contains_key("iss"));
                }
                assert_eq!(
                    db.tables(&["user", "account", "session", "verification", "oauthClient"])
                        .await?,
                    before
                );
            } else {
                assert_eq!(target.origin(), url::Url::parse(callback_uri)?.origin());
                let fields = target
                    .query_pairs()
                    .collect::<std::collections::HashMap<_, _>>();
                let code = &fields["code"];
                assert_eq!(code.len(), 32);
                assert!(code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                assert_eq!(fields["state"], "policy-state");
                assert_eq!(fields["iss"], format!("{ORIGIN}/api/auth"));
                let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(code.as_bytes()));
                let stored = Box::pin(auth.store().get_verification_by_identifier(&hash))
                    .await?
                    .unwrap();
                let grant: Value = serde_json::from_str(stored.value())?;
                assert_eq!(grant["query"]["redirect_uri"], callback_uri);
                assert_eq!(grant["query"]["client_id"], client);
                assert_eq!(grant["query"]["state"], "policy-state");
                assert_eq!(grant["userId"], body(owner)["user"]["id"]);
                assert_eq!(grant["sessionId"], session_id);
            }
        }
    }
    let input = json!({"client_id":[client],"response_type":"token","redirect_uri":preview,"state":"policy-state"});
    let before = db
        .tables(&["user", "account", "session", "verification", "oauthClient"])
        .await?;
    let mut physical = request("/oauth2/authorize", None, &cookie);
    _ = physical
        .headers
        .insert("accept".into(), "application/json".into());
    let response = Box::pin(authorization_response(auth, &input, physical, false)).await?;
    let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
    assert_eq!(target.path(), "/api/auth/error");
    assert!(policy.calls.lock().unwrap().is_empty());
    assert_eq!(
        db.tables(&["user", "account", "session", "verification", "oauthClient"])
            .await?,
        before
    );
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
                "resource",
                json!("relative"),
                Some(("invalid_request", "resource: Invalid input", true)),
            ),
            (
                "resource",
                json!("https://api.fixture.test/#"),
                Some((
                    "invalid_request",
                    "resource: resource must not contain a fragment",
                    true,
                )),
            ),
            (
                "resource",
                json!("data:,literal"),
                Some((
                    "invalid_request",
                    "resource: resource cannot use javascript:, data:, or vbscript: scheme",
                    true,
                )),
            ),
            (
                "resource",
                json!([
                    "https://api.fixture.test/valid",
                    "https://api.fixture.test/#"
                ]),
                Some((
                    "invalid_request",
                    "resource[1]: resource must not contain a fragment",
                    true,
                )),
            ),
            (
                "resource",
                json!([]),
                Some((
                    "invalid_request",
                    "resource: Too small: expected array to have >=1 items",
                    true,
                )),
            ),
            (
                "resource",
                json!([42]),
                Some(("invalid_request", "resource: Invalid input", true)),
            ),
            (
                "resource",
                json!(42),
                Some(("invalid_request", "resource: Invalid input", true)),
            ),
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
            if http
                && !value.is_string()
                && !value
                    .as_array()
                    .is_some_and(|values| values.len() > 1 && values.iter().all(Value::is_string))
            {
                continue;
            }
            let before = db
                .tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?;
            let mut input = json!({"client_id":client,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"prompt-state"});
            input[name] = value.clone();
            if name == "resource" {
                input["response_mode"] = json!("fragment");
                if value == json!("relative") {
                    input["prompt"] = json!("select_account");
                }
            }
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
        let input = json!({"client_id":client,"response_type":"code","redirect_uri":RESERVED_CALLBACK,"scope":"email","state":"code-state"});
        let mut physical = request("/oauth2/authorize", None, cookie);
        _ = physical
            .headers
            .insert("accept".into(), "application/json".into());
        let before = db.count("verification").await?;
        let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(body(&response)["url"].as_str().unwrap())?;
        let fields = |name: &str| {
            target
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>()
        };
        let codes = fields("code");
        assert_eq!(codes.len(), 1, "http={http}");
        assert_eq!(codes[0].len(), 32);
        assert!(codes[0].bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(fields("state"), ["code-state"]);
        assert_eq!(fields("iss"), [format!("{ORIGIN}/api/auth")]);
        assert_eq!(fields("keep"), ["first", "second"]);
        assert_eq!(db.count("verification").await?, before + 1);
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(codes[0].as_bytes()));
        let stored = auth
            .store()
            .get_verification_by_identifier(&hash)
            .await?
            .unwrap();
        let grant: Value = serde_json::from_str(stored.value())?;
        assert_eq!(grant["query"]["redirect_uri"], RESERVED_CALLBACK);
        assert_eq!(grant["query"]["state"], "code-state");
    }
    Ok(())
}

async fn assert_nonfinite_authorization<S: AuthSchema>(
    auth: &Alibi<S>,
    cookie: &str,
    client: &str,
    owner: &str,
) -> TestResult {
    let base=json!({"client_id":client,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"nonfinite-state"}).to_string();
    let raw = format!(
        "{},\"extension_scalar\":1e400,\"extension_array\":[1e400,[1e400]],\"exp\":1e400}}",
        base.strip_suffix('}').unwrap()
    );
    for authenticated in [false, true] {
        let mut physical = request(
            "/oauth2/authorize",
            Some(json!({})),
            if authenticated { cookie } else { "" },
        );
        physical.body = Some(raw.as_bytes().to_vec());
        _ = physical.headers.insert(
            "content-type".into(),
            "application/jsonapplication/x-www-form-urlencoded".into(),
        );
        _ = physical
            .headers
            .insert("accept".into(), "application/json".into());
        let response = Box::pin(auth.handle_request(physical)).await?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        let target = if !authenticated {
            assert_eq!(target.path(), "/login");
            assert!(
                target
                    .query_pairs()
                    .find(|(key, _)| key == "exp")
                    .unwrap()
                    .1
                    .parse::<f64>()?
                    .is_finite()
            );
            let mut signin = request(
                "/sign-in/email",
                Some(
                    json!({"email":"oauth-authorization-owner@example.test","password":PASSWORD,"oauth_query":target.query().unwrap()}),
                ),
                "",
            );
            _ = signin
                .headers
                .insert("accept".into(), "application/json".into());
            let resumed = Box::pin(call(auth, signin, 200)).await;
            url::Url::parse(ORIGIN)?.join(body(&resumed)["url"].as_str().unwrap())?
        } else {
            target
        };
        let code = target
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(code.as_bytes()));
        let stored = auth
            .store()
            .get_verification_by_identifier(&hash)
            .await?
            .unwrap();
        let grant: Value = serde_json::from_str(stored.value())?;
        assert_eq!(grant["userId"], owner);
        assert_eq!(grant["query"]["client_id"], client);
        if authenticated {
            assert_eq!(grant["query"]["extension_scalar"], Value::Null);
            assert_eq!(grant["query"]["extension_array"], json!([null, [null]]));
            assert_eq!(grant["query"]["exp"], Value::Null);
        } else {
            assert_eq!(grant["query"]["extension_scalar"], "Infinity");
            assert_eq!(
                grant["query"]["extension_array"],
                json!(["Infinity", "Infinity"])
            );
            assert!(grant["query"].get("exp").is_none());
        }
    }
    Ok(())
}

async fn assert_authorization_schema<S: AuthSchema>(
    auth: &Alibi<S>,
    db: &Db,
    cookie: &str,
    client: &str,
) -> TestResult {
    for http in [false, true] {
        let mut physical = request("/oauth2/authorize", None, cookie);
        _ = physical
            .headers
            .insert("accept".into(), "application/json".into());
        let query = json!({"client_id":client,"response_type":"code","redirect_uri":"\u{feff} https://app.fixture.test/callback \u{a0}","scope":"email","state":"schema-state"});
        let response = Box::pin(authorization_response(auth, &query, physical, http)).await?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(
            target.host_str(),
            Some("app.fixture.test"),
            "parsed redirect http={http}"
        );
        let code = target
            .query_pairs()
            .find(|(name, _)| name == "code")
            .unwrap()
            .1
            .into_owned();
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(code.as_bytes()));
        let stored = auth
            .store()
            .get_verification_by_identifier(&hash)
            .await?
            .unwrap();
        let grant: Value = serde_json::from_str(stored.value())?;
        assert_eq!(
            grant["query"]["redirect_uri"],
            "https://app.fixture.test/callback"
        );
        assert_eq!(grant["query"]["state"], "schema-state");
        for (patch, error, description, trusted) in [
            (
                json!({"redirect_uri":"http://localhost./callback"}),
                "invalid_redirect",
                "invalid redirect uri",
                false,
            ),
            (
                json!({"redirect_uri":"http://[::ffff:127.0.0.1]/callback"}),
                "invalid_redirect",
                "invalid redirect uri",
                false,
            ),
            (
                json!({"response_type":""}),
                "unsupported_response_type",
                "response_type must be one of: code",
                true,
            ),
            (
                json!({"code_challenge_method":"plain","dpop_jkt":"bad-value"}),
                "invalid_request",
                "code_challenge_method must be one of: S256",
                true,
            ),
            (
                json!({"redirect_uri":"relative","prompt":"select_account"}),
                "invalid_request",
                "redirect_uri: Invalid URL",
                false,
            ),
            (
                json!({"client_id":"","prompt":"surprise"}),
                "invalid_request",
                "client_id: client_id is required",
                false,
            ),
            (
                json!({"prompt":"surprise","display":42}),
                "invalid_request",
                "prompt: unsupported prompt value: surprise",
                true,
            ),
            (
                json!({"claims":null}),
                "invalid_request",
                "claims: Invalid input",
                true,
            ),
        ] {
            if http && !patch.as_object().unwrap().values().all(Value::is_string) {
                continue;
            }
            let before = db
                .tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?;
            let mut input = json!({"client_id":client,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"schema-state","response_mode":"fragment"});
            input.as_object_mut().unwrap().extend(
                patch
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            let mut physical = request("/oauth2/authorize", None, cookie);
            _ = physical
                .headers
                .insert("accept".into(), "application/json".into());
            let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
            assert_eq!(response.status, 200);
            assert!(!response.headers.contains_key("set-cookie"));
            let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
            let parameters = if trusted {
                target.fragment().unwrap()
            } else {
                assert!(target.fragment().is_none());
                target.query().unwrap()
            };
            let fields = url::form_urlencoded::parse(parameters.as_bytes())
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(fields["error"], error, "http={http}, patch={patch}");
            assert_eq!(
                fields["error_description"], description,
                "http={http}, patch={patch}"
            );
            assert!(!fields.contains_key("code"));
            assert_eq!(
                db.tables(&["user", "account", "session", "verification", "oauthClient"])
                    .await?,
                before
            );
        }
    }
    Ok(())
}

async fn assert_loopback_authorization<S: AuthSchema>(
    auth: &Alibi<S>,
    db: &Db,
    cookie: &str,
) -> TestResult {
    let created=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"client_name":"Loopback client","redirect_uris":["http://localhost:1234/callback","http://127.0.0.1:1234/callback","http://[::1]:1234/callback"],"application_type":"native","scope":"email","skip_consent":true,"require_pkce":false}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.into())].into_iter().collect()),..Default::default()})).await?.into_response()?;
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    for http in [false, true] {
        for (redirect, allowed) in [
            ("http://localhost:5678/callback", true),
            ("http://127.0.0.1:5678/callback", true),
            ("http://[::1]:5678/callback", true),
            ("http://LOCALHOST:5678/callback", false),
            ("http://127.1:5678/callback", false),
            ("http://127.0.0.1:5678/other/../callback", false),
        ] {
            let before = db
                .tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?;
            let input = json!({"client_id":id,"response_type":"code","redirect_uri":redirect,"scope":"email","state":"loopback-state"});
            let mut physical = request("/oauth2/authorize", None, cookie);
            _ = physical
                .headers
                .insert("accept".into(), "application/json".into());
            let response = Box::pin(authorization_response(auth, &input, physical, http)).await?;
            assert_eq!(response.status, 200);
            assert!(!response.headers.contains_key("set-cookie"));
            let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
            let fields = target
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            if allowed {
                assert_eq!(target.origin(), url::Url::parse(redirect)?.origin());
                assert_eq!(target.path(), "/callback");
                assert_eq!(fields["code"].len(), 32);
                assert_eq!(fields["state"], "loopback-state");
                let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(fields["code"].as_bytes()));
                let stored = auth
                    .store()
                    .get_verification_by_identifier(&hash)
                    .await?
                    .unwrap();
                let grant: Value = serde_json::from_str(stored.value())?;
                assert_eq!(grant["query"]["client_id"], id);
                assert_eq!(grant["query"]["redirect_uri"], redirect);
            } else {
                assert_eq!(
                    target.path(),
                    "/api/auth/error",
                    "http={http}, redirect={redirect}"
                );
                assert_eq!(fields["error"], "invalid_redirect");
                assert!(!fields.contains_key("code"));
                assert!(!fields.contains_key("state"));
                assert!(!fields.contains_key("iss"));
                assert_eq!(
                    db.tables(&["user", "account", "session", "verification", "oauthClient"])
                        .await?,
                    before
                );
            }
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
