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
    let input = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"caller-state","code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
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
    Ok(())
}
