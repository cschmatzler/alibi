//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(oauth_protocol_http_forms_deliver_tokens_claims_introspection_and_revocation);
async fn oauth_protocol_http_forms_deliver_tokens_claims_introspection_and_revocation<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "form-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":"client_secret_post","skip_consent":true}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let secret = body(&created)["client_secret"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email profile","state":"token-state","nonce":"oidc-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
    let grant = Box::pin(
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
    assert_eq!(grant.status, 200);
    let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    assert_eq!(callback.path(), "/callback");
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let input = json!({"grant_type":"authorization_code","client_id":id,"client_secret":secret,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let output = call(&auth, form_request("/oauth2/token", &input), 200).await;
    assert_eq!(output.status, 200);
    let token = body(&output);
    assert_eq!(token["scope"], "openid email profile");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());

    let expected = json!({"sub":body(&owner)["user"]["id"],"name":"Native owner","given_name":"Native","family_name":"owner","email":"form-owner@example.test","email_verified":false});
    let mut get = request("/oauth2/userinfo", None, "");
    _ = get
        .headers
        .insert("authorization".into(), format!("Bearer {plaintext}"));
    let info = call(&auth, get, 200).await;
    assert_eq!(body(&info), expected);
    let info = call(
        &auth,
        form_request("/oauth2/userinfo", &json!({"access_token":plaintext})),
        200,
    )
    .await;
    assert_eq!(body(&info), expected);
    let introspection = json!({"client_id":id,"client_secret":secret,"token":plaintext,"token_type_hint":"access_token"});
    let observed = call(
        &auth,
        form_request("/oauth2/introspect", &introspection),
        200,
    )
    .await;
    assert_eq!(body(&observed)["active"], true);
    for (path, input) in [
        ("/oauth2/token", input.clone()),
        ("/oauth2/introspect", introspection.clone()),
        ("/oauth2/revoke", introspection.clone()),
        ("/oauth2/userinfo", json!({"access_token":plaintext})),
    ] {
        let denied = call(&auth, request(path, Some(input), ""), 415).await;
        assert_eq!(
            body(&denied),
            json!({"code":"UNSUPPORTED_MEDIA_TYPE","message":"Content-Type \"application/json\" is not allowed. Allowed types: application/x-www-form-urlencoded"})
        );
    }
    let retired = call(&auth, form_request("/oauth2/revoke", &introspection), 200).await;
    assert!(retired.body.is_empty());
    let inactive = call(
        &auth,
        form_request("/oauth2/introspect", &introspection),
        200,
    )
    .await;
    assert_eq!(body(&inactive), json!({"active":false}));
    let denied = call(
        &auth,
        form_request("/oauth2/userinfo", &json!({"access_token":plaintext})),
        401,
    )
    .await;
    assert_eq!(
        body(&denied),
        json!({"error":"invalid_token","error_description":"Invalid access token"})
    );
    Ok(())
}
fn form_request(path: &str, input: &Value) -> AuthRequest {
    let mut req = request(path, Some(json!({})), "");
    req.body = Some(
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                input
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str().unwrap())),
            )
            .finish()
            .into_bytes(),
    );
    _ = req.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded; charset=UTF-8".into(),
    );
    req
}
