//! SSO authorization uses the durable provider and emits redeemable PKCE state.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::SsoPlugin;
use alibi::{AuthVerification, store::VerificationStore};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(sso_sign_in_uses_registered_provider_and_binds_pkce_state);
async fn sso_sign_in_uses_registered_provider_and_binds_pkce_state<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-signin-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"signin-provider","issuer":"https://idp.example.com","domain":"company.com,subsidiary.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"scopes":["openid","email"],"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 200);
    let input = json!({"providerId":"signin-provider","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed"),"loginHint":"employee@company.com","scopes":["openid","profile"]});
    let response = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::sign_in_sso_endpoint(&input)?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(response.status, 200);
    let data = body(&response);
    assert_eq!(data["redirect"], true);
    let url = url::Url::parse(data["url"].as_str().unwrap())?;
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://idp.example.com"
    );
    assert_eq!(url.path(), "/authorize");
    let params: std::collections::HashMap<String, String> =
        url.query_pairs().into_owned().collect();
    assert_eq!(params["client_id"], "enterprise-client");
    assert_eq!(
        params["redirect_uri"],
        format!("{ORIGIN}/api/auth/sso/callback/signin-provider")
    );
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["scope"], "openid profile");
    assert_eq!(params["login_hint"], "employee@company.com");
    assert_eq!(params["code_challenge_method"], "S256");
    let state = &params["state"];
    let proof = store
        .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
        .await?
        .ok_or("SSO authorization state was not persisted")?;
    let payload: Value = serde_json::from_str(proof.value())?;
    assert_eq!(payload["callbackURL"], input["callbackURL"]);
    assert_eq!(payload["errorURL"], input["errorCallbackURL"]);
    assert_eq!(payload["oauthState"], *state);
    let verifier = payload["codeVerifier"].as_str().unwrap();
    assert_eq!(verifier.len(), 128);
    assert_eq!(
        params["code_challenge"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()))
    );
    assert_eq!(
        payload["serverContext"]["ssoProviderReference"]["providerId"],
        "signin-provider"
    );
    assert_eq!(
        payload["serverContext"]["ssoProviderReference"]["source"]["recordId"],
        body(&created)["id"]
    );
    assert_eq!(
        payload["serverContext"]["ssoProviderReference"]["source"]["type"],
        "persisted"
    );
    let canonical_configuration = r#"{"domain":"company.com,subsidiary.com","issuer":"https://idp.example.com","oidcConfig":{"authorizationEndpoint":"https://idp.example.com/authorize","clientId":"enterprise-client","discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration","issuer":"https://idp.example.com","jwksEndpoint":"https://idp.example.com/jwks","overrideUserInfo":false,"pkce":true,"scopes":["openid","email"],"tokenEndpoint":"https://idp.example.com/token","tokenEndpointAuthentication":"client_secret_basic"},"organizationId":null}"#;
    assert_eq!(
        payload["serverContext"]["ssoProviderReference"]["authenticationConfigurationFingerprint"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(canonical_configuration.as_bytes()))
    );
    assert!(proof.expires_at() > chrono::Utc::now() + chrono::Duration::minutes(9));
    assert!(proof.expires_at() <= chrono::Utc::now() + chrono::Duration::minutes(10));
    let cookie = response
        .headers
        .get_all("set-cookie")
        .next()
        .ok_or("SSO state cookie absent")?;
    assert!(cookie.starts_with("better-auth.state="));
    assert!(cookie.contains("Max-Age=300"));
    use hkdf::hmac::{Hmac, KeyInit, Mac};
    let signed = urlencoding_for_state_cookie(cookie)?;
    let (cookie_state, signature) = signed
        .rsplit_once('.')
        .ok_or("State cookie has no signature")?;
    assert_eq!(cookie_state, state);
    let signature = base64::engine::general_purpose::STANDARD.decode(signature)?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes())?;
    mac.update(state.as_bytes());
    mac.verify_slice(&signature)?;
    for selector in [
        json!({"domain":" engineering.COMPANY.com "}),
        json!({"email":"employee@engineering.subsidiary.com"}),
        json!({"domain":"COMPANY.COM"}),
    ] {
        let selected = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::sign_in_sso_endpoint(&{
                let mut value = selector;
                value["callbackURL"] = input["callbackURL"].clone();
                value
            })?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        assert_eq!(selected.status, 200);
        let selected_url = url::Url::parse(body(&selected)["url"].as_str().unwrap())?;
        assert_eq!(
            selected_url.origin().ascii_serialization(),
            "https://idp.example.com"
        );
        assert_eq!(
            selected_url
                .query_pairs()
                .find(|(key, _)| key == "redirect_uri")
                .unwrap()
                .1,
            format!("{ORIGIN}/api/auth/sso/callback/signin-provider")
        );
    }
    for domain in [
        "notcompany.com",
        "company.com.attacker.test",
        "unrelated.test",
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::sign_in_sso_endpoint(
                &json!({"domain":domain,"callbackURL":input["callbackURL"]}),
            )?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), 404);
    }
    let missing = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::sign_in_sso_endpoint(
            &json!({"providerId":"missing-provider","callbackURL":format!("{ORIGIN}/complete")}),
        )?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(missing.error.status_code(), 404);
    assert_eq!(
        body(&missing.error.to_auth_response()),
        json!({"message":"No provider found for the issuer"})
    );
    B::close(connection).await
}

fn urlencoding_for_state_cookie(cookie: &str) -> TestResult<String> {
    let pair = cookie.split(';').next().ok_or("State cookie missing")?;
    let value = pair.split_once('=').ok_or("State cookie value missing")?.1;
    // Decode the cookie's percent escapes through the standard URL form decoder.
    Ok(
        url::form_urlencoded::parse(format!("value={value}").as_bytes())
            .next()
            .ok_or("State cookie is empty")?
            .1
            .into_owned(),
    )
}
