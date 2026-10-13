//! An actual PKCE code exchange produces a usable session and rejects replay.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{
    AuthAccount, AuthVerification,
    store::{AccountStore, VerificationStore},
};
#[path = "../../../support/sso_oidc_peer.rs"]
mod peer;
backend_tests!(
    sso_callback_redeems_bound_code_and_creates_usable_session,
    sso_shared_callback_selects_provider_from_protected_state
);
async fn sso_callback_redeems_bound_code_and_creates_usable_session<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, false).await
}
async fn sso_shared_callback_selects_provider_from_protected_state<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, true).await
}
async fn callback_flow<B: Backend>(db: Db, shared: bool) -> TestResult {
    let idp = peer::start().await;
    *idp.email.lock().unwrap() = "sso-employee@example.test".into();
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::with_config(SsoConfig {
            redirect_uri: shared.then(|| "/sso/callback".into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "sso-callback-owner@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"callback-provider","issuer":idp.base,"domain":"example.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"scopes":["openid","email"],"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"userInfoEndpoint":format!("{}/userinfo",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base)}}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 200);
    let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"callback-provider","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
    let authorization = body(&started)["url"].as_str().unwrap().to_owned();
    let granted = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(&authorization)
        .send()
        .await?;
    assert_eq!(granted.status(), 302);
    let callback = url::Url::parse(granted.headers().get("location").unwrap().to_str()?)?;
    let query: std::collections::HashMap<String, String> =
        callback.query_pairs().into_owned().collect();
    let state = query.get("state").unwrap();
    let proof = store
        .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
        .await?
        .unwrap();
    let payload: Value = serde_json::from_str(proof.value())?;
    let endpoint = ServerEndpoint::<Value>::new(
        "sso",
        if shared {
            "callbackSSOShared"
        } else {
            "callbackSSO"
        },
    )
    .with_params(
        &json!({"providerId":if shared {"untrusted-route-provider"}else{"callback-provider"}}),
    )?
    .with_query(&query)?;
    let options = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
        ..Default::default()
    };
    let unbound = Box::pin(auth.dispatch_endpoint(endpoint.clone(), EndpointOptions::default()))
        .await?
        .into_response()?;
    assert_eq!(unbound.status, 302);
    assert_eq!(
        unbound.headers.get("location"),
        Some(&format!("{ORIGIN}/failed?error=state_mismatch"))
    );
    assert!(
        store
            .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
            .await?
            .is_some()
    );
    assert!(idp.exchanges.lock().unwrap().is_empty());
    let completed = Box::pin(auth.dispatch_endpoint(endpoint.clone(), options.clone()))
        .await?
        .into_response()?;
    assert_eq!(completed.status, 302);
    assert_eq!(
        completed.headers.get("location"),
        Some(&format!("{ORIGIN}/complete"))
    );
    authenticated(&auth, &cookies(&completed), "sso-employee@example.test").await;
    assert!(
        store
            .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
            .await?
            .is_none()
    );
    let account = store
        .get_account("callback-provider", "employee-subject")
        .await?
        .ok_or("SSO account was not created")?;
    assert_eq!(account.scope(), Some("openid,email"));
    assert!(account.access_token().is_some());
    let exchanges = idp.exchanges.lock().unwrap().clone();
    assert_eq!(exchanges.len(), 1);
    assert_eq!(
        exchanges[0]["form"]["code_verifier"],
        payload["codeVerifier"]
    );
    assert_eq!(
        exchanges[0]["form"]["redirect_uri"],
        if shared {
            format!("{ORIGIN}/api/auth/sso/callback")
        } else {
            format!("{ORIGIN}/api/auth/sso/callback/callback-provider")
        }
    );
    let replay = Box::pin(auth.dispatch_endpoint(endpoint, options))
        .await?
        .into_response()?;
    assert_eq!(replay.status, 302);
    assert!(
        replay
            .headers
            .get("location")
            .unwrap()
            .contains("error=state_mismatch")
    );
    assert_eq!(idp.exchanges.lock().unwrap().len(), 1);
    B::close(connection).await
}
