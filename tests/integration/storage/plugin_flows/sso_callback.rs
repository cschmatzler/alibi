//! An actual PKCE code exchange produces a usable session and rejects replay.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{
    AuthAccount, AuthVerification,
    store::{AccountStore, SsoProviderStore, VerificationStore},
};
#[path = "../../../support/sso_oidc_peer.rs"]
mod peer;
backend_tests!(
    sso_callback_redeems_bound_code_and_creates_usable_session,
    sso_shared_callback_selects_provider_from_protected_state,
    sso_callback_verifies_id_token_authority_claims_and_userinfo_subject,
    sso_callback_defaults_omitted_pkce_to_bound_code_exchange,
    sso_discovery_hydrates_registered_endpoints_and_completes_real_login,
    sso_runtime_discovery_rejects_bad_documents_and_hydrates_login_without_persisting
);
async fn sso_callback_redeems_bound_code_and_creates_usable_session<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, CallbackCase::PerProvider).await
}
async fn sso_shared_callback_selects_provider_from_protected_state<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, CallbackCase::Shared).await
}
async fn sso_callback_defaults_omitted_pkce_to_bound_code_exchange<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, CallbackCase::DefaultPkce).await
}
async fn sso_discovery_hydrates_registered_endpoints_and_completes_real_login<B: Backend>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, CallbackCase::Discovery).await
}
async fn sso_runtime_discovery_rejects_bad_documents_and_hydrates_login_without_persisting<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    callback_flow::<B>(db, CallbackCase::RuntimeDiscovery).await
}
enum CallbackCase {
    PerProvider,
    Shared,
    DefaultPkce,
    Discovery,
    RuntimeDiscovery,
}
async fn callback_flow<B: Backend>(db: Db, case: CallbackCase) -> TestResult {
    let shared = matches!(case, CallbackCase::Shared);
    let default_pkce = matches!(
        case,
        CallbackCase::DefaultPkce | CallbackCase::Discovery | CallbackCase::RuntimeDiscovery
    );
    let discovery = matches!(case, CallbackCase::Discovery);
    let runtime = matches!(case, CallbackCase::RuntimeDiscovery);
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
    let mut registration = json!({"providerId":"callback-provider","issuer":idp.base,"domain":"example.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"scopes":["openid","email"],"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"userInfoEndpoint":format!("{}/userinfo",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base)}});
    if default_pkce {
        _ = registration["oidcConfig"]
            .as_object_mut()
            .unwrap()
            .remove("pkce");
    }
    if runtime {
        let config = registration["oidcConfig"].as_object_mut().unwrap();
        for field in [
            "authorizationEndpoint",
            "tokenEndpoint",
            "jwksEndpoint",
            "userInfoEndpoint",
        ] {
            _ = config.remove(field);
        }
    }
    if discovery {
        let config = registration["oidcConfig"].as_object_mut().unwrap();
        for field in [
            "skipDiscovery",
            "authorizationEndpoint",
            "tokenEndpoint",
            "jwksEndpoint",
            "userInfoEndpoint",
        ] {
            _ = config.remove(field);
        }
        *idp.discovery_case.lock().unwrap() = "missing".into();
        let mut rejected_input = registration.clone();
        rejected_input["providerId"] = json!("incomplete-discovery-provider");
        let rejected = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&rejected_input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400);
        assert_eq!(
            body(&rejected.error.to_auth_response())["code"],
            "discovery_incomplete"
        );
        assert!(
            store
                .get_sso_provider("incomplete-discovery-provider")
                .await?
                .is_none()
        );
        *idp.discovery_case.lock().unwrap() = "valid".into();
    }
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&registration)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    if discovery {
        let row = store
            .get_sso_provider("callback-provider")
            .await?
            .ok_or("Discovery did not persist provider")?;
        let config: Value = serde_json::from_str(row.oidc_config.as_deref().unwrap())?;
        for (field, path) in [
            ("authorizationEndpoint", "authorize"),
            ("tokenEndpoint", "token"),
            ("jwksEndpoint", "jwks"),
            ("userInfoEndpoint", "userinfo"),
        ] {
            assert_eq!(config[field], format!("{}/{path}", idp.base));
        }
        assert_eq!(config["pkce"], true);
        assert_eq!(config["tokenEndpointAuthentication"], "client_secret_basic");
    }
    if runtime {
        *idp.discovery_case.lock().unwrap() = "missing".into();
        let denied = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"callback-provider","callbackURL":format!("{ORIGIN}/complete")}))?,EndpointOptions::default())).await.unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert_eq!(
            body(&denied.error.to_auth_response())["code"],
            "discovery_incomplete"
        );
        *idp.discovery_case.lock().unwrap() = "valid".into();
        let extra = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"callback-provider","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
        let grant = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get(body(&extra)["url"].as_str().unwrap())
            .send()
            .await?;
        let redirect = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
        let query = redirect
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<String, String>>();
        *idp.discovery_case.lock().unwrap() = "missing".into();
        let failed = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::callback_sso_endpoint("callback-provider", &json!(query))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&extra))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let location = url::Url::parse(failed.headers.get("location").unwrap())?;
        assert_eq!(location.path(), "/failed");
        let error = location
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(error["error"], "discovery_failed");
        assert_eq!(
            error["error_description"],
            "Discovery document is missing required fields: jwks_uri"
        );
        assert!(
            store
                .get_latest_verification_by_identifier(&format!("auth-state:{}", query["state"]))
                .await?
                .is_none()
        );
        assert!(
            store
                .get_account("callback-provider", "employee-subject")
                .await?
                .is_none()
        );
        assert!(idp.exchanges.lock().unwrap().is_empty());
        *idp.discovery_case.lock().unwrap() = "valid".into();
    }
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
    if runtime {
        let row = store.get_sso_provider("callback-provider").await?.unwrap();
        let stored: Value = serde_json::from_str(row.oidc_config.as_deref().unwrap())?;
        for field in [
            "authorizationEndpoint",
            "tokenEndpoint",
            "jwksEndpoint",
            "userInfoEndpoint",
        ] {
            assert!(stored.get(field).is_none());
        }
    }
    B::close(connection).await
}

async fn sso_callback_verifies_id_token_authority_claims_and_userinfo_subject<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "id-token-owner@example.test").await;
    for userinfo in [false, true] {
        let provider = if userinfo {
            "id-token-userinfo-provider"
        } else {
            "id-token-provider"
        };
        let mut oidc = json!({"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base)});
        if userinfo {
            oidc["userInfoEndpoint"] = json!(format!("{}/userinfo", idp.base));
        }
        let created = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider,"issuer":idp.base,"domain":"example.test","oidcConfig":oidc}))?,EndpointOptions { headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default() })).await?.into_response()?;
        assert_eq!(created.status, 200);
    }
    for (case, description) in [
        ("issuer", Some("token_not_verified")),
        ("audience", Some("token_not_verified")),
        ("expired", Some("token_not_verified")),
        ("signature", Some("token_not_verified")),
        ("authorized-party", Some("token_not_verified")),
        ("multi-audience", Some("token_not_verified")),
        ("subject", Some("id_token_subject_missing")),
        (
            "userinfo-mismatch",
            Some("id_token_userinfo_subject_mismatch"),
        ),
        ("valid", None),
        ("valid-multi-audience", None),
    ] {
        *idp.id_token_case.lock().unwrap() = case.into();
        let email = format!("id-token-{case}@example.test");
        *idp.email.lock().unwrap() = email.clone();
        let provider = if case == "userinfo-mismatch" {
            "id-token-userinfo-provider"
        } else {
            "id-token-provider"
        };
        let started = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(started.status, 200);
        let granted = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get(body(&started)["url"].as_str().unwrap())
            .send()
            .await?;
        assert_eq!(granted.status(), 302);
        let callback = url::Url::parse(granted.headers().get("location").unwrap().to_str()?)?;
        let query = callback
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<String, String>>();
        let output = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::callback_sso_endpoint(provider, &json!(query))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(output.status, 302);
        let redirect = url::Url::parse(output.headers.get("location").unwrap())?;
        assert!(
            store
                .get_latest_verification_by_identifier(&format!("auth-state:{}", query["state"]))
                .await?
                .is_none()
        );
        if let Some(description) = description {
            assert_eq!(redirect.path(), "/failed");
            let error = redirect
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(error["error"], "invalid_provider");
            assert_eq!(error["error_description"], description);
            assert!(
                store
                    .get_account(provider, "employee-subject")
                    .await?
                    .is_none()
            );
            assert!(
                store
                    .get_account(provider, "other-subject")
                    .await?
                    .is_none()
            );
        } else {
            assert_eq!(redirect.path(), "/complete");
            let session = call(&auth, request("/get-session", None, &cookies(&output)), 200).await;
            assert!(body(&session)["session"].is_object());
            assert_eq!(body(&session)["user"]["emailVerified"], false);
            let account = store
                .get_account(provider, "employee-subject")
                .await?
                .ok_or("ID token did not create account")?;
            assert!(account.id_token().is_some());
        }
    }
    B::close(connection).await
}
