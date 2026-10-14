//! An actual PKCE code exchange produces a usable session and rejects replay.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{
    AuthAccount, AuthVerification,
    store::{AccountStore, SsoProviderStore, UserStore, VerificationStore},
};
#[path = "../../../support/sso_oidc_peer.rs"]
mod peer;
#[path = "../../../support/sso_validation_policy.rs"]
mod validation_policy;
backend_tests!(
    sso_callback_redeems_bound_code_and_creates_usable_session,
    sso_shared_callback_selects_provider_from_protected_state,
    sso_callback_verifies_id_token_authority_claims_and_userinfo_subject,
    sso_callback_defaults_omitted_pkce_to_bound_code_exchange,
    sso_discovery_hydrates_registered_endpoints_and_completes_real_login,
    sso_runtime_discovery_rejects_bad_documents_and_hydrates_login_without_persisting,
    sso_trusted_oidc_email_verification_accepts_only_exact_true_claims,
    sso_validation_receives_protocol_source_before_identity_writes,
    sso_signup_policy_gates_new_identity_and_honors_oidc_explicit_requests,
    sso_verified_domain_links_subdomain_accounts_without_trusting_foreign_email,
    sso_configured_providers_issue_bound_state_and_complete_oidc_and_saml_login,
    sso_configured_state_rejects_reconfigured_authority_before_identity_writes,
    sso_private_key_jwt_authenticates_actual_token_requests_and_rejects_missing_key
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

async fn sso_trusted_oidc_email_verification_accepts_only_exact_true_claims<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::with_config(SsoConfig {
            trust_email_verified: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "trusted-claims-owner@example.test").await;
    let cases = [
        (json!(true), true),
        (json!("true"), true),
        (json!(false), false),
        (json!("false"), false),
        (json!("TRUE"), false),
        (json!(1), false),
        (json!([true]), false),
        (json!({}), false),
    ];
    for jwt in [false, true] {
        let provider = if jwt {
            "trusted-id-token-provider"
        } else {
            "trusted-userinfo-provider"
        };
        let mut config = json!({"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base)});
        if !jwt {
            config["userInfoEndpoint"] = json!(format!("{}/userinfo", idp.base));
        }
        let created = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider,"issuer":idp.base,"domain":"example.test","oidcConfig":config}))?,EndpointOptions { headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default() })).await?.into_response()?;
        assert_eq!(created.status, 200);
        *idp.id_token_case.lock().unwrap() = if jwt { "valid" } else { "none" }.into();
        for (index, (claim, expected)) in cases.iter().enumerate() {
            let email = format!("trusted-{jwt}-{index}@example.test");
            *idp.profile.lock().unwrap() = Some(
                json!({"sub":format!("trusted-{jwt}-{index}"),"email":email,"name":"SSO employee","email_verified":claim}),
            );
            let started = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::sign_in_sso_endpoint(
                    &json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete")}),
                )?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let grant = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
                .get(body(&started)["url"].as_str().unwrap())
                .send()
                .await?;
            assert_eq!(grant.status(), 302);
            let callback = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
            let query = callback
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            let completed = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::callback_sso_endpoint(provider, &json!(query))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(
                completed.headers.get("location").map(String::as_str),
                Some(format!("{ORIGIN}/complete").as_str())
            );
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert_eq!(body(&session)["user"]["emailVerified"], *expected);
        }
    }
    B::close(connection).await
}

async fn sso_validation_receives_protocol_source_before_identity_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let policy = validation_policy::Policy::default();
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    config.user_validation = Some(Arc::new(policy.clone()));
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-validation-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    for saml in [false, true] {
        policy
            .deny_returning
            .store(false, std::sync::atomic::Ordering::SeqCst);
        policy.events.lock().unwrap().clear();
        let provider = if saml {
            "validation-saml-provider"
        } else {
            "validation-oidc-provider"
        };
        let email = if saml {
            "saml-validation-user@example.test"
        } else {
            "oidc-validation-user@example.test"
        };
        *idp.email.lock().unwrap() = email.into();
        let input = if saml {
            json!({"providerId":provider,"issuer":"https://sp.example.test/entity","domain":"example.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true}})
        } else {
            json!({"providerId":provider,"issuer":idp.base,"domain":"example.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base),"userInfoEndpoint":format!("{}/userinfo",idp.base)}})
        };
        let registered = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(registered.status, 200);
        let mut established = String::new();
        for deny in [false, true] {
            policy
                .deny_returning
                .store(deny, std::sync::atomic::Ordering::SeqCst);
            let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
            let endpoint = if saml {
                let grant =
                    super::saml_idp::grant(body(&started)["url"].as_str().unwrap(), email, false)?;
                SsoPlugin::acs_endpoint(provider, &grant)?
            } else {
                let grant = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .get(body(&started)["url"].as_str().unwrap())
                    .send()
                    .await?;
                let url = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
                SsoPlugin::callback_sso_endpoint(
                    provider,
                    &json!(
                        url.query_pairs()
                            .into_owned()
                            .collect::<std::collections::HashMap<_, _>>()
                    ),
                )?
            };
            let completed = Box::pin(auth.dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            let location = url::Url::parse(completed.headers.get("location").unwrap())?;
            if deny {
                assert_eq!(location.path(), "/failed");
                let error = location
                    .query_pairs()
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>();
                assert_eq!(error["error"], "sso_validation_denied");
                assert_eq!(error["error_description"], "SSO identity rejected");
                let session = call(&auth, request("/get-session", None, &established), 200).await;
                assert_eq!(body(&session)["user"]["name"], "Policy SSO user");
            } else {
                assert_eq!(location.path(), "/complete");
                established = cookies(&completed);
                let session = call(&auth, request("/get-session", None, &established), 200).await;
                assert_eq!(body(&session)["user"]["name"], "Policy SSO user");
            }
        }
        let events = policy.events.lock().unwrap().clone();
        assert_eq!(events.len(), 2);
        for (event, action) in events.iter().zip(["create-user", "sign-in"]) {
            assert_eq!(
                event["source"]["method"],
                if saml { "sso-saml" } else { "sso-oidc" }
            );
            assert_eq!(event["source"]["action"], action);
            assert_eq!(event["source"]["sso"]["providerId"], provider);
            assert!(event["source"].get("oauth").is_none());
            assert_eq!(event["source"]["sso"]["profile"]["email"], email);
            assert_eq!(event["name"], "SSO employee");
            assert_eq!(event["requestPresent"], false);
            assert_eq!(
                event["path"],
                if saml {
                    "/sso/saml2/sp/acs/:providerId"
                } else {
                    "/sso/callback/:providerId"
                }
            );
        }
        assert!(
            store
                .get_account(provider, if saml { email } else { "employee-subject" })
                .await?
                .is_some()
        );
    }
    B::close(connection).await
}

async fn sso_signup_policy_gates_new_identity_and_honors_oidc_explicit_requests<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let build = |disabled| {
        AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(SsoPlugin::with_config(SsoConfig {
                disable_implicit_sign_up: disabled,
                ..Default::default()
            }))
            .build()
    };
    let allowed = build(false).await?;
    let blocked = build(true).await?;
    let owner = signup(&allowed, "sso-signup-policy-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    for saml in [false, true] {
        let provider = if saml {
            "signup-saml-provider"
        } else {
            "signup-oidc-provider"
        };
        let input = if saml {
            json!({"providerId":provider,"issuer":"https://sp.example.test/entity","domain":"example.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true}})
        } else {
            json!({"providerId":provider,"issuer":idp.base,"domain":"example.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base),"userInfoEndpoint":format!("{}/userinfo",idp.base)}})
        };
        let registered = Box::pin(allowed.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(registered.status, 200);
        for index in 0..4 {
            let auth = if index == 0 { &allowed } else { &blocked };
            let request_signup = index == 3;
            let email = format!(
                "signup-{saml}-{}@example.test",
                if index <= 1 { 0 } else { index }
            );
            let subject = if saml {
                email.clone()
            } else {
                format!("signup-{saml}-{}", if index <= 1 { 0 } else { index })
            };
            *idp.profile.lock().unwrap() = Some(
                json!({"sub":subject,"email":email,"email_verified":true,"name":"SSO employee"}),
            );
            let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed"),"requestSignUp":request_signup}))?,EndpointOptions::default())).await?.into_response()?;
            let endpoint = if saml {
                SsoPlugin::acs_endpoint(
                    provider,
                    &super::saml_idp::grant(
                        body(&started)["url"].as_str().unwrap(),
                        &email,
                        false,
                    )?,
                )?
            } else {
                let grant = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .get(body(&started)["url"].as_str().unwrap())
                    .send()
                    .await?;
                assert_eq!(grant.status(), 302);
                let url = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
                let mut query = url
                    .query_pairs()
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>();
                _ = query.insert("requestSignUp".into(), "true".into());
                SsoPlugin::callback_sso_endpoint(provider, &json!(query))?
            };
            let completed = Box::pin(auth.dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            let location = url::Url::parse(completed.headers.get("location").unwrap())?;
            let query = location
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            let denied = index == 2 || (saml && index == 3);
            if denied {
                assert_eq!(
                    query.get("error").map(String::as_str),
                    Some(if saml {
                        "signup_disabled"
                    } else {
                        "signup disabled"
                    })
                );
                assert_eq!(location.path(), if saml { "/complete" } else { "/failed" });
                assert!(store.get_account(provider, &subject).await?.is_none());
                assert!(store.get_user_by_email(&email).await?.is_none());
            } else {
                assert!(!query.contains_key("error"));
                let session = call(
                    auth,
                    request("/get-session", None, &cookies(&completed)),
                    200,
                )
                .await;
                assert_eq!(body(&session)["user"]["email"], email);
                assert!(store.get_account(provider, &subject).await?.is_some());
            }
        }
    }
    B::close(connection).await
}

async fn sso_verified_domain_links_subdomain_accounts_without_trusting_foreign_email<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let dns = super::sso_dns::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    config.account.account_linking.require_local_email_verified = false;
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::with_config(SsoConfig {
            domain_verification: true,
            domain_verification_dns_servers: vec![dns.address],
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "domain-link-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    for saml in [false, true] {
        let provider = if saml {
            "domain-link-saml"
        } else {
            "domain-link-oidc"
        };
        let registration = if saml {
            json!({"providerId":provider,"issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true}})
        } else {
            json!({"providerId":provider,"issuer":idp.base,"domain":"company.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"authorizationEndpoint":format!("{}/authorize",idp.base),"tokenEndpoint":format!("{}/token",idp.base),"jwksEndpoint":format!("{}/jwks",idp.base),"userInfoEndpoint":format!("{}/userinfo",idp.base)}})
        };
        let created = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&registration)?,
            owned.clone(),
        ))
        .await?
        .into_response()?;
        let token = body(&created)["domainVerificationToken"]
            .as_str()
            .unwrap()
            .to_owned();
        *dns.records.lock().unwrap() = vec![vec![format!("_better-auth-token-{provider}={token}")]];
        let verified = Box::pin(
            auth.dispatch_endpoint(SsoPlugin::verify_domain_endpoint(provider)?, owned.clone()),
        )
        .await?
        .into_response()?;
        assert_eq!(verified.status, 204);
        assert_eq!(
            store
                .get_sso_provider(provider)
                .await?
                .unwrap()
                .domain_verified,
            Some(true)
        );
        for (index, domain) in [
            "company.test",
            "engineering.company.test",
            "notcompany.test",
        ]
        .into_iter()
        .enumerate()
        {
            let email = format!("domain-link-{saml}-{index}@{domain}");
            let existing = signup(&auth, &email).await;
            let existing_id = body(&existing)["user"]["id"].clone();
            let subject = if saml {
                email.clone()
            } else {
                format!("domain-link-{index}")
            };
            *idp.profile.lock().unwrap() = Some(
                json!({"sub":subject,"email":email,"email_verified":false,"name":"SSO employee"}),
            );
            let started = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
            let endpoint = if saml {
                SsoPlugin::acs_endpoint(
                    provider,
                    &super::saml_idp::grant(
                        body(&started)["url"].as_str().unwrap(),
                        &email,
                        false,
                    )?,
                )?
            } else {
                let grant = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .get(body(&started)["url"].as_str().unwrap())
                    .send()
                    .await?;
                assert_eq!(grant.status(), 302);
                let url = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
                let query = url
                    .query_pairs()
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>();
                SsoPlugin::callback_sso_endpoint(provider, &json!(query))?
            };
            let completed = Box::pin(auth.dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            let location = url::Url::parse(completed.headers.get("location").unwrap())?;
            let error = location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned());
            if index == 2 {
                assert_eq!(
                    error.as_deref(),
                    Some(if saml {
                        "account_not_linked"
                    } else {
                        "account not linked"
                    })
                );
                assert!(store.get_account(provider, &subject).await?.is_none());
                assert!(completed.headers.get_all("set-cookie").all(|raw| {
                    raw.split(';')
                        .next()
                        .and_then(|pair| pair.strip_prefix("better-auth.session_token="))
                        .is_none_or(str::is_empty)
                }));
            } else {
                assert_eq!(error, None);
                let session = call(
                    &auth,
                    request("/get-session", None, &cookies(&completed)),
                    200,
                )
                .await;
                assert_eq!(body(&session)["user"]["id"], existing_id);
                assert_eq!(
                    store
                        .get_account(provider, &subject)
                        .await?
                        .unwrap()
                        .user_id()
                        .as_ref(),
                    existing_id.as_str().unwrap()
                );
            }
        }
    }
    B::close(connection).await
}

async fn sso_configured_providers_issue_bound_state_and_complete_oidc_and_saml_login<B: Backend>(
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
        .plugin(SsoPlugin::with_config(SsoConfig {
            default_providers: super::sso_configured_providers::providers(&idp.base),
            domain_verification: true,
            ..Default::default()
        }))
        .build()
        .await?;
    for saml in [false, true] {
        let provider = if saml {
            "configured-saml"
        } else {
            "configured-oidc"
        };
        assert!(store.get_sso_provider(provider).await?.is_none());
        let email = format!(
            "configured-employee@engineering.{}.company.test",
            if saml { "saml" } else { "oidc" }
        );
        *idp.profile.lock().unwrap() = Some(
            json!({"sub":"configured-subject","email":email,"email_verified":false,"name":"Configured employee"}),
        );
        for by_domain in [false, true] {
            let mut input = json!({"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")});
            if by_domain {
                input["email"] = json!(email);
            } else {
                input["providerId"] = json!(provider);
            }
            let started = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::sign_in_sso_endpoint(&input)?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(started.status, 200);
            let authorization = url::Url::parse(body(&started)["url"].as_str().unwrap())?;
            let (endpoint, state) = if saml {
                let grant = super::saml_idp::grant(authorization.as_str(), &email, false)?;
                (
                    SsoPlugin::acs_endpoint(provider, &grant)?,
                    grant["RelayState"].as_str().unwrap().to_owned(),
                )
            } else {
                let response = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .get(authorization.as_str())
                    .send()
                    .await?;
                assert_eq!(response.status(), 302);
                let url = url::Url::parse(response.headers().get("location").unwrap().to_str()?)?;
                let query = url
                    .query_pairs()
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>();
                (
                    SsoPlugin::callback_sso_endpoint(provider, &json!(query))?,
                    query["state"].clone(),
                )
            };
            let proof = store
                .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
                .await?
                .unwrap();
            let payload: Value = serde_json::from_str(proof.value())?;
            assert_eq!(
                payload["serverContext"]["ssoProviderReference"]["source"],
                json!({"type":"configured"})
            );
            let completed = Box::pin(auth.dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(completed.status, 302);
            assert_eq!(
                completed.headers.get("location").map(String::as_str),
                Some(format!("{ORIGIN}/complete").as_str())
            );
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert!(
                store
                    .get_account(provider, if saml { &email } else { "configured-subject" })
                    .await?
                    .is_some()
            );
            assert!(store.get_sso_provider(provider).await?.is_none());
        }
        if saml {
            let metadata = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::sp_metadata_endpoint(provider)?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(metadata.status, 200);
            assert!(
                std::str::from_utf8(&metadata.body)?.contains("https://sp.example.test/entity")
            );
        }
    }
    let owner = signup(&auth, "configured-owner@example.test").await;
    let rejected = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"configured-oidc","issuer":idp.base,"domain":"oidc.company.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true}}))?,EndpointOptions {headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await.unwrap_err();
    assert_eq!(rejected.error.status_code(), 422);
    assert_eq!(
        body(&rejected.error.to_auth_response()),
        json!({"message":"This providerId is reserved and cannot be used for an SSO provider"})
    );
    B::close(connection).await
}

async fn sso_configured_state_rejects_reconfigured_authority_before_identity_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let build = |providers| {
        AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(SsoPlugin::with_config(SsoConfig {
                default_providers: providers,
                domain_verification: true,
                ..Default::default()
            }))
            .build()
    };
    let original = build(super::sso_configured_providers::providers(&idp.base)).await?;
    let changed = build(super::sso_configured_providers::changed_providers(
        &idp.base,
    ))
    .await?;
    for saml in [false, true] {
        let provider = if saml {
            "configured-saml"
        } else {
            "configured-oidc"
        };
        let email = format!("configured-change-{saml}@company.test");
        let subject = if saml {
            email.as_str()
        } else {
            "changed-configured-subject"
        };
        *idp.profile.lock().unwrap() = Some(
            json!({"sub":subject,"email":email,"email_verified":false,"name":"Configured employee"}),
        );
        idp.exchanges.lock().unwrap().clear();
        for stale in [true, false] {
            let issuing = if stale { &original } else { &changed };
            let started = Box::pin(issuing.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
            let (endpoint, state, assertion) = if saml {
                let grant =
                    super::saml_idp::grant(body(&started)["url"].as_str().unwrap(), &email, false)?;
                (
                    SsoPlugin::acs_endpoint(provider, &grant)?,
                    grant["RelayState"].as_str().unwrap().to_owned(),
                    Some(grant["assertionId"].as_str().unwrap().to_owned()),
                )
            } else {
                let response = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .get(body(&started)["url"].as_str().unwrap())
                    .send()
                    .await?;
                assert_eq!(response.status(), 302);
                let url = url::Url::parse(response.headers().get("location").unwrap().to_str()?)?;
                let query = url
                    .query_pairs()
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>();
                (
                    SsoPlugin::callback_sso_endpoint(provider, &json!(query))?,
                    query["state"].clone(),
                    None,
                )
            };
            let completed = Box::pin(changed.dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(completed.status, 302);
            let location = url::Url::parse(completed.headers.get("location").unwrap())?;
            let query = location
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            if stale {
                assert_eq!(location.path(), "/failed");
                assert_eq!(
                    query.get("error").map(String::as_str),
                    Some("invalid_state")
                );
                assert_eq!(
                    query.get("error_description").map(String::as_str),
                    Some("sso_provider_changed_during_authentication")
                );
                assert!(store.get_user_by_email(&email).await?.is_none());
                assert!(store.get_account(provider, subject).await?.is_none());
                if !saml {
                    assert!(idp.exchanges.lock().unwrap().is_empty());
                }
                if let Some(id) = assertion {
                    assert!(
                        store
                            .get_latest_verification_by_identifier(&format!(
                                "saml-used-assertion:{id}"
                            ))
                            .await?
                            .is_none()
                    );
                }
            } else {
                assert_eq!(location.path(), "/complete");
                assert!(!query.contains_key("error"));
                let session = call(
                    &changed,
                    request("/get-session", None, &cookies(&completed)),
                    200,
                )
                .await;
                assert_eq!(body(&session)["user"]["email"], email);
                assert!(store.get_account(provider, subject).await?.is_some());
            }
            assert!(
                store
                    .get_latest_verification_by_identifier(&format!("auth-state:{state}"))
                    .await?
                    .is_none()
            );
            assert!(store.get_sso_provider(provider).await?.is_none());
        }
    }
    B::close(connection).await
}

async fn sso_private_key_jwt_authenticates_actual_token_requests_and_rejects_missing_key<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use base64::Engine as _;
    let idp = peer::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    let build = |key| {
        AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(SsoPlugin::with_config(SsoConfig {
                default_providers: super::sso_configured_providers::jwt_provider(&idp.base, key),
                ..Default::default()
            }))
            .build()
    };
    let valid = build(true).await?;
    let missing = build(false).await?;
    let mut jtis = Vec::new();
    for (index, key) in [(0, true), (1, true), (2, false)] {
        let auth = if key { &valid } else { &missing };
        let email = format!("private-key-jwt-{index}@company.test");
        let subject = format!("private-jwt-subject-{index}");
        *idp.profile.lock().unwrap() = Some(
            json!({"sub":subject,"email":email,"email_verified":false,"name":"Private JWT employee"}),
        );
        idp.exchanges.lock().unwrap().clear();
        let started = Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"configured-jwt","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
        let grant = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get(body(&started)["url"].as_str().unwrap())
            .send()
            .await?;
        assert_eq!(grant.status(), 302);
        let url = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
        let query = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        let completed = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::callback_sso_endpoint("configured-jwt", &json!(query))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let location = url::Url::parse(completed.headers.get("location").unwrap())?;
        if !key {
            assert_eq!(location.path(), "/failed");
            assert_eq!(
                location
                    .query_pairs()
                    .collect::<std::collections::HashMap<_, _>>()
                    .get("error_description")
                    .map(|value| value.as_ref()),
                Some("no_private_key_available")
            );
            assert!(idp.exchanges.lock().unwrap().is_empty());
            assert!(store.get_user_by_email(&email).await?.is_none());
            assert!(
                store
                    .get_account("configured-jwt", &subject)
                    .await?
                    .is_none()
            );
        } else {
            assert_eq!(location.path(), "/complete");
            let session = call(
                auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            let exchanges = idp.exchanges.lock().unwrap().clone();
            assert_eq!(exchanges.len(), 1);
            assert!(exchanges[0]["authorization"].is_null());
            assert!(exchanges[0]["form"].get("client_secret").is_none());
            assert_eq!(exchanges[0]["form"]["client_id"], "enterprise-client");
            assert_eq!(
                exchanges[0]["form"]["client_assertion_type"],
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            );
            let assertion = exchanges[0]["form"]["client_assertion"].as_str().unwrap();
            let claims: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(assertion.split('.').nth(1).unwrap())?,
            )?;
            let jti = claims["jti"].as_str().unwrap().to_owned();
            assert!(!jtis.contains(&jti));
            jtis.push(jti);
            assert!(
                store
                    .get_account("configured-jwt", &subject)
                    .await?
                    .is_some()
            );
        }
        assert!(store.get_sso_provider("configured-jwt").await?.is_none());
    }
    B::close(connection).await
}
