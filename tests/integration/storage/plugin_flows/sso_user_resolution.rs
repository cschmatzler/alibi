//! Verified identities are resolved through real application transaction policies.
use super::saml_idp as idp;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin, SsoResolver};
use alibi::store::{AccountStore, SsoProviderStore, UserStore, VerificationStore};
use alibi::{AuthAccount, AuthSchema, AuthVerification};
use std::sync::{Arc, atomic::Ordering};
backend_tests!(
    sso_user_resolution_reject_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_continue_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_preserve_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_update_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_throw_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_invalid_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_missing_user_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_ownership_conflict_signed_saml_preserves_transaction_and_ownership,
    sso_user_resolution_reject_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_continue_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_preserve_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_update_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_throw_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_invalid_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_missing_user_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_ownership_conflict_verified_oidc_preserves_transaction_and_ownership,
    sso_user_resolution_missing_id_token_stops_before_application_policy,
    sso_user_resolution_invalid_id_token_stops_before_application_policy,
    sso_user_resolution_session_failure_rolls_back_authentication,
    sso_user_resolution_after_commit_failure_preserves_authentication,
    sso_user_resolution_oidc_session_failure_rolls_back_authentication,
    sso_user_resolution_oidc_after_commit_failure_preserves_authentication
);
async fn sso_user_resolution_reject_signed_saml_preserves_transaction_and_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "reject", false).await
}
async fn sso_user_resolution_continue_signed_saml_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "continue", false).await
}
async fn sso_user_resolution_preserve_signed_saml_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "preserve", false).await
}
async fn sso_user_resolution_update_signed_saml_preserves_transaction_and_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "update", false).await
}
async fn sso_user_resolution_throw_signed_saml_preserves_transaction_and_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "throw", false).await
}
async fn sso_user_resolution_invalid_signed_saml_preserves_transaction_and_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "invalid", false).await
}
async fn sso_user_resolution_missing_user_signed_saml_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "missing-user", false).await
}
async fn sso_user_resolution_ownership_conflict_signed_saml_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "ownership-conflict", false).await
}
async fn sso_user_resolution_reject_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "reject", true).await
}
async fn sso_user_resolution_continue_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "continue", true).await
}
async fn sso_user_resolution_preserve_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "preserve", true).await
}
async fn sso_user_resolution_update_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "update", true).await
}
async fn sso_user_resolution_throw_verified_oidc_preserves_transaction_and_ownership<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "throw", true).await
}
async fn sso_user_resolution_invalid_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "invalid", true).await
}
async fn sso_user_resolution_missing_user_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "missing-user", true).await
}
async fn sso_user_resolution_ownership_conflict_verified_oidc_preserves_transaction_and_ownership<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "ownership-conflict", true).await
}
async fn sso_user_resolution_missing_id_token_stops_before_application_policy<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "missing-token", true).await
}
async fn sso_user_resolution_invalid_id_token_stops_before_application_policy<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "invalid-token", true).await
}
async fn sso_user_resolution_session_failure_rolls_back_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "session-failure", false).await
}
async fn sso_user_resolution_after_commit_failure_preserves_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "after-commit", false).await
}
async fn sso_user_resolution_oidc_session_failure_rolls_back_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "session-failure", true).await
}
async fn sso_user_resolution_oidc_after_commit_failure_preserves_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    resolution_flow::<B>(db, "after-commit", true).await
}
async fn login<S: AuthSchema>(
    auth: &alibi::Alibi<S>,
    email: &str,
    peer: Option<&super::sso_oidc_peer::Peer>,
    token_case: &str,
) -> Result<alibi::AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
    let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"resolver-provider","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
    assert_eq!(started.status, 200);
    if let Some(peer) = peer {
        *peer.email.lock().unwrap() = email.into();
        *peer.id_token_case.lock().unwrap() = token_case.into();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let granted = client
            .get(body(&started)["url"].as_str().unwrap())
            .send()
            .await?;
        assert_eq!(granted.status().as_u16(), 302);
        let callback = url::Url::parse(granted.headers().get("location").unwrap().to_str()?)?;
        return Ok(Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("sso", "callbackSSO")
                    .with_params(&json!({"providerId":"resolver-provider"}))?
                    .with_query(&json!(
                        callback
                            .query_pairs()
                            .into_owned()
                            .collect::<std::collections::HashMap<_, _>>()
                    ))?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?);
    }
    let grant = idp::grant(body(&started)["url"].as_str().unwrap(), email, false)?;
    let completed = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "acsEndpoint")
                .with_params(&json!({"providerId":"resolver-provider"}))?
                .with_body(&grant)?,
            EndpointOptions::default(),
        ),
    )
    .await?
    .into_response()?;
    Ok(completed)
}
async fn resolution_flow<B: Backend>(db: Db, mode: &str, oidc: bool) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let policy = super::sso_user_resolution_policy::Policy::default();
    let peer = if oidc {
        Some(super::sso_oidc_peer::start().await)
    } else {
        None
    };
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    if let Some(peer) = &peer {
        config = config.trusted_origin(&peer.base);
    }
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::hook(
            B::store(Arc::new(config), &connection),
            policy.clone(),
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::with_config(SsoConfig {
            resolve_user: Some(SsoResolver::new::<B::Schema>(Arc::new(policy.clone()))),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "resolver-owner@example.test").await;
    let owner_user = body(&owner)["user"].clone();
    *policy.decision.lock().unwrap() = match mode {
        "reject" => {
            json!({"action":"reject","code":"tenant_denied","message":"Enterprise tenant rejected"})
        }
        "throw" => json!({"action":"throw"}),
        "invalid" => json!({"action":"reject","code":" "}),
        "continue" | "session-failure" | "after-commit" => json!({"action":"continue"}),
        _ => {
            json!({"action":"link","userId":if mode=="missing-user" {uuid::Uuid::new_v4().to_string()}else{owner_user["id"].as_str().unwrap().into()},"profile":if mode=="update" {"update"}else{"preserve"}})
        }
    };
    let input = if let Some(peer) = &peer {
        json!({"providerId":"resolver-provider","issuer":peer.base,"domain":"company.test","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":format!("{}/authorize",peer.base),"tokenEndpoint":format!("{}/token",peer.base),"jwksEndpoint":format!("{}/jwks",peer.base),"userInfoEndpoint":format!("{}/userinfo",peer.base)}})
    } else {
        json!({"providerId":"resolver-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true}})
    };
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    assert!(policy.events.lock().unwrap().is_empty());
    policy
        .deny_sessions
        .store(mode == "session-failure", Ordering::SeqCst);
    policy
        .fail_after_user
        .store(mode == "after-commit", Ordering::SeqCst);
    let email = "resolver-employee@example.test";
    let token_case = if mode == "missing-token" {
        "none"
    } else if mode == "invalid-token" {
        "signature"
    } else {
        "valid"
    };
    let mut completed = login(&auth, email, peer.as_ref(), token_case).await?;
    if mode == "ownership-conflict" {
        assert_eq!(
            url::Url::parse(completed.headers.get("location").unwrap())?.path(),
            "/complete"
        );
        let first_cookie = cookies(&completed);
        let foreign = signup(&auth, "foreign-target@example.test").await;
        *policy.decision.lock().unwrap() =
            json!({"action":"link","userId":body(&foreign)["user"]["id"],"profile":"preserve"});
        completed = login(&auth, email, peer.as_ref(), token_case).await?;
        let retained = call(&auth, request("/get-session", None, &first_cookie), 200).await;
        assert_eq!(body(&retained)["user"]["id"], owner_user["id"]);
    }
    assert_eq!(completed.status, 302);
    let location = url::Url::parse(completed.headers.get("location").unwrap())?;
    let success = matches!(mode, "continue" | "preserve" | "update" | "after-commit");
    let precondition = matches!(mode, "missing-token" | "invalid-token");
    let ordinal = if precondition {
        0
    } else if mode == "ownership-conflict" {
        2
    } else {
        1
    };
    let account_id = if oidc { "employee-subject" } else { email };
    let account = store.get_account("resolver-provider", account_id).await?;
    let proof = store
        .get_latest_verification_by_identifier(&format!("sso-resolver-write:{}", ordinal.max(1)))
        .await?;
    if success {
        assert_eq!(location.path(), "/complete");
        assert_eq!(proof.unwrap().value(), "resolver-provider");
        let session = call(
            &auth,
            request("/get-session", None, &cookies(&completed)),
            200,
        )
        .await;
        let user = body(&session)["user"].clone();
        assert_eq!(account.unwrap().user_id(), user["id"].as_str().unwrap());
        assert_eq!(
            user["email"],
            if mode == "preserve" {
                owner_user["email"].clone()
            } else {
                json!(email)
            }
        );
        assert_eq!(
            user["name"],
            if mode == "preserve" {
                owner_user["name"].clone()
            } else {
                json!("SSO employee")
            }
        );
        if matches!(mode, "continue" | "after-commit") {
            assert_ne!(user["id"], owner_user["id"]);
        } else {
            assert_eq!(user["id"], owner_user["id"]);
        }
    } else {
        assert_eq!(location.path(), "/failed");
        let expected = match mode {
            "session-failure" => ("SESSION_POLICY_DENIED", "Session policy rejected"),
            "missing-token" => ("invalid_provider", "id_token_required_for_user_resolution"),
            "invalid-token" => ("invalid_provider", "token_not_verified"),
            "reject" => ("tenant_denied", "Enterprise tenant rejected"),
            "missing-user" => ("user_not_found", "User not found"),
            "ownership-conflict" => (
                "account_ownership_conflict",
                "Account is already linked to another user",
            ),
            _ => (
                "SSO_USER_RESOLUTION_FAILED",
                "Unable to resolve the SSO user",
            ),
        };
        let query = location
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(query["error"], expected.0);
        assert_eq!(query["error_description"], expected.1);
        assert!(proof.is_none());
        assert!(store.get_user_by_email(email).await?.is_none());
        if mode == "ownership-conflict" {
            assert_eq!(
                account.unwrap().user_id(),
                owner_user["id"].as_str().unwrap()
            );
        } else {
            assert!(account.is_none());
        }
        assert!(!completed.headers.get_all("set-cookie").any(|raw| {
            raw.strip_prefix("better-auth.session_token=")
                .is_some_and(|value| !value.split(';').next().unwrap_or_default().is_empty())
        }));
    }
    let events = policy.events.lock().unwrap().clone();
    assert_eq!(events.len(), ordinal);
    for event in events {
        assert_eq!(
            event["input"]["protocol"],
            if oidc { "oidc" } else { "saml" }
        );
        assert_eq!(
            event["input"]["accountKey"],
            json!({"issuer":peer.as_ref().map_or("https://idp.example.test/entity",|peer|peer.base.as_str()),"accountId":account_id})
        );
        assert_eq!(
            event["input"]["providerUser"],
            json!({"email":email,"name":"SSO employee","emailVerified":false})
        );
        if let Some(peer) = &peer {
            assert_eq!(event["input"]["providerClaims"]["email"], email);
            assert_eq!(event["input"]["providerClaims"]["sub"], "employee-subject");
            assert_eq!(event["input"]["verifiedIdTokenClaims"]["iss"], peer.base);
            assert_eq!(
                event["input"]["verifiedIdTokenClaims"]["sub"],
                "employee-subject"
            );
            assert_eq!(
                event["input"]["verifiedIdTokenClaims"]["aud"],
                "enterprise-client"
            );
            assert!(event["input"].get("providerAttributes").is_none());
        } else {
            assert_eq!(event["input"]["providerAttributes"]["email"], email);
            assert!(event["input"].get("verifiedIdTokenClaims").is_none());
        }
    }
    assert!(store.get_sso_provider("resolver-provider").await?.is_some());
    let retained = call(&auth, request("/get-session", None, &cookies(&owner)), 200).await;
    assert_eq!(body(&retained)["user"]["id"], owner_user["id"]);
    assert_eq!(
        body(&retained)["user"]["email"],
        if mode == "update" {
            json!(email)
        } else {
            owner_user["email"].clone()
        }
    );
    B::close(connection).await
}
