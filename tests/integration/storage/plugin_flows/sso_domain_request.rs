//! Requests reuse real live domain proofs and replace expired values.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{AuthVerification, store::VerificationStore};
backend_tests!(sso_domain_request_reuses_live_proof_and_renews_expired_proof);
async fn sso_domain_request_reuses_live_proof_and_renews_expired_proof<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            domain_verification: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "sso-domain-owner@example.test").await;
    let foreign = signup(&auth, "sso-domain-foreign@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let registered=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"request-provider","issuer":"https://idp.example.com","domain":"company.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(registered.status, 200);
    let endpoint = SsoPlugin::request_domain_verification_endpoint("request-provider")?;
    let requested = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(requested.status, 201);
    let token = body(&requested)["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(token.len(), 24);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert_eq!(body(&registered)["domainVerificationToken"], token);
    assert_eq!(body(&registered)["domainVerified"], false);
    let proof = store
        .get_latest_verification_by_identifier("_better-auth-token-request-provider")
        .await?
        .ok_or("Domain proof was not persisted")?;
    assert_eq!(proof.value(), token);
    assert!(proof.expires_at() > chrono::Utc::now() + chrono::Duration::days(6));
    assert!(proof.expires_at() <= chrono::Utc::now() + chrono::Duration::days(7));
    let repeated = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(body(&repeated)["domainVerificationToken"], token);
    let same = store
        .get_latest_verification_by_identifier("_better-auth-token-request-provider")
        .await?
        .unwrap();
    assert_eq!(same.id(), proof.id());
    assert_eq!(same.expires_at(), proof.expires_at());
    let denied = Box::pin(auth.dispatch_endpoint(
        endpoint.clone(),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&foreign))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    let anonymous = Box::pin(auth.dispatch_endpoint(endpoint.clone(), EndpointOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(anonymous.error.status_code(), 401);
    let preserved = store
        .get_latest_verification_by_identifier("_better-auth-token-request-provider")
        .await?
        .unwrap();
    assert_eq!(preserved.id(), proof.id());
    assert_eq!(preserved.value(), token);
    _ = store
        .update_verification_by_identifier(
            "_better-auth-token-request-provider",
            alibi::UpdateVerification {
                expires_at: Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
                ..Default::default()
            },
        )
        .await?;
    let renewed = Box::pin(auth.dispatch_endpoint(endpoint, owned))
        .await?
        .into_response()?;
    assert_eq!(renewed.status, 201);
    let next = body(&renewed)["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(next, token);
    assert_eq!(next.len(), 24);
    let fresh = store
        .get_latest_verification_by_identifier("_better-auth-token-request-provider")
        .await?
        .unwrap();
    assert_eq!(fresh.value(), next);
    assert_ne!(fresh.id(), proof.id());
    assert!(fresh.expires_at() > chrono::Utc::now() + chrono::Duration::days(6));
    B::close(connection).await
}
