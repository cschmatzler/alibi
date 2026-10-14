//! Mutation policies share locks, commit, and rollback with provider/account writes.
use super::*;
use alibi::AuthVerification;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoMutationGuard, SsoPlugin};
use alibi::store::{AccountStore, SsoProviderStore, VerificationStore};
use std::sync::{Arc, atomic::Ordering};
backend_tests!(sso_provider_mutation_guards_share_transaction_rollback_and_namespace_retirement);
async fn sso_provider_mutation_guards_share_transaction_rollback_and_namespace_retirement<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let policy = super::sso_mutation_policy::Policy::default();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            guard_provider_mutation: Some(SsoMutationGuard::new::<B::Schema>(Arc::new(
                policy.clone(),
            ))),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "mutation-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"guard-provider","issuer":"https://idp.example.com","domain":"original.test","oidcConfig":{"clientId":"client","clientSecret":"original-secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    assert!(policy.events.lock().unwrap().is_empty());
    let original = store.get_sso_provider("guard-provider").await?.unwrap();
    _ = store
        .create_account(alibi::CreateAccount {
            user_id: body(&owner)["user"]["id"].as_str().unwrap().into(),
            provider_id: "guard-provider".into(),
            account_id: "linked-subject".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
            additional_fields: Default::default(),
        })
        .await?;
    let update = SsoPlugin::update_sso_provider_endpoint(
        &json!({"providerId":"guard-provider","oidcConfig":{"clientSecret":"rotated-secret"}}),
    )?;
    let denied = match Box::pin(auth.dispatch_endpoint(update.clone(), owned.clone())).await {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(denied.status, 409);
    assert_eq!(
        body(&denied),
        json!({"code":"SSO_PROVIDER_MUTATION_REJECTED","message":"SSO provider mutation is not allowed"})
    );
    assert_eq!(
        store.get_sso_provider("guard-provider").await?.unwrap(),
        original
    );
    assert!(
        store
            .get_latest_verification_by_identifier("sso-guard-write:update:1")
            .await?
            .is_none()
    );
    policy.denied.store(false, Ordering::SeqCst);
    let allowed = Box::pin(auth.dispatch_endpoint(update, owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(allowed.status, 200);
    let rotated = store.get_sso_provider("guard-provider").await?.unwrap();
    let config: Value = serde_json::from_str(rotated.oidc_config.as_deref().unwrap())?;
    assert_eq!(config["clientSecret"], "rotated-secret");
    assert_eq!(
        store
            .get_latest_verification_by_identifier("sso-guard-write:update:2")
            .await?
            .unwrap()
            .value(),
        "original.test"
    );
    let boundary = match Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(
            &json!({"providerId":"guard-provider","oidcConfig":{"clientId":"changed-client"}}),
        )?,
        owned.clone(),
    ))
    .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(boundary.status, 409);
    assert_eq!(
        body(&boundary),
        json!({"message":"Cannot change SSO provider identity fields while linked accounts exist"})
    );
    assert!(
        store
            .get_latest_verification_by_identifier("sso-guard-write:update:3")
            .await?
            .is_none()
    );
    assert_eq!(
        store.get_sso_provider("guard-provider").await?.unwrap(),
        rotated
    );
    policy.denied.store(true, Ordering::SeqCst);
    let denied = match Box::pin(auth.dispatch_endpoint(
        SsoPlugin::delete_sso_provider_endpoint("guard-provider")?,
        owned.clone(),
    ))
    .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(denied.status, 409);
    assert_eq!(
        body(&denied),
        json!({"code":"SSO_PROVIDER_MUTATION_REJECTED","message":"SSO provider mutation is not allowed"})
    );
    assert!(
        store
            .get_latest_verification_by_identifier("sso-guard-write:delete:4")
            .await?
            .is_none()
    );
    assert_eq!(
        store.get_sso_provider("guard-provider").await?.unwrap(),
        rotated
    );
    assert!(
        store
            .get_account("guard-provider", "linked-subject")
            .await?
            .is_some()
    );
    policy.denied.store(false, Ordering::SeqCst);
    let deleted = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::delete_sso_provider_endpoint("guard-provider")?,
        owned,
    ))
    .await?
    .into_response()?;
    assert_eq!(deleted.status, 200);
    assert_eq!(body(&deleted), json!({"success":true}));
    assert!(store.get_sso_provider("guard-provider").await?.is_none());
    assert!(
        store
            .get_account("guard-provider", "linked-subject")
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_latest_verification_by_identifier("sso-guard-write:delete:5")
            .await?
            .unwrap()
            .value(),
        "original.test"
    );
    let events = policy.events.lock().unwrap().clone();
    assert_eq!(events.len(), 5);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["domain"], "original.test");
        assert_eq!(
            event["mutation"]["provider"],
            json!({"id":original.id,"providerId":"guard-provider","organizationId":null})
        );
        assert_eq!(
            event["mutation"]["providerReference"]["source"],
            json!({"type":"persisted","recordId":original.id})
        );
        assert_eq!(
            event["mutation"]["providerReference"]["providerId"],
            "guard-provider"
        );
        assert_eq!(
            event["mutation"]["providerReference"]["authenticationConfigurationFingerprint"]
                .as_str()
                .unwrap()
                .len(),
            43
        );
        assert_eq!(
            event["mutation"].as_object().unwrap().len(),
            if index < 3 { 4 } else { 3 }
        );
    }
    assert_eq!(
        events[0]["mutation"]["isAuthenticationBoundaryChange"],
        false
    );
    assert_eq!(
        events[1]["mutation"]["isAuthenticationBoundaryChange"],
        false
    );
    assert_eq!(
        events[2]["mutation"]["isAuthenticationBoundaryChange"],
        true
    );
    assert_eq!(events[3]["mutation"]["action"], "delete");
    assert_eq!(
        events[0]["mutation"]["providerReference"],
        events[4]["mutation"]["providerReference"]
    );
    authenticated(&auth, &cookies(&owner), "mutation-owner@example.test").await;
    B::close(connection).await
}
