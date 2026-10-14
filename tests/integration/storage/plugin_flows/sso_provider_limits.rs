//! Per-user admission resolves application limits on every authenticated registration.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoPlugin, SsoProviderLimit};
use alibi::store::SsoProviderStore;
use std::sync::Arc;
backend_tests!(sso_provider_limits_resolve_authenticated_users_before_durable_registration);
async fn sso_provider_limits_resolve_authenticated_users_before_durable_registration<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let policy = super::sso_provider_limit_policy::Policy::default();
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            resolve_providers_limit: Some(SsoProviderLimit(Arc::new(policy.clone()))),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "limit-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"limit-provider","issuer":"https://idp.example.com","domain":"company.test","oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    for (index, (limit, status, message)) in [
        (0.0, 403, Some("SSO provider registration is disabled")),
        (1.0, 200, None),
        (
            1.0,
            403,
            Some("You have reached the maximum number of SSO providers"),
        ),
        (2.0, 200, None),
        (
            1.5,
            403,
            Some("You have reached the maximum number of SSO providers"),
        ),
        (3.0, 200, None),
        (
            -1.0,
            403,
            Some("You have reached the maximum number of SSO providers"),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        *policy.limit.lock().unwrap() = limit;
        policy.events.lock().unwrap().clear();
        let provider_id = format!("limit-provider-{index}");
        let mut candidate = input.clone();
        candidate["providerId"] = json!(provider_id);
        let response = match Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&candidate)?,
            owned.clone(),
        ))
        .await
        {
            Ok(output) => output.into_response()?,
            Err(error) => error.error.to_auth_response(),
        };
        assert_eq!(response.status, status);
        if let Some(message) = message {
            assert_eq!(body(&response)["message"], message);
        }
        assert_eq!(
            store.get_sso_provider(&provider_id).await?.is_some(),
            status == 200
        );
        let user = &body(&owner)["user"];
        assert_eq!(
            *policy.events.lock().unwrap(),
            vec![
                json!({"userId":user["id"],"email":user["email"],"name":user["name"],"emailVerified":user["emailVerified"]})
            ]
        );
    }
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(store.list_sso_providers_by_user(&user_id).await?.len(), 3);
    let other = signup(&auth, "limit-other@example.test").await;
    *policy.limit.lock().unwrap() = 1.0;
    policy.events.lock().unwrap().clear();
    let other_options = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&other))].into_iter().collect()),
        ..Default::default()
    };
    let accepted = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        other_options,
    ))
    .await?
    .into_response()?;
    assert_eq!(accepted.status, 200);
    assert_eq!(
        store
            .get_sso_provider("limit-provider")
            .await?
            .unwrap()
            .user_id
            .as_deref(),
        body(&other)["user"]["id"].as_str()
    );
    assert_eq!(
        policy.events.lock().unwrap()[0]["userId"],
        body(&other)["user"]["id"]
    );
    policy.events.lock().unwrap().clear();
    let denied = match Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        EndpointOptions::default(),
    ))
    .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(denied.status, 401);
    assert!(policy.events.lock().unwrap().is_empty());
    B::close(connection).await
}
