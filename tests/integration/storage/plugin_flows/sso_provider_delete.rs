//! Provider deletion removes its real account links while preserving other providers.
use super::*;
use alibi::AuthAccount;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::store::AccountStore;
backend_tests!(sso_provider_delete_retires_linked_accounts_and_preserves_other_providers);
postgres_tests!(sso_provider_delete_retires_linked_accounts_and_preserves_other_providers);
async fn sso_provider_delete_retires_linked_accounts_and_preserves_other_providers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "sso-delete-owner@example.test").await;
    let foreign = signup(&auth, "sso-delete-foreign@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let other = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&foreign))].into_iter().collect()),
        ..Default::default()
    };
    for (id, options) in [
        ("delete-provider", owned.clone()),
        ("keep-provider", other.clone()),
    ] {
        let response=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":id,"issuer":"https://idp.example.com","domain":"company.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true}}))?,options)).await?.into_response()?;
        assert_eq!(response.status, 200);
    }
    for (user_id, provider_id, account_id) in [
        (
            body(&owner)["user"]["id"].as_str().unwrap().to_owned(),
            "delete-provider",
            "owner-subject",
        ),
        (
            body(&foreign)["user"]["id"].as_str().unwrap().to_owned(),
            "delete-provider",
            "foreign-subject",
        ),
        (
            body(&foreign)["user"]["id"].as_str().unwrap().to_owned(),
            "keep-provider",
            "kept-subject",
        ),
    ] {
        let account = store
            .create_account(alibi::CreateAccount {
                additional_fields: Default::default(),
                user_id: user_id.clone(),
                provider_id: provider_id.into(),
                account_id: account_id.into(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: None,
            })
            .await?;
        assert_eq!(account.user_id().as_ref(), user_id);
        assert_eq!(account.provider_id(), provider_id);
    }
    let endpoint = ServerEndpoint::<Value>::new("sso", "deleteSSOProvider")
        .with_body(&json!({"providerId":"delete-provider"}))?;
    let denied = Box::pin(auth.dispatch_endpoint(endpoint.clone(), other))
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    assert!(
        store
            .get_account("delete-provider", "owner-subject")
            .await?
            .is_some()
    );
    assert!(
        store
            .get_account("delete-provider", "foreign-subject")
            .await?
            .is_some()
    );
    assert_eq!(
        Box::pin(auth.dispatch_endpoint(endpoint.clone(), EndpointOptions::default()))
            .await
            .unwrap_err()
            .error
            .status_code(),
        401
    );
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION sso_delete_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced provider deletion failure'; END $$",&[]).await?;
        _=db.execute("CREATE TRIGGER sso_delete_fault BEFORE DELETE ON \"ssoProvider\" FOR EACH ROW EXECUTE FUNCTION sso_delete_fault_fn()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER sso_delete_fault BEFORE DELETE ON \"ssoProvider\" BEGIN SELECT RAISE(ABORT, 'forced provider deletion failure'); END",&[]).await?;
    }
    let failed = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await
        .unwrap_err();
    assert_eq!(failed.error.status_code(), 500);
    assert!(!alibi::endpoint::is_endpoint_api_error(&failed.error));
    assert!(
        auth.store()
            .get_sso_provider("delete-provider")
            .await?
            .is_some()
    );
    assert!(
        store
            .get_account("delete-provider", "owner-subject")
            .await?
            .is_some()
    );
    assert!(
        store
            .get_account("delete-provider", "foreign-subject")
            .await?
            .is_some()
    );
    if db.is_postgres() {
        _ = db
            .execute("DROP TRIGGER sso_delete_fault ON \"ssoProvider\"", &[])
            .await?;
        _ = db
            .execute("DROP FUNCTION sso_delete_fault_fn()", &[])
            .await?;
    } else {
        _ = db.execute("DROP TRIGGER sso_delete_fault", &[]).await?;
    }
    let deleted = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(deleted.status, 200);
    assert_eq!(body(&deleted), json!({"success":true}));
    assert!(
        auth.store()
            .get_sso_provider("delete-provider")
            .await?
            .is_none()
    );
    assert!(
        auth.store()
            .get_sso_provider("keep-provider")
            .await?
            .is_some()
    );
    assert!(
        store
            .get_account("delete-provider", "owner-subject")
            .await?
            .is_none()
    );
    assert!(
        store
            .get_account("delete-provider", "foreign-subject")
            .await?
            .is_none()
    );
    assert!(
        store
            .get_account("keep-provider", "kept-subject")
            .await?
            .is_some()
    );
    let replay = Box::pin(auth.dispatch_endpoint(endpoint, owned))
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 404);
    assert_eq!(
        body(&replay.error.to_auth_response()),
        json!({"message":"Provider not found"})
    );
    B::close(connection).await
}
