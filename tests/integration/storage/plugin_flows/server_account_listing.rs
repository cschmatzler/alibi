//! Logical account listing is available to server callers with safe output and real authority.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointHook, EndpointOptions, EndpointResponse};
use alibi::field_policy::FieldConfig;
use alibi::plugins::AccountManagementPlugin;
use alibi::{AuthContext, AuthResult, CreateAccount, entity::AuthAccount};

backend_tests!(server_account_listing_retains_logical_authority_projection_and_headers);

#[derive(Clone, Default)]
struct AccountObserver(Arc<Mutex<Vec<(bool, Option<String>)>>>);

#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for AccountObserver {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "listUserAccounts")
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "listUserAccounts")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/list-accounts"));
        self.0.lock().unwrap().push((
            response.result().is_ok(),
            call.session().map(|(user, _)| user.id),
        ));
        Ok(response
            .with_header("x-account-list", "logical")
            .with_header("set-cookie", "account-first=owned; Path=/; HttpOnly")
            .with_header("set-cookie", "account-second=owned; Path=/; HttpOnly"))
    }
}

async fn server_account_listing_retains_logical_authority_projection_and_headers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    // The application intentionally suppresses scope but publishes its declared alias.
    drop(config.account.additional_fields.insert(
        "scope".into(),
        FieldConfig::new(json!({"type":"string"})).hidden(),
    ));
    drop(config.account.additional_fields.insert(
        "grants".into(),
        FieldConfig::new(json!({"type":"string"})).field_name("scope"),
    ));
    let observer = AccountObserver::default();
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(observer.clone())
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "logical-account-owner@example.test").await;
    let foreign = signup(&auth, "logical-account-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let mut remote_ids = Vec::new();
    for id in [&owner_id, &foreign_id] {
        let account = auth
            .store()
            .create_account(CreateAccount {
                user_id: id.clone(),
                account_id: format!("remote-{id}"),
                provider_id: "google".into(),
                access_token: Some("private-access".into()),
                refresh_token: Some("private-refresh".into()),
                id_token: Some("private-id-token".into()),
                password: Some("private-password".into()),
                scope: Some(" email profile, , offline_access ,email ".into()),
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                additional_fields: Default::default(),
            })
            .await?;
        remote_ids.push(account.id().to_string());
    }
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for (response, user_id, remote_id) in [
        (&owner, &owner_id, &remote_ids[0]),
        (&foreign, &foreign_id, &remote_ids[1]),
    ] {
        let output = auth
            .dispatch_endpoint(
                AccountManagementPlugin::list_accounts_endpoint(),
                EndpointOptions {
                    headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(
            output.headers().get("x-account-list").map(String::as_str),
            Some("logical")
        );
        assert_eq!(
            output
                .headers()
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "account-first=owned; Path=/; HttpOnly",
                "account-second=owned; Path=/; HttpOnly",
            ]
        );
        let accounts = output.decode()?;
        assert_eq!(accounts.len(), 2);
        assert!(
            accounts
                .iter()
                .all(|account| account.get("userId") == Some(&json!(user_id)))
        );
        let remote = accounts
            .iter()
            .find(|account| account.get("id") == Some(&json!(remote_id)))
            .unwrap();
        assert_eq!(
            remote.get("accountId"),
            Some(&json!(format!("remote-{user_id}")))
        );
        assert_eq!(
            remote.get("grants"),
            Some(&json!(" email profile, , offline_access ,email "))
        );
        assert_eq!(remote.get("scopes"), Some(&json!([])));
        for account in accounts {
            for private in [
                "accessToken",
                "refreshToken",
                "idToken",
                "password",
                "scope",
            ] {
                assert!(
                    !account.contains_key(private),
                    "logical list leaked {private}"
                );
            }
        }
    }
    for headers in [
        None,
        Some(Default::default()),
        Some(
            [(
                "cookie".into(),
                "better-auth.session_token=unissued.signature".into(),
            )]
            .into_iter()
            .collect(),
        ),
    ] {
        let denied = auth
            .dispatch_endpoint(
                AccountManagementPlugin::list_accounts_endpoint(),
                EndpointOptions {
                    headers,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 401);
        assert!(denied.error.to_string().contains("Unauthorized"));
        assert_eq!(
            denied
                .headers
                .unwrap()
                .get("x-account-list")
                .map(String::as_str),
            Some("logical")
        );
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    // A real post-auth store failure is not converted into absence or an empty list.
    let _ = db
        .execute("ALTER TABLE accounts RENAME TO suspended_accounts", &[])
        .await?;
    let failure = auth
        .dispatch_endpoint(
            AccountManagementPlugin::list_accounts_endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(failure.error.status_code(), 500);
    let _ = db
        .execute("ALTER TABLE suspended_accounts RENAME TO accounts", &[])
        .await?;
    let retried = auth
        .dispatch_endpoint(
            AccountManagementPlugin::list_accounts_endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .decode()?;
    assert_eq!(retried.len(), 2);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let events = observer.0.lock().unwrap();
    assert_eq!(events[0], (true, Some(owner_id.clone())));
    assert_eq!(events[1], (true, Some(foreign_id)));
    assert!(events[2..5].iter().all(|event| event == &(false, None)));
    assert_eq!(events.last(), Some(&(true, Some(owner_id))));
    Ok(())
}
