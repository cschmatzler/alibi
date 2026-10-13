//! Public logical account deletion retains source admission and physical ownership.
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::plugins::AccountManagementPlugin;
use alibi::{
    AuthContext, AuthResult, CreateAccount,
    entity::{AuthAccount, AuthSession},
};

backend_tests!(
    server_unlink_account_requires_fresh_authority_and_deletes_only_selected_owned_row,
    http_unlink_account_rejects_stale_session_before_removing_selected_row
);

#[derive(Clone, Default)]
struct UnlinkObserver(Arc<Mutex<Vec<(bool, Option<String>)>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for UnlinkObserver {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "unlinkAccount")
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "unlinkAccount")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/unlink-account"));
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

async fn remote_account<S: AuthSchema>(auth: &Alibi<S>, user_id: &str) -> TestResult<String> {
    let account = auth
        .store()
        .create_account(CreateAccount {
            user_id: user_id.into(),
            account_id: format!("owned-remote-{user_id}"),
            provider_id: "google".into(),
            access_token: Some("retained-private-access".into()),
            refresh_token: Some("retained-private-refresh".into()),
            id_token: None,
            password: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("email,profile".into()),
            additional_fields: Default::default(),
        })
        .await?;
    Ok(account.id().into_owned())
}
fn logical_credentials(response: &AuthResponse) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    }
}
async fn server_unlink_account_requires_fresh_authority_and_deletes_only_selected_owned_row<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = UnlinkObserver::default();
    let auth = builder::<B>(&connection)
        .endpoint_hook(observer.clone())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "server-unlink-owner@example.test").await;
    let foreign = signup(&auth, "server-unlink-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let selected = remote_account(&auth, &owner_id).await?;
    let foreign_target = remote_account(&auth, &foreign_id).await?;
    let original = db.tables(&["user", "account", "session"]).await?;
    let mut retained_accounts: Vec<Value> = serde_json::from_str(&original[1])?;
    retained_accounts.retain(|row| row["id"] != json!(selected));
    for input in [json!({}), json!({"accountId": 5})] {
        let denied = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("account-management", "unlinkAccount")
                    .with_body_value(alibi::utils::json::parse_value(&input.to_string())?),
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert!(denied.error.to_string().contains("[body.accountId]"));
    }
    let guest = auth
        .dispatch_endpoint(
            AccountManagementPlugin::unlink_account_endpoint(&selected),
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let wrong_owner = auth
        .dispatch_endpoint(
            AccountManagementPlugin::unlink_account_endpoint(&foreign_target),
            logical_credentials(&owner),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong_owner.error.status_code(), 400);
    assert!(wrong_owner.error.to_string().contains("Account not found"));
    assert_eq!(db.tables(&["user", "account", "session"]).await?, original);

    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let created_at = auth
        .store()
        .get_session(&token)
        .await?
        .unwrap()
        .created_at();
    let past =
        chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")?.with_timezone(&chrono::Utc);
    db.set_timestamp("session", "createdAt", ("token", &token), past)
        .await?;
    let stale = db.tables(&["user", "account", "session"]).await?;
    let denied = auth
        .dispatch_endpoint(
            AccountManagementPlugin::unlink_account_endpoint(&selected),
            logical_credentials(&owner),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        denied.error,
        alibi::AuthError::Upstream {
            status: 403,
            code: "SESSION_NOT_FRESH",
            ..
        }
    ));
    assert_eq!(db.tables(&["user", "account", "session"]).await?, stale);
    db.set_timestamp("session", "createdAt", ("token", &token), created_at)
        .await?;
    let restored = db.tables(&["user", "session"]).await?;
    let removed = auth
        .dispatch_endpoint(
            AccountManagementPlugin::unlink_account_endpoint(&selected),
            logical_credentials(&owner),
        )
        .await?;
    assert!(removed.decode()?.status);
    assert_eq!(
        removed.headers().get("x-account-list").map(String::as_str),
        Some("logical")
    );
    assert_eq!(
        removed
            .headers()
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "account-first=owned; Path=/; HttpOnly",
            "account-second=owned; Path=/; HttpOnly",
        ]
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"account\" WHERE id = $1",
            &[&selected]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"account\" WHERE id = $1",
            &[&foreign_target]
        )
        .await?,
        1
    );
    let after = db.tables(&["user", "account", "session"]).await?;
    assert_eq!(db.tables(&["user", "session"]).await?, restored);
    assert_eq!(db.count("account").await?, 3);
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&db.table("account").await?)?,
        retained_accounts
    );
    let credential = auth
        .store()
        .get_user_accounts(&owner_id)
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential")
        .unwrap()
        .id()
        .into_owned();
    for id in [&selected, &credential] {
        let denied = auth
            .dispatch_endpoint(
                AccountManagementPlugin::unlink_account_endpoint(id),
                logical_credentials(&owner),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert!(denied.error.to_string().contains("last account"));
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, after);
    let _ = call(&auth, request("/get-session", None, &cookies(&owner)), 200).await;
    let _ = call(
        &auth,
        request("/get-session", None, &cookies(&foreign)),
        200,
    )
    .await;
    let events = observer.0.lock().unwrap();
    assert!(events.contains(&(true, Some(owner_id))));
    assert_eq!(events.iter().filter(|(success, _)| *success).count(), 1);
    Ok(())
}

async fn http_unlink_account_rejects_stale_session_before_removing_selected_row<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(AccountManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "http-stale-unlink-owner@example.test").await;
    let foreign = signup(&auth, "http-stale-unlink-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let selected = remote_account(&auth, &owner_id).await?;
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let original_creation = auth
        .store()
        .get_session(&token)
        .await?
        .unwrap()
        .created_at();
    let past =
        chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")?.with_timezone(&chrono::Utc);
    db.set_timestamp("session", "createdAt", ("token", &token), past)
        .await?;
    let before = db.tables(&["user", "account", "session"]).await?;
    let denied = call(
        &auth,
        request(
            "/unlink-account",
            Some(json!({"accountId":selected})),
            &cookies(&owner),
        ),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "SESSION_NOT_FRESH");
    assert!(
        !denied
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token="))
    );
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    db.set_timestamp("session", "createdAt", ("token", &token), original_creation)
        .await?;
    let removed = call(
        &auth,
        request(
            "/unlink-account",
            Some(json!({"accountId":selected})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&removed), json!({"status":true}));
    for input in [json!({}), json!({"accountId": 5})] {
        let malformed = call(&auth, request("/unlink-account", Some(input), ""), 400).await;
        assert_eq!(body(&malformed)["code"], "VALIDATION_ERROR");
    }
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"account\" WHERE id = $1",
            &[&selected]
        )
        .await?,
        0
    );
    let _ = call(
        &auth,
        request("/get-session", None, &cookies(&foreign)),
        200,
    )
    .await;
    Ok(())
}
