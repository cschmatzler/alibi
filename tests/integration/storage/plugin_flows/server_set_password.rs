//! Pathless public dispatch must own credential creation and its logical hooks.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::entity::AuthAccount;
use alibi::plugins::password_management::{PasswordManagementPlugin, SetPasswordRequest};
use alibi::{AuthResult, StatusResponse};

backend_tests!(server_set_password_is_pathless_and_creates_only_owned_credentials);

fn endpoint(password: &str) -> AuthResult<ServerEndpoint<StatusResponse>> {
    PasswordManagementPlugin::set_password_endpoint(&SetPasswordRequest {
        new_password: password.into(),
    })?
    .with_query(&json!({"disableRefresh":true}))
}
async fn server_set_password_is_pathless_and_creates_only_owned_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("setPassword", "/");
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(alibi::CookieCacheConfig {
        enabled: true,
        max_age: 300.0,
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(observer.clone())
        .plugin(super::auth_probe::fast_password())
        .build()
        .await?;
    let owner = signup(&auth, "logical-set-owner@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logical-set-owner@example.test", "password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logical-set-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let owner_token = body(&owner)["token"].as_str().unwrap().to_owned();
    let credential = auth
        .store()
        .get_user_accounts(&owner_id)
        .await?
        .pop()
        .unwrap();
    auth.store()
        .delete_account(credential.id().as_ref())
        .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for input in [
        json!({}),
        json!({"newPassword":null}),
        json!({"newPassword":7}),
    ] {
        let denied = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "setPassword")
                    .with_body_value(alibi::utils::json::parse_value(&input.to_string())?),
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[body.newPassword]"));
    }
    let guest = auth
        .dispatch_endpoint(endpoint(PASSWORD)?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let short = auth
        .dispatch_endpoint(endpoint("short")?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(short.error.status_code(), 400);
    assert!(short.error.to_string().contains("Password too short"));
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let users = db.table("users").await?;
    let sessions = db.table("sessions").await?;
    let foreign_accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    let set = auth
        .dispatch_endpoint(
            PasswordManagementPlugin::set_password_endpoint(&SetPasswordRequest {
                new_password: "replacement-password-205".into(),
            })?
            .with_body(&json!({"newPassword":"replacement-password-205", "userId":foreign_id}))?
            .with_query(&json!({"disableRefresh":true}))?,
            options(&owner),
        )
        .await?;
    assert!(set.decode()?.status);
    assert_eq!(
        set.headers().get("x-revocation-result").map(String::as_str),
        Some("logical")
    );
    assert!(set.headers().get_all("set-cookie").next().is_none());
    assert_eq!(db.table("users").await?, users);
    assert_eq!(db.table("sessions").await?, sessions);
    let accounts = auth.store().get_user_accounts(&owner_id).await?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].provider_id(), "credential");
    assert_eq!(accounts[0].account_id(), owner_id);
    assert_eq!(
        accounts[0].password(),
        Some("fast$replacement-password-205")
    );
    let persisted_accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    assert_eq!(
        persisted_accounts
            .into_iter()
            .filter(|row| row["user_id"] == foreign_id)
            .collect::<Vec<_>>(),
        foreign_accounts
    );
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    let duplicate = auth
        .dispatch_endpoint(endpoint("another-password-205")?, options(&sibling))
        .await
        .unwrap_err();
    assert_eq!(duplicate.error.status_code(), 400);
    assert!(
        duplicate
            .error
            .to_string()
            .contains("User already has a password set")
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    auth.store().delete_session(&owner_token).await?;
    let revoked_before = db.tables(&["users", "accounts", "sessions"]).await?;
    let revoked = auth
        .dispatch_endpoint(endpoint("another-password-205")?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(revoked.error.status_code(), 401);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        revoked_before
    );
    {
        let events = observer.0.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|id| id.as_deref() == Some(owner_id.as_str()))
        );
        assert!(events.last().unwrap().is_none());
    }
    let login = call(&auth, request("/sign-in/email",Some(json!({"email":"logical-set-owner@example.test","password":"replacement-password-205"})),""),200).await;
    assert_eq!(body(&login)["user"]["id"], owner_id);
    let http = call(
        &auth,
        request(
            "/set-password",
            Some(json!({"newPassword":PASSWORD})),
            &cookies(&sibling),
        ),
        404,
    )
    .await;
    assert_eq!(http.status, 404);
    B::close(connection).await
}
