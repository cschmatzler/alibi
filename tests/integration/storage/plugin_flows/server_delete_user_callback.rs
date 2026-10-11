//! Delivered callback proofs are consumed before ownership rejection; deletion retires only the caller.
use super::auth_probe::fast_password;
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::AuthResult;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::UserManagementPlugin;
use alibi::plugins::user_management::{SendDeleteAccountVerification, UserInfo};

#[derive(Default)]
struct Mailbox(Mutex<Vec<(String, String)>>);
#[async_trait::async_trait]
impl SendDeleteAccountVerification for Mailbox {
    async fn send(&self, user: &UserInfo, _: &str, token: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push((user.id.clone(), token.into()));
        Ok(())
    }
}
fn endpoint(query: &Value) -> AuthResult<ServerEndpoint<alibi::SuccessMessageResponse>> {
    UserManagementPlugin::delete_user_callback_endpoint(
        &alibi::plugins::user_management::DeleteUserCallbackQuery {
            token: String::new(),
            callback_url: None,
        },
    )?
    .with_query(query)
}
backend_tests!(server_delete_user_callback_consumes_owned_proofs_and_preserves_foreign_rows);
async fn server_delete_user_callback_consumes_owned_proofs_and_preserves_foreign_rows<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            ..Default::default()
        });
    let mailbox = Arc::new(Mailbox::default());
    let observer = Observer::new("deleteUserCallback", "/delete-user/callback");
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(
            UserManagementPlugin::new()
                .delete_user_enabled(true)
                .delete_token_expires_in(chrono::Duration::seconds(90))
                .send_delete_account_verification(mailbox.clone()),
        )
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let delivery_config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let delivery_auth = AuthBuilder::new(delivery_config.clone())
        .store(B::store(Arc::new(delivery_config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(
            UserManagementPlugin::new()
                .delete_user_enabled(true)
                .delete_token_expires_in(chrono::Duration::seconds(90))
                .send_delete_account_verification(mailbox.clone()),
        )
        .build()
        .await?;
    let owner = signup(&auth, "logical-callback-owner@example.test").await;
    let foreign = signup(&auth, "logical-callback-foreign@example.test").await;
    let bystander = signup(&auth, "logical-callback-bystander@example.test").await;
    let owner_id = body(&owner)["user"]["id"].clone();
    let foreign_id = body(&foreign)["user"]["id"].clone();
    let auth_before = db.tables(&["users", "accounts", "sessions"]).await?;
    let requested = call(
        &delivery_auth,
        request("/delete-user", Some(json!({})), &cookies(&owner)),
        200,
    )
    .await;
    assert_eq!(
        body(&requested),
        json!({"success":true,"message":"Verification email sent"})
    );
    assert!(
        requested
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_data=")
                && cookie.contains("Max-Age=0"))
    );

    let first = mailbox.0.lock().unwrap().last().unwrap().1.clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for query in [
        json!({}),
        json!(null),
        json!({"token":null}),
        json!({"token":7}),
        json!({"token":first,"callbackURL":null}),
        json!({"token":first,"callbackURL":7}),
    ] {
        let rejected = auth
            .dispatch_endpoint(endpoint(&query)?, options(&owner))
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[query"));
    }
    let guest = auth
        .dispatch_endpoint(
            endpoint(&json!({"token":first}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 404);
    assert!(guest.error.to_string().contains("Failed to get user info"));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let wrong = auth
        .dispatch_endpoint(
            UserManagementPlugin::delete_user_callback_endpoint(
                &alibi::plugins::user_management::DeleteUserCallbackQuery {
                    token: first.clone(),
                    callback_url: None,
                },
            )?,
            options(&foreign),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.error.status_code(), 404);
    assert!(wrong.error.to_string().contains("Invalid token"));
    assert_eq!(db.table("verifications").await?, "[]");
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        auth_before
    );
    assert_eq!(
        observer.0.lock().unwrap().last().unwrap().as_deref(),
        foreign_id.as_str()
    );
    let after_wrong = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let spent = auth
        .dispatch_endpoint(endpoint(&json!({"token":first}))?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(spent.error.status_code(), 404);
    assert!(spent.error.to_string().contains("Invalid token"));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        after_wrong
    );
    for (target, id, callback) in [
        (&owner, &owner_id, ""),
        (
            &foreign,
            &foreign_id,
            "https://external.example/done?kept=1#deleted",
        ),
    ] {
        let requested = call(
            &delivery_auth,
            request("/delete-user", Some(json!({})), &cookies(target)),
            200,
        )
        .await;
        assert_eq!(
            body(&requested),
            json!({"success":true,"message":"Verification email sent"})
        );
        assert!(
            requested
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.session_data=")
                    && cookie.contains("Max-Age=0"))
        );

        let token = mailbox.0.lock().unwrap().last().unwrap().1.clone();
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let result=auth.dispatch_endpoint(endpoint(&json!({"token":token,"callbackURL":callback,"userId":body(&bystander)["user"]["id"]}))?,options(target)).await;
        let headers = if callback.is_empty() {
            let output = result?;
            assert_eq!(output.decode()?.message, "User deleted");
            assert!(output.decode()?.success);
            output.headers().clone()
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.error.status_code(), 302);
            assert!(error.body_absent);
            assert_eq!(
                error
                    .headers
                    .as_ref()
                    .unwrap()
                    .get("location")
                    .map(String::as_str),
                Some(callback)
            );
            error.headers.unwrap()
        };
        for name in ["session_token", "session_data", "dont_remember"] {
            assert!(
                headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.starts_with(&format!("better-auth.{name}="))
                        && cookie.contains("Max-Age=0"))
            );
        }
        assert!(
            headers
                .get_all("set-cookie")
                .filter(|cookie| cookie.starts_with("better-auth.session_data="))
                .all(|cookie| cookie.contains("Max-Age=0"))
        );
        for (index, table) in ["users", "accounts", "sessions"].iter().enumerate() {
            let original: Vec<Value> = serde_json::from_str(&before[index])?;
            let expected: Vec<_> = original
                .into_iter()
                .filter(|row| row[if *table == "users" { "id" } else { "user_id" }] != *id)
                .collect();
            let actual: Vec<Value> = serde_json::from_str(&db.table(table).await?)?;
            assert_eq!(actual, expected, "unexpected changes to {table}");
        }
        assert_eq!(db.table("verifications").await?, "[]");
        assert_eq!(
            observer.0.lock().unwrap().last().unwrap().as_deref(),
            id.as_str()
        );
        let before_replay = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let replay = auth
            .dispatch_endpoint(endpoint(&json!({"token":token}))?, options(target))
            .await
            .unwrap_err();
        assert_eq!(replay.error.status_code(), 404);
        assert!(replay.error.to_string().contains("Failed to get user info"));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before_replay
        );
    }
    authenticated(
        &auth,
        &cookies(&bystander),
        "logical-callback-bystander@example.test",
    )
    .await;
    B::close(connection).await
}
