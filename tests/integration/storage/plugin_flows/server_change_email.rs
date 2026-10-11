//! Logical mailbox changes deliver a bound challenge before committing the authenticated owner.
use super::auth_probe::fast_password;
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{EmailVerificationPlugin, SendVerificationEmail, UserManagementPlugin};
use alibi::{AuthResult, UserView};

#[derive(Default)]
struct Mailbox(Mutex<Vec<(UserView, String, String)>>);
#[async_trait::async_trait]
impl SendVerificationEmail for Mailbox {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.clone(), url.into(), token.into()));
        Ok(())
    }
}
fn endpoint(body: &Value) -> AuthResult<ServerEndpoint<alibi::StatusResponse>> {
    UserManagementPlugin::change_email_endpoint(
        &alibi::plugins::user_management::ChangeEmailRequest {
            new_email: String::new(),
            callback_url: None,
        },
    )?
    .with_body(body)
}
backend_tests!(server_change_email_delivers_and_redeems_only_authenticated_owner_challenge);
async fn server_change_email_delivers_and_redeems_only_authenticated_owner_challenge<B: Backend>(
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
    let observer = Observer::new("changeEmail", "/change-email");
    let verifier_observer = Observer::new("verifyEmail", "/verify-email");
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(UserManagementPlugin::new().change_email_enabled(true))
        .plugin(
            EmailVerificationPlugin::new()
                .send_on_sign_up(false)
                .custom_send_verification_email(mailbox.clone()),
        )
        .endpoint_hook(observer.clone())
        .endpoint_hook(verifier_observer.clone())
        .build()
        .await?;
    let old = "logical-mailbox-owner@example.test";
    let new = "logical-mailbox-next@example.test";
    let owner = signup(&auth, old).await;
    let foreign = signup(&auth, "logical-mailbox-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for malformed in [
        json!(null),
        json!({}),
        json!({"newEmail":7}),
        json!({"newEmail":"invalid"}),
        json!({"newEmail":new,"callbackURL":null}),
        json!({"newEmail":new,"callbackURL":7}),
    ] {
        let rejected = auth
            .dispatch_endpoint(endpoint(&malformed)?, options(&owner))
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[body"));
    }
    let guest = auth
        .dispatch_endpoint(
            endpoint(&json!({"newEmail":new}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let same = auth
        .dispatch_endpoint(
            UserManagementPlugin::change_email_endpoint(
                &alibi::plugins::user_management::ChangeEmailRequest {
                    new_email: old.to_uppercase(),
                    callback_url: None,
                },
            )?,
            options(&owner),
        )
        .await
        .unwrap_err();
    assert_eq!(same.error.status_code(), 400);
    assert!(same.error.to_string().contains("Email is the same"));
    let existing=auth.dispatch_endpoint(endpoint(&json!({"newEmail":body(&foreign)["user"]["email"].as_str().unwrap().to_uppercase()}))?,options(&owner)).await?;
    assert!(existing.decode()?.status);
    assert!(mailbox.0.lock().unwrap().is_empty());
    let callback = "https://external.example/mailbox?kept=1#verified";
    let requested=auth.dispatch_endpoint(endpoint(&json!({"newEmail":new.to_uppercase(),"callbackURL":callback,"userId":body(&foreign)["user"]["id"]}))?,options(&owner)).await?;
    assert!(requested.decode()?.status);
    assert_eq!(
        observer.0.lock().unwrap().last().unwrap().as_deref(),
        owner_id.as_str()
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let delivered = mailbox.0.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    let (user, url, token) = &delivered[0];
    assert_eq!(user.id, owner_id.as_str().unwrap());
    assert_eq!(user.email.as_deref(), Some(new));
    assert!(!user.email_verified);
    let url = url::Url::parse(url)?;
    assert_eq!(url.path(), "/api/auth/verify-email");
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query.get("callbackURL").map(String::as_str), Some(callback));
    assert_eq!(query.get("token"), Some(token));
    let verified = auth
        .dispatch_endpoint(
            EmailVerificationPlugin::verify_email_endpoint(
                &alibi::plugins::email_verification::VerifyEmailQuery {
                    token: token.clone(),
                    callback_url: None,
                },
            )?,
            options(&owner),
        )
        .await?;
    assert_eq!(
        verifier_observer
            .0
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .as_deref(),
        owner_id.as_str()
    );
    let verified = verified.decode()?;
    assert!(verified.status);
    let verified = verified.user.unwrap();
    assert_eq!(verified.id, owner_id.as_str().unwrap());
    assert_eq!(verified.email.as_deref(), Some(new));
    assert!(verified.email_verified);
    let original: Vec<Value> = serde_json::from_str(&before[0])?;
    let actual: Vec<Value> = serde_json::from_str(&db.table("users").await?)?;
    assert_eq!(actual.len(), original.len());
    for (original, actual) in original.iter().zip(&actual) {
        let mut expected = original.clone();
        if actual["id"] == owner_id {
            expected["email"] = json!(new);
            expected["email_verified"] = json!(1);
            expected["updated_at"] = actual["updated_at"].clone();
        }
        assert_eq!(actual, &expected);
    }
    assert_eq!(
        db.tables(&["accounts", "sessions", "verifications"])
            .await?,
        before[1..]
    );
    let after = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let replay = auth
        .dispatch_endpoint(
            EmailVerificationPlugin::verify_email_endpoint(
                &alibi::plugins::email_verification::VerifyEmailQuery {
                    token: token.clone(),
                    callback_url: None,
                },
            )?,
            options(&owner),
        )
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 401);
    assert!(replay.error.to_string().contains("User not found"));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        after
    );
    let signin = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":new,"password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&signin)["user"]["id"], owner_id);
    B::close(connection).await
}
