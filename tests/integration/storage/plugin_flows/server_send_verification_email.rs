//! Direct verification delivery validates before reading a logical session.
use super::auth_probe::fast_password;
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{EmailVerificationPlugin, SendVerificationEmail};
use alibi::{AuthResult, UserView};

#[derive(Default)]
struct Inbox(Mutex<Vec<(UserView, String, String)>>);
#[async_trait::async_trait]
impl SendVerificationEmail for Inbox {
    async fn send(&self, user: &UserView, url: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.clone(), url.into(), token.into()));
        Ok(())
    }
}
fn endpoint(body: &Value) -> AuthResult<ServerEndpoint<Value>> {
    ServerEndpoint::new("email-verification", "sendVerificationEmail").with_body(body)
}
backend_tests!(server_send_verification_email_delivers_owned_proofs_for_logical_callers);
async fn server_send_verification_email_delivers_owned_proofs_for_logical_callers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let observer = Observer::new("sendVerificationEmail", "/send-verification-email");
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            ..Default::default()
        });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(
            EmailVerificationPlugin::new()
                .custom_send_verification_email(inbox.clone())
                .send_on_sign_up(false),
        )
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let email = "logical-send-owner@example.test";
    let owner = signup(&auth, email).await;
    let foreign_email = "logical-send-foreign@example.test";
    let foreign = signup(&auth, foreign_email).await;
    assert!(cookies(&owner).contains("better-auth.session_data="));
    assert!(inbox.0.lock().unwrap().is_empty());
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    for malformed in [
        json!(null),
        json!({}),
        json!({"email":7}),
        json!({"email":"invalid"}),
        json!({"email":email,"callbackURL":null}),
        json!({"email":email,"callbackURL":7}),
    ] {
        let rejected = auth
            .dispatch_endpoint(endpoint(&malformed)?, options(&owner))
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[body"));
    }
    let unknown = auth
        .dispatch_endpoint(
            endpoint(&json!({"email":"missing@example.test"}))?,
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        serde_json::to_value(unknown.value())?,
        json!({"status":true})
    );
    assert!(inbox.0.lock().unwrap().is_empty());
    let callback = "https://external.example/finish?kept=1#verified";
    let guest = auth.dispatch_endpoint(endpoint(&json!({"email":email,"callbackURL":callback,"userId":body(&foreign)["user"]["id"]}))?, EndpointOptions::default()).await?;
    assert_eq!(serde_json::to_value(guest.value())?, json!({"status":true}));
    assert!(guest.headers().get_all("set-cookie").next().is_none());
    assert!(observer.0.lock().unwrap().last().unwrap().is_none());
    let authenticated = auth
        .dispatch_endpoint(
            EmailVerificationPlugin::send_verification_email_endpoint(
                &alibi::plugins::email_verification::SendVerificationEmailRequest {
                    email: foreign_email.to_uppercase(),
                    callback_url: Some(String::new()),
                },
            )?,
            options(&foreign),
        )
        .await?;
    assert!(authenticated.decode()?.status);
    assert!(
        authenticated
            .headers()
            .get_all("set-cookie")
            .next()
            .is_none()
    );
    assert_eq!(
        observer.0.lock().unwrap().last().unwrap().as_deref(),
        body(&foreign)["user"]["id"].as_str()
    );
    let mismatch = auth
        .dispatch_endpoint(
            endpoint(&json!({"email":body(&foreign)["user"]["email"]}))?,
            options(&owner),
        )
        .await
        .unwrap_err();
    assert_eq!(mismatch.error.status_code(), 400);
    assert!(mismatch.error.to_string().contains("Email mismatch"));
    assert_eq!(
        db.tables(&["user", "account", "session", "verification"])
            .await?,
        before
    );
    let deliveries = inbox.0.lock().unwrap().clone();
    assert_eq!(deliveries.len(), 2);
    for (index, (user, url, token)) in deliveries.iter().enumerate() {
        let delivery_owner = if index == 0 { &owner } else { &foreign };
        assert_eq!(
            user.id,
            body(delivery_owner)["user"]["id"].as_str().unwrap()
        );
        assert_eq!(
            user.email.as_deref(),
            Some(if index == 0 { email } else { foreign_email })
        );
        assert!(!user.email_verified);
        let url = url::Url::parse(url)?;
        assert_eq!(url.path(), "/api/auth/verify-email");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("token"), Some(token));
        assert_eq!(
            query.get("callbackURL").map(String::as_str),
            Some(if index == 0 { callback } else { "/" })
        );
    }
    let verified = auth
        .dispatch_endpoint(
            EmailVerificationPlugin::verify_email_endpoint(
                &alibi::plugins::email_verification::VerifyEmailQuery {
                    token: deliveries[0].2.clone(),
                    callback_url: None,
                },
            )?,
            EndpointOptions::default(),
        )
        .await?;
    assert!(verified.decode()?.status);
    assert!(verified.decode()?.user.is_none());
    let before_users: Vec<Value> = serde_json::from_str(&before[0])?;
    let after_users: Vec<Value> = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(before_users.len(), after_users.len());
    let owner_id = body(&owner)["user"]["id"].clone();
    assert!(after_users.iter().any(|user| user["id"] == owner_id));
    for (before_user, after_user) in before_users.iter().zip(&after_users) {
        let mut expected = before_user.clone();
        if after_user["id"] == owner_id {
            expected["emailVerified"] = json!(1);
            expected["updatedAt"] = after_user["updatedAt"].clone();
        }
        assert_eq!(after_user, &expected);
    }
    assert_eq!(
        db.tables(&["account", "session", "verification"]).await?,
        before[1..]
    );
    B::close(connection).await
}
