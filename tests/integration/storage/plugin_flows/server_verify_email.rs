//! Public verification dispatch verifies the proof owner without an HTTP request.
use super::auth_probe::fast_builder;
use super::server_revocation_support::Observer;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{EmailVerificationPlugin, SendVerificationEmail};
use alibi::{AuthResult, UserView};

#[derive(Default)]
struct Inbox(Mutex<Vec<(String, String)>>);
#[async_trait::async_trait]
impl SendVerificationEmail for Inbox {
    async fn send(&self, user: &UserView, _: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.email.clone().unwrap(), token.into()));
        Ok(())
    }
}
fn endpoint(query: &Value) -> AuthResult<ServerEndpoint<Value>> {
    ServerEndpoint::new("email-verification", "verifyEmail").with_query(query)
}
backend_tests!(server_verify_email_changes_only_proof_owner_without_request);
async fn server_verify_email_changes_only_proof_owner_without_request<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let observer = Observer::new("verifyEmail", "/verify-email");
    let auth = fast_builder::<B>(&connection)
        .plugin(
            EmailVerificationPlugin::new()
                .custom_send_verification_email(inbox.clone())
                .send_on_sign_up(true),
        )
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "logical-verification-owner@example.test").await;
    let foreign = signup(&auth, "logical-verification-foreign@example.test").await;
    let token = inbox
        .0
        .lock()
        .unwrap()
        .iter()
        .find(|(email, _)| email == "logical-verification-owner@example.test")
        .unwrap()
        .1
        .clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for query in [
        json!({}),
        json!(null),
        json!({"token":null}),
        json!({"token":7}),
        json!({"token":token,"callbackURL":null}),
        json!({"token":token,"callbackURL":7}),
    ] {
        let rejected = auth
            .dispatch_endpoint(endpoint(&query)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[query"));
    }
    let invalid = auth
        .dispatch_endpoint(
            endpoint(&json!({"token":"not.a.token"}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(invalid.error.status_code(), 401);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let unchanged = db
        .tables(&["accounts", "sessions", "verifications"])
        .await?;
    let users: Vec<Value> = serde_json::from_str(&db.table("users").await?)?;
    let verified = auth
        .dispatch_endpoint(
            endpoint(
                &json!({"token":token,"callbackURL":"","userId":body(&foreign)["user"]["id"]}),
            )?,
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        serde_json::to_value(verified.value())?,
        json!({"status":true,"user":null})
    );
    assert!(verified.headers().get_all("set-cookie").next().is_none());
    assert_eq!(
        verified
            .headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    assert_eq!(
        db.tables(&["accounts", "sessions", "verifications"])
            .await?,
        unchanged
    );
    let after_users: Vec<Value> = serde_json::from_str(&db.table("users").await?)?;
    let owner_id = body(&owner)["user"]["id"].clone();
    assert_eq!(users.len(), after_users.len());
    assert!(after_users.iter().any(|user| user["id"] == owner_id));
    for (before, after) in users.iter().zip(&after_users) {
        if after["id"] == owner_id {
            assert_eq!(after["email_verified"], json!(1));
            let mut expected = before.clone();
            expected["email_verified"] = json!(1);
            expected["updated_at"] = after["updated_at"].clone();
            assert_eq!(*after, expected);
        } else {
            assert_eq!(before, after);
        }
    }
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
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        serde_json::to_value(replay.value())?,
        json!({"status":true,"user":null})
    );
    assert!(replay.headers().get_all("set-cookie").next().is_none());
    for (proof, callback, expected) in [
        (
            token.as_str(),
            "https://external.example/done?kept=1#verified",
            "https://external.example/done?kept=1#verified",
        ),
        (
            "not.a.token",
            "/done?kept=1#verified",
            "/done?kept=1&error=INVALID_TOKEN#verified",
        ),
    ] {
        let redirect = auth
            .dispatch_endpoint(
                endpoint(&json!({"token":proof,"callbackURL":callback}))?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(redirect.error.status_code(), 302);
        assert!(redirect.body_absent);
        assert_eq!(
            redirect
                .headers
                .unwrap()
                .get("location")
                .map(String::as_str),
            Some(expected)
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            after
        );
    }
    assert!(observer.0.lock().unwrap().iter().all(Option::is_none));
    B::close(connection).await
}
