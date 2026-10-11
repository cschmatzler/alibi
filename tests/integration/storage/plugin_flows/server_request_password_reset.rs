//! Headerless reset delivery through the public server operation.
use super::auth_probe::fast_builder;
use super::server_revocation_support::Observer;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::password_management::{
    PasswordManagementPlugin, RequestPasswordResetRequest, SendResetPassword,
};
use alibi::{AuthResult, StatusResponse};

#[derive(Default)]
struct Delivery(Mutex<Vec<(Value, String, String)>>);
#[async_trait::async_trait]
impl SendResetPassword for Delivery {
    async fn send(&self, user: &Value, url: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.clone(), url.into(), token.into()));
        Ok(())
    }
}
backend_tests!(server_request_password_reset_delivers_only_owned_redeemable_proof);
async fn server_request_password_reset_delivers_only_owned_redeemable_proof<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let sender = Arc::new(Delivery::default());
    let observer = Observer::new("requestPasswordReset", "/request-password-reset");
    let auth = fast_builder::<B>(&connection)
        .plugin(PasswordManagementPlugin::new().send_reset_password(sender.clone()))
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "logical-delivery-owner@example.test").await;
    let foreign = signup(&auth, "logical-delivery-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for input in [
        json!({}),
        json!({"email":null}),
        json!({"email":7}),
        json!({"email":"invalid"}),
        json!({"email":"logical-delivery-owner@example.test","redirectTo":null}),
        json!({"email":"logical-delivery-owner@example.test","redirectTo":7}),
    ] {
        let denied = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "requestPasswordReset")
                    .with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[body."));
    }
    let missing = auth
        .dispatch_endpoint(
            PasswordManagementPlugin::request_password_reset_endpoint(
                &RequestPasswordResetRequest {
                    email: "logical-delivery-missing@example.test".into(),
                    redirect_to: Some("https://external.example/reset".into()),
                },
            )?,
            EndpointOptions::default(),
        )
        .await?;
    assert!(missing.decode()?.status);
    assert_eq!(
        missing.decode()?.message,
        "If this email exists in our system, check your email for the reset link"
    );
    assert!(sender.0.lock().unwrap().is_empty());
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let unchanged = db.tables(&["users", "accounts", "sessions"]).await?;
    let sent = auth.dispatch_endpoint(ServerEndpoint::<Value>::new("password-management", "requestPasswordReset").with_body(&json!({"email":"logical-delivery-owner@example.test","redirectTo":"https://external.example/reset?a=1#step","userId":body(&foreign)["user"]["id"]}))?,EndpointOptions::default()).await?;
    assert_eq!(sent.value(), missing.value());
    assert_eq!(
        sent.headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    assert!(sent.headers().get_all("set-cookie").next().is_none());
    let (user, url, token) = sender.0.lock().unwrap()[0].clone();
    assert_eq!(user["id"], body(&owner)["user"]["id"]);
    assert_eq!(token.len(), 24);
    let url = url::Url::parse(&url)?;
    assert_eq!(url.origin().ascii_serialization(), ORIGIN);
    assert_eq!(url.path(), format!("/api/auth/reset-password/{token}"));
    assert_eq!(
        url.query_pairs()
            .find(|(name, _)| name == "callbackURL")
            .unwrap()
            .1,
        "https://external.example/reset?a=1#step"
    );
    let rows: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["identifier"], format!("reset-password:{token}"));
    assert_eq!(rows[0]["value"], body(&owner)["user"]["id"]);
    let expires = chrono::DateTime::parse_from_rfc3339(rows[0]["expires_at"].as_str().unwrap())?;
    assert!(
        (3590..=3600).contains(
            &expires
                .signed_duration_since(chrono::Utc::now())
                .num_seconds()
        )
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        unchanged
    );
    let reset = auth
        .dispatch_endpoint(
            ServerEndpoint::<StatusResponse>::new("password-management", "resetPassword")
                .with_body(
                    &json!({"token":token,"newPassword":"logical-delivery-replacement-205"}),
                )?,
            EndpointOptions::default(),
        )
        .await?;
    assert!(reset.decode()?.status);
    assert_eq!(db.count("verifications").await?, 0);
    let login = call(&auth,request("/sign-in/email",Some(json!({"email":"logical-delivery-owner@example.test","password":"logical-delivery-replacement-205"})),""),200).await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    assert!(observer.0.lock().unwrap().iter().all(Option::is_none));
    B::close(connection).await
}
