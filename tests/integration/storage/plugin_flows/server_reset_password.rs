//! Public reset dispatch consumes delivered proofs without requiring a session.
use super::auth_probe::fast_builder;
use super::server_revocation_support::Observer;
use super::*;
use alibi::AuthResult;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::password_management::{
    PasswordManagementPlugin, ResetPasswordRequest, SendResetPassword,
};

#[derive(Default)]
struct Delivery(Mutex<Vec<String>>);
#[async_trait::async_trait]
impl SendResetPassword for Delivery {
    async fn send(&self, _: &Value, _: &str, token: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(token.into());
        Ok(())
    }
}
backend_tests!(server_reset_password_consumes_owned_proof_without_session);
async fn server_reset_password_consumes_owned_proof_without_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let delivery = Arc::new(Delivery::default());
    let observer = Observer::new("resetPassword", "/reset-password");
    let auth = fast_builder::<B>(&connection)
        .plugin(PasswordManagementPlugin::new().send_reset_password(delivery.clone()))
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "logical-reset-owner@example.test").await;
    let foreign = signup(&auth, "logical-reset-foreign@example.test").await;
    for email in [
        "logical-reset-owner@example.test",
        "logical-reset-foreign@example.test",
    ] {
        let _ = call(
            &auth,
            request("/request-password-reset", Some(json!({"email":email})), ""),
            200,
        )
        .await;
    }
    let proofs = delivery.0.lock().unwrap().clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (input, query) in [
        (json!({}), json!({})),
        (json!({"newPassword":null}), json!({})),
        (json!({"newPassword":PASSWORD,"token":null}), json!({})),
        (
            json!({"newPassword":PASSWORD,"token":proofs[0]}),
            json!({"token":7}),
        ),
        (json!({"newPassword":PASSWORD}), json!(null)),
    ] {
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "resetPassword")
                    .with_body(&input)?
                    .with_query(&query)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("["));
    }
    for input in [
        json!({"newPassword":PASSWORD}),
        json!({"newPassword":"short","token":proofs[0]}),
    ] {
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "resetPassword")
                    .with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400);
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    let users = db.table("users").await?;
    let sessions = db.table("sessions").await?;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let proof_rows: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
    let foreign_proof: Vec<_> = proof_rows
        .into_iter()
        .filter(|row| row["identifier"] == format!("reset-password:{}", proofs[1]))
        .collect();
    assert_eq!(foreign_proof.len(), 1);
    let accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    let reset = auth.dispatch_endpoint(PasswordManagementPlugin::reset_password_endpoint(&ResetPasswordRequest { new_password: "logical-replacement-205".into(), token: Some(proofs[0].clone()) })?
        .with_body(&json!({"newPassword":"logical-replacement-205","token":proofs[0],"userId":foreign_id}))?
        .with_query(&json!({"token":proofs[1]}))?, EndpointOptions::default()).await?;
    assert!(reset.decode()?.status);
    assert_eq!(
        reset
            .headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    assert!(reset.headers().get_all("set-cookie").next().is_none());
    assert_eq!(db.table("users").await?, users);
    assert_eq!(db.table("sessions").await?, sessions);
    let after_accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    assert_eq!(
        after_accounts
            .into_iter()
            .filter(|r| r["user_id"] == foreign_id)
            .collect::<Vec<_>>(),
        accounts
            .into_iter()
            .filter(|r| r["user_id"] == foreign_id)
            .collect::<Vec<_>>()
    );
    let remaining: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
    assert_eq!(remaining, foreign_proof);
    let after = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let replay = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("password-management", "resetPassword")
                .with_body(&json!({"newPassword":PASSWORD,"token":proofs[0]}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(replay.error.status_code(), 400);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        after
    );
    let _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logical-reset-owner@example.test","password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    let login = call(&auth,request("/sign-in/email",Some(json!({"email":"logical-reset-owner@example.test","password":"logical-replacement-205"})),""),200).await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    let fallback = auth
        .dispatch_endpoint(
            PasswordManagementPlugin::reset_password_endpoint(&ResetPasswordRequest {
                new_password: "foreign-replacement-205".into(),
                token: Some(String::new()),
            })?
            .with_query(&json!({"token":proofs[1]}))?,
            EndpointOptions::default(),
        )
        .await?;
    assert!(fallback.decode()?.status);
    assert_eq!(db.count("verifications").await?, 0);
    assert!(observer.0.lock().unwrap().iter().all(Option::is_none));
    B::close(connection).await
}
