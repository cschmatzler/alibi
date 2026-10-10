use super::*;
use alibi::plugins::custom_session::{CustomSessionPlugin, SessionTransform};
use alibi::plugins::last_login_method::{
    BeforeStoreLastLoginMethodCookie, LastLoginMethodConfig, LastLoginMethodContext,
    LastLoginMethodPlugin,
};
use alibi::plugins::{BearerPlugin, MultiSessionPlugin};
use alibi::{AuthContext, AuthResult};
use async_trait::async_trait;
use reqwest::cookie::{CookieStore, Jar};

backend_tests!(
    last_login_consent_controls_tracking_cookie_without_changing_authentication,
    multiple_sessions_require_delivered_device_proofs,
    custom_session_projection_cannot_replace_bearer_authority,
    last_login_consent_error_keeps_database_tracking_and_issued_authority
);
postgres_tests!(
    last_login_consent_controls_tracking_cookie_without_changing_authentication,
    multiple_sessions_require_delivered_device_proofs,
    custom_session_projection_cannot_replace_bearer_authority
);

struct Consent(bool);
#[async_trait]
impl BeforeStoreLastLoginMethodCookie for Consent {
    async fn before_store(&self, _: &LastLoginMethodContext, _: &str) -> AuthResult<bool> {
        Ok(self.0)
    }
}

async fn last_login_consent_controls_tracking_cookie_without_changing_authentication<B: Backend>(
    db: Db,
) -> TestResult {
    for consent in [true, false] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
                store_in_database: true,
                before_store_cookie: Some(Arc::new(Consent(consent))),
                ..Default::default()
            }))
            .build()
            .await?;
        let issued = signup(&auth, "last-login@example.test").await;
        authenticated(&auth, &cookies(&issued), "last-login@example.test").await;
        assert_eq!(
            db.text("SELECT last_login_method FROM users", &[])
                .await?
                .as_deref(),
            Some("email")
        );
        assert_eq!(
            issued
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.last_used_login_method=email;")),
            consent
        );
        let denied = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"last-login@example.test","password":"wrong-password"})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_EMAIL_OR_PASSWORD");
        assert!(
            !denied
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.last_used_login_method="))
        );
        assert_eq!(db.count("sessions").await?, 1);
        B::close(connection).await?;
    }
    Ok(())
}

fn retain(jar: &Jar, response: &AuthResponse) {
    let values: Vec<_> = response
        .headers
        .get_all("set-cookie")
        .map(|value| reqwest::header::HeaderValue::from_str(value).unwrap())
        .collect();
    jar.set_cookies(&mut values.iter(), &url::Url::parse(ORIGIN).unwrap());
}
fn browser_cookie(jar: &Jar) -> String {
    jar.cookies(&url::Url::parse(ORIGIN).unwrap())
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

async fn multiple_sessions_require_delivered_device_proofs<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(MultiSessionPlugin::new())
        .build()
        .await?;
    let jar = Jar::default();
    let alice = signup(&auth, "alice-device@example.test").await;
    retain(&jar, &alice);
    let bob = call(
        &auth,
        request(
            "/sign-up/email",
            Some(json!({"email":"bob-device@example.test","password":PASSWORD,"name":"Bob"})),
            &browser_cookie(&jar),
        ),
        200,
    )
    .await;
    retain(&jar, &bob);
    let foreign = signup(&auth, "foreign-device@example.test").await;
    let listed = call(
        &auth,
        request(
            "/multi-session/list-device-sessions",
            None,
            &browser_cookie(&jar),
        ),
        200,
    )
    .await;
    let mut emails: Vec<_> = body(&listed)
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["user"]["email"].as_str().unwrap().to_owned())
        .collect();
    emails.sort();
    assert_eq!(
        emails,
        ["alice-device@example.test", "bob-device@example.test"]
    );
    let denied = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":body(&foreign)["token"]})),
            &browser_cookie(&jar),
        ),
        401,
    )
    .await;
    assert_eq!(body(&denied)["code"], "INVALID_SESSION_TOKEN");
    let selected = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":body(&alice)["token"]})),
            &browser_cookie(&jar),
        ),
        200,
    )
    .await;
    retain(&jar, &selected);
    authenticated(&auth, &browser_cookie(&jar), "alice-device@example.test").await;
    let revoked = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken":body(&alice)["token"]})),
            &browser_cookie(&jar),
        ),
        200,
    )
    .await;
    retain(&jar, &revoked);
    authenticated(&auth, &browser_cookie(&jar), "bob-device@example.test").await;
    authenticated(&auth, &cookies(&foreign), "foreign-device@example.test").await;
    assert_eq!(db.count("sessions").await?, 2);
    assert!(
        auth.store()
            .get_session(body(&alice)["token"].as_str().unwrap())
            .await?
            .is_none()
    );
    B::close(connection).await
}

struct Projection;
#[async_trait]
impl<S: AuthSchema> SessionTransform<S> for Projection {
    async fn transform(&self, _: Value, _: &AuthRequest, _: &AuthContext<S>) -> AuthResult<Value> {
        Ok(json!({"user":{"id":"presentation-only","email":"display@example.test"},"custom":true}))
    }
}

async fn custom_session_projection_cannot_replace_bearer_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(EmailPasswordPlugin::new())
        .plugin(CustomSessionPlugin::new(Projection))
        .plugin(SessionManagementPlugin::new())
        .plugin(BearerPlugin::new())
        .build()
        .await?;
    let issued = signup(&auth, "authority@example.test").await;
    let token = body(&issued)["token"].as_str().unwrap().to_owned();
    let mut read = request("/get-session", None, "");
    drop(
        read.headers
            .insert("authorization".into(), format!("Bearer {token}")),
    );
    let projected = call(&auth, read, 200).await;
    assert_eq!(body(&projected)["custom"], true);
    assert_eq!(body(&projected)["user"]["id"], "presentation-only");
    let mut sessions = request("/list-sessions", None, "");
    drop(
        sessions
            .headers
            .insert("authorization".into(), format!("Bearer {token}")),
    );
    let listed = call(&auth, sessions, 200).await;
    assert_eq!(body(&listed).as_array().unwrap().len(), 1);
    assert_eq!(body(&listed)[0]["userId"], body(&issued)["user"]["id"]);
    assert_eq!(
        db.text("SELECT email FROM users", &[]).await?.as_deref(),
        Some("authority@example.test")
    );
    let anonymous = call(&auth, request("/get-session", None, ""), 200).await;
    assert!(
        body(&anonymous).is_null(),
        "projection must never run for an unauthenticated caller"
    );
    B::close(connection).await
}

async fn last_login_consent_error_keeps_database_tracking_and_issued_authority<B: Backend>(
    db: Db,
) -> TestResult {
    struct Reject;
    #[async_trait]
    impl BeforeStoreLastLoginMethodCookie for Reject {
        async fn before_store(&self, _: &LastLoginMethodContext, _: &str) -> AuthResult<bool> {
            Err(alibi::AuthError::internal("consent unavailable"))
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            before_store_cookie: Some(Arc::new(Reject)),
            ..Default::default()
        }))
        .build()
        .await?;
    let issued = signup(&auth, "owner@example.test").await;
    let id = body(&issued)["user"]["id"].as_str().unwrap().to_owned();
    for response in [
        issued,
        call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await,
    ] {
        assert!(
            !response
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with("better-auth.last_used_login_method="))
        );
        authenticated(&auth, &cookies(&response), "owner@example.test").await;
        assert_eq!(
            db.text("SELECT last_login_method FROM users WHERE id=$1", &[&id])
                .await?
                .as_deref(),
            Some("email")
        );
    }
    assert_eq!(db.count("sessions").await?, 2);
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"owner@example.test","password":"incorrect"})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    B::close(connection).await
}
