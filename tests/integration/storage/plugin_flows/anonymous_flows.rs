//! Anonymous identity generation, remember-me sessions, account linking and
//! storage failures.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::AnonymousPlugin;
use alibi::plugins::anonymous::{
    AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount,
};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use alibi::{AuthResult, CreateSession, CreateUser};
use std::collections::BTreeMap;

backend_tests!(
    anonymous_identity_and_lifecycle,
    anonymous_creation_failures,
    anonymous_deletion_and_linking,
    anonymous_transfer_uses_original_completed_snapshot
);

#[derive(Default)]
struct Identity(Mutex<Option<String>>);

#[async_trait::async_trait]
impl AnonymousIdentity for Identity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Linker(Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl LinkAnonymousAccount for Linker {
    async fn link(&self, accounts: &AnonymousLink, _: &AuthRequest) -> AuthResult<()> {
        self.0.lock().unwrap().push((
            accounts.anonymous_user.id.clone(),
            accounts.new_user.id.clone(),
        ));
        assert_eq!(accounts.new_session.user_id, accounts.new_user.id);
        Ok(())
    }
}

#[derive(Default)]
struct Cancel {
    users: Mutex<bool>,
    sessions: Mutex<bool>,
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> DatabaseHooks<S, B> for Cancel {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(
            if *self.users.lock().unwrap() && user.is_anonymous == Some(true) {
                HookControl::Cancel
            } else {
                HookControl::Continue
            },
        )
    }
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        Ok(if *self.sessions.lock().unwrap() {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
}

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            _ = jar.insert(name.to_owned(), value.to_owned());
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn trigger(db: &Db, name: &str, event: &str, table: &str) -> TestResult {
    _ = db
        .execute(
            &format!("CREATE TRIGGER {name} BEFORE {event} ON {table} BEGIN SELECT RAISE(ABORT, 'forced'); END"),
            &[],
        )
        .await?;
    Ok(())
}

async fn anonymous_identity_and_lifecycle<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let identity = Arc::new(Identity::default());
    let auth = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            identity: Some(identity.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    for (label, email) in [
        ("malformed generated email", Some("not-an-email")),
        ("generated email", Some("generated-anonymous@example.test")),
        ("default email", None),
    ] {
        *identity.0.lock().unwrap() = email.map(str::to_owned);
        let response =
            Box::pin(auth.handle_request(request("/sign-in/anonymous", Some(json!({})), "")))
                .await?;
        trace.response(label, &response);
        trace.value(
            &format!("{label} user"),
            json!(
                body(&response)["user"]["email"].as_str().map(|email| email
                    .rsplit('@')
                    .next()
                    .unwrap()
                    .to_owned())
            ),
        );
        if response.status == 200 {
            let current = cookies(&response);
            trace.response(
                &format!("{label}: second anonymous sign-in"),
                &Box::pin(auth.handle_request(request(
                    "/sign-in/anonymous",
                    Some(json!({})),
                    &current,
                )))
                .await?,
            );
        }
    }

    let remembered = call(
        &auth,
        request(
            "/sign-up/email",
            Some(json!({"email": "remembered@example.test", "password": PASSWORD, "name": "R"})),
            "",
        ),
        200,
    )
    .await;
    _ = remembered;
    let device = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "remembered@example.test", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let from_remembered = Box::pin(auth.handle_request(request(
        "/sign-in/anonymous",
        Some(json!({})),
        &cookies(&device),
    )))
    .await?;
    trace.response("anonymous from a remember-me browser", &from_remembered);
    assert!(cookies(&from_remembered).contains("dont_remember"));
    trace.assert("anonymous/identity-and-lifecycle");
    B::close(connection).await
}

async fn anonymous_creation_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cancel = Arc::new(Cancel::default());
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        SharedCancel(cancel.clone()),
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(AnonymousPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let anonymous = || request("/sign-in/anonymous", Some(json!({})), "");
    *cancel.users.lock().unwrap() = true;
    trace.response(
        "user creation cancelled",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    *cancel.users.lock().unwrap() = false;
    *cancel.sessions.lock().unwrap() = true;
    trace.response(
        "session creation cancelled",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    *cancel.sessions.lock().unwrap() = false;
    trigger(&db, "fail_user_insert", "INSERT", "users").await?;
    trace.response(
        "user storage failure",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    _ = db.execute("DROP TRIGGER fail_user_insert", &[]).await?;
    trigger(&db, "fail_session_insert", "INSERT", "sessions").await?;
    trace.response(
        "session storage failure",
        &Box::pin(auth.handle_request(anonymous())).await?,
    );
    _ = db.execute("DROP TRIGGER fail_session_insert", &[]).await?;
    trace.value("users left", json!(db.count("users").await?));
    trace.assert("anonymous/creation-failures");
    B::close(connection).await
}

struct SharedCancel(Arc<Cancel>);

#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> DatabaseHooks<S, B> for SharedCancel {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        DatabaseHooks::<S, B>::before_create_user(&*self.0, user, context).await
    }
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        DatabaseHooks::<S, B>::before_create_session(&*self.0, session, context).await
    }
}

async fn anonymous_deletion_and_linking<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let linker = Arc::new(Linker::default());
    let enabled = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(linker.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let anonymous = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let anonymous_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&anonymous_id);
    let linked = Box::pin(enabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "linked@example.test", "password": PASSWORD, "name": "Linked"})),
        &cookies(&anonymous),
    )))
    .await?;
    trace.response("upgrade by sign-up", &linked);
    assert_eq!(linker.0.lock().unwrap().len(), 1);
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE is_anonymous = 1", &[])
            .await?,
        0
    );
    let regular = cookies(&linked);
    trace.response(
        "delete as a regular user",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &regular,
        )))
        .await?,
    );
    trace.response(
        "delete without a session",
        &Box::pin(enabled.handle_request(request("/delete-anonymous-user", Some(json!({})), "")))
            .await?,
    );

    let second = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trigger(&db, "fail_session_delete", "DELETE", "sessions").await?;
    trace.response(
        "session cleanup failure",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&second),
        )))
        .await?,
    );
    _ = db.execute("DROP TRIGGER fail_session_delete", &[]).await?;
    let third = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trigger(&db, "fail_user_delete", "DELETE", "users").await?;
    trace.response(
        "user cleanup failure",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&third),
        )))
        .await?,
    );
    let upgraded = Box::pin(enabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "undeletable@example.test", "password": PASSWORD, "name": "U"})),
        &cookies(&third),
    )))
    .await?;
    trace.response("upgrade with cleanup failure", &upgraded);
    _ = db.execute("DROP TRIGGER fail_user_delete", &[]).await?;
    let fourth = call(
        &enabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.response(
        "delete anonymous",
        &Box::pin(enabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&fourth),
        )))
        .await?,
    );

    let fresh = db.fresh().await?;
    let (disabled_connection, _) = fresh.migrated::<B>(SECRET).await?;
    let disabled = builder::<B>(&disabled_connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            disable_delete_anonymous_user: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let kept = call(
        &disabled,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.response(
        "deletion disabled",
        &Box::pin(disabled.handle_request(request(
            "/delete-anonymous-user",
            Some(json!({})),
            &cookies(&kept),
        )))
        .await?,
    );
    let merged = Box::pin(disabled.handle_request(request(
        "/sign-up/email",
        Some(json!({"email": "kept@example.test", "password": PASSWORD, "name": "K"})),
        &merge("", &cookies(&kept)),
    )))
    .await?;
    trace.response("upgrade keeps the anonymous user", &merged);
    B::close(disabled_connection).await?;
    trace.assert("anonymous/deletion-and-linking");
    B::close(connection).await
}

async fn anonymous_transfer_uses_original_completed_snapshot<B: Backend>(db: Db) -> TestResult {
    use alibi::AuthSession;
    struct Hook(crate::storage::Raw);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: alibi::store::HookBackend> DatabaseHooks<S, H> for Hook {
        async fn after_create_session(
            &self,
            session: &S::Session,
            context: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            if context
                .request
                .as_ref()
                .is_some_and(|request| request.path.ends_with("/sign-up/email"))
            {
                _ = self
                    .0
                    .execute(
                        "UPDATE users SET name='Stored Hook Name' WHERE id=$1",
                        &[session.user_id().as_ref()],
                    )
                    .await
                    .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
            }
            Ok(())
        }
    }
    struct Capture(Mutex<Vec<Value>>);
    #[async_trait::async_trait]
    impl LinkAnonymousAccount for Capture {
        async fn link(&self, link: &AnonymousLink, request: &AuthRequest) -> AuthResult<()> {
            self.0.lock().unwrap().push(json!({"anonymousUser":link.anonymous_user,"anonymousSession":link.anonymous_session,"newUser":link.new_user,"newSession":link.new_session,"path":request.path}));
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let linker = Arc::new(Capture(Mutex::new(Vec::new())));
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .store(B::hook(
            B::store(
                Arc::new(AuthConfig::new(SECRET).base_url(ORIGIN)),
                &connection,
            ),
            Hook(db.raw.clone()),
        ))
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            on_link_account: Some(linker.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let foreign = signup(&auth, "foreign@example.test").await;
    let baseline = db.tables(&["users", "accounts", "sessions"]).await?;
    let anonymous = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    let original = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&anonymous)),
            200,
        )
        .await,
    );
    let upgrade=call(&auth,request("/sign-up/email",Some(json!({"email":"upgrade@example.test","password":PASSWORD,"name":"Original New Owner"})),&cookies(&anonymous)),200).await;
    assert_eq!(body(&upgrade)["user"]["name"], "Original New Owner");
    let receipts = linker.0.lock().unwrap().clone();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["anonymousUser"], original["user"]);
    assert_eq!(receipts[0]["anonymousSession"], original["session"]);
    assert_eq!(receipts[0]["newUser"], body(&upgrade)["user"]);
    assert_eq!(receipts[0]["newSession"]["token"], body(&upgrade)["token"]);
    assert_eq!(
        receipts[0]["newSession"]["userId"],
        body(&upgrade)["user"]["id"]
    );
    assert!(
        receipts[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("/sign-up/email")
    );
    let old_id = body(&anonymous)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM users WHERE id=$1", &[&old_id])
            .await?,
        0
    );
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&old_id])
            .await?,
        0
    );
    let current = body(
        &call(
            &auth,
            request("/get-session", None, &cookies(&upgrade)),
            200,
        )
        .await,
    );
    assert_eq!(current["user"]["id"], body(&upgrade)["user"]["id"]);
    assert_eq!(current["user"]["name"], "Stored Hook Name");
    assert_eq!(current["session"]["token"], body(&upgrade)["token"]);
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    for (before, after) in baseline.iter().zip(after.iter()) {
        let before: Vec<Value> = serde_json::from_str(before)?;
        let after: Vec<Value> = serde_json::from_str(after)?;
        assert!(before.iter().all(|row| after.contains(row)));
    }
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
