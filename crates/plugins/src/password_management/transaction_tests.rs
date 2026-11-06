use super::*;
use crate::test_helpers;
use alibi_core::session::cookie_cache::runtime::{published_session, take_issuance};
use alibi_core::session::cookie_cache::{
    CacheVersionContext, CookieCacheVersion, CookieCacheVersionResolver,
};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{CookieCacheConfig, CreateAccount, CreateSession, CreateUser, UpdateAccount};
use alibi_seaorm::{
    Database, DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore,
};
use chrono::Duration;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
type TestSession = <TestSchema as alibi_core::AuthSchema>::Session;
type TestAccount = <TestSchema as alibi_core::AuthSchema>::Account;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    None,
    Delete,
    Update,
    Create,
    CancelCreate,
    AfterDelete,
    AfterUpdate,
    AfterCreate,
    Cookies,
}

struct Hooks {
    armed: AtomicBool,
    failure: Failure,
    events: Mutex<Vec<&'static str>>,
}

impl Hooks {
    fn before(&self, event: &'static str, ctx: &SeaOrmHookContext<'_>) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        assert!(ctx.tx.is_some(), "{event} must run inside the transaction");
        self.events.lock().unwrap().push(event);
        true
    }

    fn after(&self, event: &'static str, ctx: &SeaOrmHookContext<'_>) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        assert!(ctx.tx.is_none(), "{event} must run after commit");
        self.events.lock().unwrap().push(event);
        true
    }

    fn error() -> AuthError {
        AuthError::Upstream {
            status: 503,
            code: "TEST_ADAPTER_FAILURE",
            message: "adapter failure",
        }
    }

    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl DatabaseHooks<TestSchema, SeaOrmBackend> for Hooks {
    async fn before_delete_session(
        &self,
        _: &TestSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.before("delete", ctx) && self.failure == Failure::Delete {
            return Err(Self::error());
        }
        Ok(HookControl::Continue)
    }

    async fn before_update_account(
        &self,
        _: &str,
        _: &mut UpdateAccount,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.before("update", ctx) && self.failure == Failure::Update {
            return Err(Self::error());
        }
        Ok(HookControl::Continue)
    }

    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.before("create", ctx) {
            match self.failure {
                Failure::Create => return Err(Self::error()),
                Failure::CancelCreate => return Ok(HookControl::Cancel),
                _ => {}
            }
        }
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        _: &TestSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.after("after_delete", ctx) && self.failure == Failure::AfterDelete {
            return Err(Self::error());
        }
        Ok(())
    }

    async fn after_update_account(
        &self,
        _: &TestAccount,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.after("after_update", ctx) && self.failure == Failure::AfterUpdate {
            return Err(Self::error());
        }
        Ok(())
    }

    async fn after_create_session(
        &self,
        _: &TestSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.after("after_create", ctx) && self.failure == Failure::AfterCreate {
            return Err(Self::error());
        }
        Ok(())
    }
}

#[async_trait]
impl CookieCacheVersionResolver for Hooks {
    async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String> {
        if context.source() == alibi_core::session::cookie_cache::CacheVersionSource::Created {
            let mut events = self.events.lock().unwrap();
            assert_eq!(events.last(), Some(&"after_create"));
            events.push("issuance");
            if self.failure == Failure::Cookies {
                return Err(AuthError::internal("cookie version failure"));
            }
        }
        Ok("1".into())
    }
}

struct TestHasher;

#[async_trait]
impl PasswordHasher for TestHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("hash:{password}"))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("hash:{password}"))
    }
}

struct Fixture {
    ctx: AuthContext<TestSchema>,
    user: UserView,
    sessions: Vec<SessionView>,
    hooks: Arc<Hooks>,
}

impl Fixture {
    async fn new(failure: Failure) -> Self {
        let hooks = Arc::new(Hooks {
            armed: AtomicBool::new(false),
            failure,
            events: Mutex::new(Vec::new()),
        });
        let mut config = test_helpers::create_test_config();
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: true,
            version: Some(CookieCacheVersion::Resolver(hooks.clone())),
            ..Default::default()
        });
        let config = Arc::new(config);
        let db = Database::connect("sqlite::memory:").await.unwrap();
        alibi_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let ctx = AuthContext::new(
            config.clone(),
            Arc::new(SeaOrmStore::<TestSchema>::new(config, db).with_hooks(vec![hooks.clone()])),
        );
        let user = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("transaction@example.com")
                .with_name("Owner"),
        )
        .await;
        ctx.database
            .create_account(CreateAccount {
                user_id: user.id.clone(),
                account_id: user.id.clone(),
                provider_id: "credential".into(),
                password: Some("hash:Password123!".into()),
                additional_fields: Default::default(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            })
            .await
            .unwrap();
        for _ in 0..2 {
            test_helpers::create_session(&ctx, user.id.clone(), ctx.config.session.expires_in)
                .await;
        }
        let sessions = ctx
            .database
            .get_user_sessions(&user.id)
            .await
            .unwrap()
            .iter()
            .map(SessionView::from)
            .collect();
        hooks.armed.store(true, Ordering::SeqCst);
        Self {
            ctx,
            user,
            sessions,
            hooks,
        }
    }

    async fn change(&self, revoke: Option<bool>) -> (AuthRequest, AuthResult<AuthResponse>) {
        let mut body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });
        if let Some(revoke) = revoke {
            body["revokeOtherSessions"] = revoke.into();
        }
        let mut request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&self.sessions[0].token),
            Some(body),
        );
        request
            .headers
            .insert("x-forwarded-for".into(), "127.0.0.1".into());
        request
            .headers
            .insert("user-agent".into(), "test-agent".into());
        let plugin = PasswordManagementPlugin::new().password_hasher(Arc::new(TestHasher));
        let response = alibi_core::hooks::with_request_hook_context(
            &request,
            plugin.handle_change_password(&request, &self.ctx),
        )
        .await;
        (request, response)
    }

    async fn assert_password(&self, expected: &str) {
        let accounts = self
            .ctx
            .database
            .get_user_accounts(&self.user.id)
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].password.as_deref(), Some(expected));
    }

    async fn assert_original_sessions(&self) {
        let sessions = self
            .ctx
            .database
            .get_user_sessions(&self.user.id)
            .await
            .unwrap();
        assert_eq!(sessions.len(), self.sessions.len());
        for original in &self.sessions {
            assert!(
                sessions
                    .iter()
                    .any(|session| SessionView::from(session) == *original)
            );
        }
    }

    async fn replacement(&self) -> SessionView {
        let sessions = self
            .ctx
            .database
            .get_user_sessions(&self.user.id)
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        let session = sessions.into_iter().next().unwrap();
        for original in &self.sessions {
            assert_ne!(session.token, original.token);
            assert!(
                self.ctx
                    .database
                    .get_session(&original.token)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        SessionView::from(&session)
    }
}

fn assert_unpublished(request: &AuthRequest) {
    assert!(published_session(request).is_none());
    assert!(
        request
            .extensions()
            .get::<crate::helpers::CompletedSession<TestSchema>>()
            .is_none()
    );
    assert_eq!(take_issuance(request.extensions()), (Vec::new(), false));
}

// update-user.ts:282-307: deletion, credential update, and replacement creation
// share the transaction; a false create result becomes FAILED_TO_GET_SESSION.
#[tokio::test]
async fn change_password_transaction_creation_failure_rolls_back() {
    for failure in [Failure::Create, Failure::CancelCreate] {
        let fixture = Fixture::new(failure).await;
        let (request, response) = fixture.change(Some(true)).await;
        let error = response.unwrap_err();
        let (status, code) = if failure == Failure::CancelCreate {
            (500, codes::FAILED_TO_GET_SESSION)
        } else {
            (503, "TEST_ADAPTER_FAILURE")
        };
        assert!(
            matches!(error, AuthError::Upstream { status: actual_status, code: actual_code, .. }
            if actual_status == status && actual_code == code)
        );
        fixture.assert_password("hash:Password123!").await;
        fixture.assert_original_sessions().await;
        assert_eq!(
            fixture.hooks.events(),
            ["delete", "delete", "update", "create"]
        );
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_transaction_write_failure_keeps_prior_state() {
    for failure in [Failure::Delete, Failure::Update] {
        let fixture = Fixture::new(failure).await;
        let (request, response) = fixture.change(Some(true)).await;
        assert!(matches!(
            response.unwrap_err(),
            AuthError::Upstream {
                status: 503,
                code: "TEST_ADAPTER_FAILURE",
                ..
            }
        ));
        fixture.assert_password("hash:Password123!").await;
        fixture.assert_original_sessions().await;
        let expected = if failure == Failure::Delete {
            vec!["delete"]
        } else {
            vec!["delete", "delete", "update"]
        };
        assert_eq!(fixture.hooks.events(), expected);
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_transaction_replacement_is_published_after_commit() {
    let fixture = Fixture::new(Failure::None).await;
    let (request, response) = fixture.change(Some(true)).await;
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let session = fixture.replacement().await;
    assert_eq!(body["token"], session.token);
    assert_eq!(body["user"]["id"], fixture.user.id);
    fixture.assert_password("hash:NewPassword123!").await;
    assert_eq!(session.user_id, fixture.user.id);
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(session.user_agent.as_deref(), Some("test-agent"));
    let lifetime = session.expires_at - session.created_at;
    assert!(lifetime <= fixture.ctx.config.session.expires_in);
    assert!(lifetime >= fixture.ctx.config.session.expires_in - Duration::seconds(1));
    assert!(response.headers.get("Set-Cookie").is_some());
    let (user, published) = published_session(&request).unwrap();
    assert_eq!(user.id, fixture.user.id);
    assert_eq!(published.token, session.token);
    assert!(
        request
            .extensions()
            .get::<crate::helpers::CompletedSession<TestSchema>>()
            .is_some()
    );
    let (cache_headers, ordinary_error) = take_issuance(request.extensions());
    assert!(!ordinary_error);
    assert!(!cache_headers.is_empty());
    assert_eq!(
        fixture.hooks.events(),
        [
            "delete",
            "delete",
            "update",
            "create",
            "after_delete",
            "after_delete",
            "after_update",
            "after_create",
            "issuance",
        ]
    );
}

#[tokio::test]
async fn change_password_transaction_without_revocation_preserves_sessions() {
    for revoke in [None, Some(false)] {
        let fixture = Fixture::new(Failure::Create).await;
        let (request, response) = fixture.change(revoke).await;
        let response = response.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["token"].is_null());
        assert_eq!(body["user"]["id"], fixture.user.id);
        assert!(response.headers.get("Set-Cookie").is_none());
        fixture.assert_password("hash:NewPassword123!").await;
        fixture.assert_original_sessions().await;
        assert_eq!(fixture.hooks.events(), ["update", "after_update"]);
        assert_unpublished(&request);
    }
}

// context/transaction.ts:155-190 runs queued hooks after commit and propagates
// their failures before update-user.ts:309-317 can publish the replacement.
#[tokio::test]
async fn change_password_transaction_after_hook_failure_keeps_replacement_unpublished() {
    for failure in [
        Failure::AfterDelete,
        Failure::AfterUpdate,
        Failure::AfterCreate,
    ] {
        let fixture = Fixture::new(failure).await;
        let (request, response) = fixture.change(Some(true)).await;
        assert!(matches!(
            response.unwrap_err(),
            AuthError::Upstream {
                status: 503,
                code: "TEST_ADAPTER_FAILURE",
                ..
            }
        ));
        fixture.assert_password("hash:NewPassword123!").await;
        fixture.replacement().await;
        let expected = [
            "delete",
            "delete",
            "update",
            "create",
            "after_delete",
            "after_delete",
            "after_update",
            "after_create",
        ];
        let count = match failure {
            Failure::AfterDelete => 5,
            Failure::AfterUpdate => 7,
            Failure::AfterCreate => 8,
            _ => unreachable!(),
        };
        assert_eq!(fixture.hooks.events(), expected[..count]);
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_transaction_cookie_failure_does_not_roll_back_committed_writes() {
    let fixture = Fixture::new(Failure::Cookies).await;
    let (request, response) = fixture.change(Some(true)).await;
    assert!(matches!(response.unwrap_err(), AuthError::Internal(message)
        if message == "cookie version failure"));
    fixture.assert_password("hash:NewPassword123!").await;
    fixture.replacement().await;
    assert!(published_session(&request).is_none());
    assert!(
        request
            .extensions()
            .get::<crate::helpers::CompletedSession<TestSchema>>()
            .is_none()
    );
    assert_eq!(take_issuance(request.extensions()), (Vec::new(), true));
    assert_eq!(
        fixture.hooks.events(),
        [
            "delete",
            "delete",
            "update",
            "create",
            "after_delete",
            "after_delete",
            "after_update",
            "after_create",
            "issuance",
        ]
    );
}
