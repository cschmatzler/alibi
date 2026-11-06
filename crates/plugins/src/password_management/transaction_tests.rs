use super::*;
use crate::test_helpers;
use alibi_core::session::cookie_cache::runtime::{published_session, take_issuance};
use alibi_core::session::cookie_cache::{
    CacheVersionContext, CookieCacheVersion, CookieCacheVersionResolver,
};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{
    AuthUser, CookieCacheConfig, CreateAccount, CreateSession, CreateUser, UpdateAccount,
};
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
    Commit,
}

struct Hooks {
    armed: AtomicBool,
    failure: Failure,
    events: Mutex<Vec<&'static str>>,
    cache: Option<Arc<RecordingCache>>,
    revoke_after_create: bool,
    before_create_clock: Mutex<Option<chrono::DateTime<chrono::Utc>>>,
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
            *self.before_create_clock.lock().unwrap() = Some(chrono::Utc::now());
            match self.failure {
                Failure::Create => return Err(Self::error()),
                Failure::CancelCreate => return Ok(HookControl::Cancel),
                Failure::Commit => {
                    use alibi_seaorm::sea_orm::ConnectionTrait;
                    ctx.tx.unwrap().execute_unprepared(
                        "CREATE TABLE commit_failure (id TEXT REFERENCES user(id) DEFERRABLE INITIALLY DEFERRED)"
                    ).await.unwrap();
                    ctx.tx
                        .unwrap()
                        .execute_unprepared("INSERT INTO commit_failure VALUES ('missing-user')")
                        .await
                        .unwrap();
                }
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
        session: &TestSession,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.after("after_create", ctx) {
            if self.failure == Failure::AfterCreate {
                return Err(Self::error());
            }
            if self.revoke_after_create {
                use alibi_core::AuthSession;
                use alibi_core::store::CacheAdapter;
                let cache = self.cache.as_ref().unwrap();
                assert!(
                    cache.get(session.token()).await?.is_some(),
                    "mirror must precede after-create"
                );
                cache.delete(session.token()).await?;
            }
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

#[tokio::test]
async fn cached_session_envelope_without_rust_metadata_remains_usable() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let token = &fixture.sessions[0].token;
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    snapshot.as_object_mut().unwrap().remove("absent_fields");
    cache
        .set(token, &snapshot.to_string(), Duration::hours(1))
        .await
        .unwrap();
    assert!(fixture.raw.get_session(token).await.unwrap().is_none());
    assert!(
        fixture
            .ctx
            .database
            .get_session(token)
            .await
            .unwrap()
            .is_some()
    );
    let owner = fixture
        .ctx
        .database
        .get_session_user_record(token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.stored().id, fixture.user.id);
    let expires_at = chrono::Utc::now() + Duration::hours(2);
    let updated = fixture
        .ctx
        .database
        .refresh_session(token, expires_at)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.expires_at, expires_at);
    assert!(
        fixture
            .ctx
            .database
            .get_session(token)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cached_session_token_does_not_replace_its_lookup_key() {
    use alibi_core::{AuthSession, store::CacheAdapter};
    for persist in [false, true] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), persist, false, false)
                .await;
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        let token = &fixture.sessions[0].token;
        let embedded_token = "cached-token-with-no-database-row";
        let mut snapshot: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        snapshot["session"]["token"] = embedded_token.into();
        cache
            .set(token, &snapshot.to_string(), Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(token)
                .await
                .unwrap()
                .unwrap()
                .token(),
            embedded_token
        );
        let expires_at = chrono::Utc::now() + Duration::hours(2);
        let updated = fixture
            .ctx
            .database
            .refresh_session(token, expires_at)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.token(),
            if persist {
                token.as_str()
            } else {
                embedded_token
            }
        );
        assert_eq!(updated.expires_at(), expires_at);
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["session"]["token"], embedded_token);
        assert!(cache.get(embedded_token).await.unwrap().is_none());
        let key = format!("active-sessions-{}", fixture.user.id);
        let index: serde_json::Value =
            serde_json::from_str(&cache.get(&key).await.unwrap().unwrap()).unwrap();
        assert!(
            index
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["token"] == token.as_str())
        );
        assert!(
            !index
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["token"] == embedded_token)
        );
        let lookup = token.clone();
        let scoped =
            alibi_core::store::write_transaction(fixture.ctx.database.as_ref(), move |tx| {
                Box::pin(async move {
                    tx.update_session_active_organization(&lookup, Some("from-transaction"))
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(
            scoped.token(),
            if persist {
                token.as_str()
            } else {
                embedded_token
            }
        );
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["session"]["token"], embedded_token);
        assert!(cache.get(embedded_token).await.unwrap().is_none());
        if persist {
            let physical = fixture.raw.get_session(token).await.unwrap().unwrap();
            assert_eq!(physical.token(), token.as_str());
            assert_eq!(physical.expires_at(), expires_at);
            assert_eq!(physical.active_organization_id(), Some("from-transaction"));
        }
        fixture.ctx.database.delete_session(token).await.unwrap();
        assert!(cache.get(token).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn cached_owner_identity_remains_distinct_from_session_bookkeeping() {
    use alibi_core::{AuthSession, store::CacheAdapter};
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let token = &fixture.sessions[0].token;
    let cached_owner_id = "cached-owner-with-no-database-row";
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    snapshot["user"]["id"] = cached_owner_id.into();
    cache
        .set(token, &snapshot.to_string(), Duration::hours(1))
        .await
        .unwrap();
    assert!(
        fixture
            .raw
            .get_user_by_id(cached_owner_id)
            .await
            .unwrap()
            .is_none()
    );

    let owner = fixture
        .ctx
        .database
        .get_session_user_record(token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.id(), cached_owner_id);
    assert_eq!(serde_json::to_value(&owner).unwrap()["id"], cached_owner_id);
    assert_ne!(owner.id(), fixture.user.id);
    let session = fixture
        .ctx
        .database
        .get_session(token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.user_id(), fixture.user.id);

    fixture
        .ctx
        .database
        .refresh_session(token, chrono::Utc::now() + Duration::hours(2))
        .await
        .unwrap()
        .unwrap();
    let refreshed: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    assert_eq!(refreshed["user"]["id"], cached_owner_id);
    let sessions = fixture
        .ctx
        .database
        .get_user_sessions(&fixture.user.id)
        .await
        .unwrap();
    assert!(
        sessions
            .iter()
            .any(|session| session.token() == token.as_str())
    );
    assert!(
        fixture
            .ctx
            .database
            .get_user_sessions(cached_owner_id)
            .await
            .unwrap()
            .is_empty()
    );
    fixture
        .ctx
        .database
        .delete_user_sessions(&fixture.user.id)
        .await
        .unwrap();
    assert!(cache.get(token).await.unwrap().is_none());
}

#[tokio::test]
async fn secondary_session_index_uses_typescript_expiry_shape_for_listing_and_revocation() {
    use alibi_core::store::CacheAdapter;

    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let key = format!("active-sessions-{}", fixture.user.id);
    let own: serde_json::Value =
        serde_json::from_str(&cache.get(&key).await.unwrap().unwrap()).unwrap();
    for session in &fixture.sessions {
        let reference = own
            .as_array()
            .unwrap()
            .iter()
            .find(|reference| reference["token"] == session.token)
            .unwrap();
        assert_eq!(
            reference["expiresAt"],
            session.expires_at.timestamp_millis()
        );
        assert!(reference.get("expires_at").is_none());
    }

    let selected = &fixture.sessions[0];
    let upstream = serde_json::json!([
        { "token": selected.token, "expiresAt": selected.expires_at.timestamp_millis() },
        { "token": "already-expired", "expiresAt": 0 }
    ]);
    cache
        .set(&key, &upstream.to_string(), Duration::hours(1))
        .await
        .unwrap();
    let listed = fixture
        .ctx
        .database
        .get_user_sessions(&fixture.user.id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token, selected.token);

    fixture
        .ctx
        .database
        .delete_user_sessions(&fixture.user.id)
        .await
        .unwrap();
    assert!(cache.get(&selected.token).await.unwrap().is_none());
    assert!(cache.get(&key).await.unwrap().is_none());
    assert!(
        fixture
            .ctx
            .database
            .get_user_sessions(&fixture.user.id)
            .await
            .unwrap()
            .is_empty()
    );
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
    raw: Arc<dyn alibi_core::AuthStore<TestSchema>>,
    db: alibi_seaorm::sea_orm::DatabaseConnection,
}

impl Fixture {
    async fn new(failure: Failure) -> Self {
        Self::with_secondary(failure, None, true, false, false).await
    }

    async fn with_secondary(
        failure: Failure,
        cache: Option<Arc<RecordingCache>>,
        store_in_database: bool,
        preserve_in_database: bool,
        revoke_after_create: bool,
    ) -> Self {
        Self::with_secondary_output_counter(
            failure,
            cache,
            store_in_database,
            preserve_in_database,
            revoke_after_create,
            None,
        )
        .await
    }

    async fn with_secondary_output_counter(
        failure: Failure,
        cache: Option<Arc<RecordingCache>>,
        store_in_database: bool,
        preserve_in_database: bool,
        revoke_after_create: bool,
        output_calls: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        let hooks = Arc::new(Hooks {
            armed: AtomicBool::new(false),
            failure,
            events: Mutex::new(Vec::new()),
            cache: cache.clone(),
            revoke_after_create,
            before_create_clock: Mutex::new(None),
        });
        let mut config = test_helpers::create_test_config();
        if let Some(calls) = output_calls {
            config.user.additional_fields.insert(
                "emailVerified".into(),
                alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type": "boolean"}))
                    .transform_output(move |value| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async move {
                            let value = value.unwrap().coerce_string().unwrap();
                            Ok(Some(alibi_core::utils::json::JsValue::String(
                                format!("{value}:once").into(),
                            )))
                        }
                    }),
            );
        }
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: true,
            version: Some(CookieCacheVersion::Resolver(hooks.clone())),
            ..Default::default()
        });
        config.session.secondary_storage = cache
            .clone()
            .map(|cache| cache as Arc<dyn alibi_core::store::CacheAdapter>);
        config.session.store_in_database = store_in_database;
        config.session.preserve_in_database = preserve_in_database;
        let config = Arc::new(config);
        let db = Database::connect("sqlite::memory:").await.unwrap();
        alibi_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let raw: Arc<dyn alibi_core::AuthStore<TestSchema>> = Arc::new(
            SeaOrmStore::<TestSchema>::new(config.clone(), db.clone())
                .with_hooks(vec![hooks.clone()]),
        );
        let database = alibi_core::plugin::AuthInitContext::new(config.clone(), raw.clone())
            .database_with_registered_transforms();
        let ctx = AuthContext::new(config, database);
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
                account_id: user.id.clone().into(),
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
        if let Some(cache) = &cache {
            cache.armed.store(true, Ordering::SeqCst);
        }
        Self {
            ctx,
            user,
            sessions,
            hooks,
            raw,
            db,
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

enum IndexMutation {
    Rename(Arc<dyn alibi_core::AuthStore<TestSchema>>, String),
    Delete(Arc<dyn alibi_core::AuthStore<TestSchema>>, String),
}

struct RecordingCache {
    inner: alibi_core::store::MemoryCacheAdapter,
    armed: AtomicBool,
    fail_mirror: bool,
    fail_index: AtomicBool,
    writes: Mutex<Vec<String>>,
    index_mutation: Mutex<Option<IndexMutation>>,
}

impl RecordingCache {
    fn new(fail_mirror: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: alibi_core::store::MemoryCacheAdapter::new(),
            armed: AtomicBool::new(false),
            fail_mirror,
            fail_index: AtomicBool::new(false),
            writes: Mutex::new(Vec::new()),
            index_mutation: Mutex::new(None),
        })
    }
}

#[async_trait]
impl alibi_core::store::CacheAdapter for RecordingCache {
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> AuthResult<()> {
        let snapshot = serde_json::from_str::<serde_json::Value>(value).ok();
        let mirror = snapshot
            .as_ref()
            .is_some_and(|value| value.get("session").is_some());
        if self.armed.load(Ordering::SeqCst)
            && self.fail_index.load(Ordering::SeqCst)
            && key.starts_with("active-sessions-")
            && value != "[]"
        {
            return Err(Hooks::error());
        }
        if self.armed.load(Ordering::SeqCst) && mirror {
            self.writes.lock().unwrap().push(key.to_owned());
            if self.fail_mirror {
                return Err(Hooks::error());
            }
        }
        self.inner.set(key, value, ttl).await?;
        if key.starts_with("active-sessions-") && value != "[]" {
            let mutation = self.index_mutation.lock().unwrap().take();
            match mutation {
                Some(IndexMutation::Rename(store, id)) => {
                    store
                        .update_user(
                            &id,
                            alibi_core::UpdateUser {
                                name: Some("Changed during index publication".into()),
                                ..Default::default()
                            },
                        )
                        .await?;
                }
                Some(IndexMutation::Delete(store, id)) => store.delete_user(&id).await?,
                None => {}
            }
        }
        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.inner.get(key).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.inner.delete(key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.inner.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: Duration) -> AuthResult<()> {
        self.inner.expire(key, ttl).await
    }
    async fn clear(&self) -> AuthResult<()> {
        self.inner.clear().await
    }
}

#[tokio::test]
async fn change_password_deferred_mirror_failure_commits_and_issues_usable_token() {
    let cache = RecordingCache::new(true);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
    let (request, response) = fixture.change(Some(true)).await;
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    fixture.assert_password("hash:NewPassword123!").await;
    let replacement = fixture.replacement().await;
    assert_eq!(*cache.writes.lock().unwrap(), [replacement.token.clone()]);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["token"], replacement.token);
    assert_eq!(
        published_session(&request).unwrap().1.token,
        replacement.token
    );
    assert!(
        fixture
            .ctx
            .database
            .get_session(&replacement.token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(response.headers.get("Set-Cookie").is_some());
}

#[tokio::test]
async fn change_password_deferred_mirror_is_absent_on_transaction_or_commit_failure() {
    for failure in [Failure::Create, Failure::CancelCreate, Failure::Commit] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(failure, Some(cache.clone()), true, false, false).await;
        let (request, response) = fixture.change(Some(true)).await;
        assert!(response.is_err(), "{failure:?}");
        fixture.assert_password("hash:Password123!").await;
        fixture.assert_original_sessions().await;
        assert!(cache.writes.lock().unwrap().is_empty(), "{failure:?}");
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_deferred_mirror_precedes_after_create_revocation() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, true).await;
    let (_, response) = fixture.change(Some(true)).await;
    let body: serde_json::Value = serde_json::from_slice(&response.unwrap().body).unwrap();
    let token = body["token"].as_str().unwrap();
    assert_eq!(*cache.writes.lock().unwrap(), [token]);
    assert!(
        cache.get(token).await.unwrap().is_none(),
        "no mirror may resurrect the revoked token after the hook"
    );
}

#[tokio::test]
async fn change_password_secondary_authority_keeps_inline_mirror_failures_atomic() {
    for (store, preserve) in [(false, false), (true, true)] {
        let cache = RecordingCache::new(true);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), store, preserve, false)
                .await;
        let (request, response) = fixture.change(Some(true)).await;
        assert!(response.is_err());
        fixture.assert_password("hash:Password123!").await;
        assert_eq!(cache.writes.lock().unwrap().len(), 1);
        if store {
            assert_eq!(
                fixture
                    .raw
                    .get_user_sessions(&fixture.user.id)
                    .await
                    .unwrap()
                    .len(),
                2
            );
        }
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_default_session_creation_policy_still_propagates_mirror_errors() {
    let cache = RecordingCache::new(true);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
    let user = fixture.user.id.clone();
    let result = alibi_core::store::write_transaction(fixture.ctx.database.as_ref(), move |tx| {
        Box::pin(async move {
            tx.create_session(CreateSession {
                user_id: user,
                expires_at: chrono::Utc::now() + Duration::hours(1),
                token: None,
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: Default::default(),
            })
            .await
        })
    })
    .await;
    assert!(result.is_err());
    assert_eq!(cache.writes.lock().unwrap().len(), 1);
    assert_eq!(
        fixture
            .raw
            .get_user_sessions(&fixture.user.id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn change_password_deferred_mirror_does_not_jump_preceding_after_hook_failure() {
    for failure in [Failure::AfterDelete, Failure::AfterUpdate] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(failure, Some(cache.clone()), true, false, false).await;
        let (request, response) = fixture.change(Some(true)).await;
        assert!(response.is_err());
        fixture.assert_password("hash:NewPassword123!").await;
        assert_eq!(
            fixture
                .raw
                .get_user_sessions(&fixture.user.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(cache.writes.lock().unwrap().is_empty());
        assert_unpublished(&request);
    }
}

#[tokio::test]
async fn change_password_deferred_index_failure_also_leaves_database_token_usable() {
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
    cache.fail_index.store(true, Ordering::SeqCst);
    let (request, response) = fixture.change(Some(true)).await;
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    fixture.assert_password("hash:NewPassword123!").await;
    let replacement = fixture.replacement().await;
    assert!(cache.writes.lock().unwrap().is_empty());
    assert_eq!(
        published_session(&request).unwrap().1.token,
        replacement.token
    );
    assert!(
        fixture
            .ctx
            .database
            .get_session(&replacement.token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(response.headers.get("Set-Cookie").is_some());
}

#[tokio::test]
async fn session_creation_publishes_index_before_loading_owner_in_ordinary_and_deferred_paths() {
    use alibi_core::store::CacheAdapter;
    use alibi_core::{AuthSession, AuthUser};
    for deferred in [false, true] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
        *cache.index_mutation.lock().unwrap() = Some(IndexMutation::Rename(
            fixture.raw.clone(),
            fixture.user.id.clone(),
        ));
        let token = if deferred {
            let (_, response) = fixture.change(Some(true)).await;
            let response = response.unwrap();
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            fixture.hooks.armed.store(false, Ordering::SeqCst);
            test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
                .await
                .token
        };
        let raw = cache.get(&token).await.unwrap().unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let owner = <TestSchema as alibi_core::AuthSchema>::User::from_secondary_snapshot(
            snapshot["user"].clone(),
        )
        .unwrap();
        assert_eq!(owner.name(), Some("Changed during index publication"));
        let cached = TestSession::from_secondary_snapshot(snapshot["session"].clone()).unwrap();
        if deferred {
            let before_hook = fixture.hooks.before_create_clock.lock().unwrap().unwrap();
            assert!(
                cached.created_at() <= before_hook,
                "capture creation clock before before-create hooks"
            );
        }
        assert_eq!(cached.token(), token);
    }
}

#[tokio::test]
async fn creation_codec_keeps_rounded_database_session_alive_past_cached_revocation_cutoff() {
    use alibi_core::AuthSession;
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
    let token = &fixture.sessions[0].token;
    let mut rounded = fixture.raw.get_session(token).await.unwrap().unwrap();
    let clock =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    rounded.created_at = chrono::DateTime::from_timestamp(clock.timestamp() - 1, 0).unwrap();
    let cutoff = clock.timestamp_millis() - 1;
    cache
        .set(
            &format!("revoked-sessions-before-{}", fixture.user.id),
            &cutoff.to_string(),
            Duration::hours(1),
        )
        .await
        .unwrap();
    let raw = cache.get(token).await.unwrap().unwrap();
    let mut snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
    snapshot["session"] = rounded.secondary_snapshot().unwrap();
    cache
        .set(token, &snapshot.to_string(), Duration::hours(1))
        .await
        .unwrap();
    assert!(
        fixture
            .ctx
            .database
            .get_session(token)
            .await
            .unwrap()
            .is_none(),
        "rounded clock incorrectly predates revocation"
    );
    snapshot["session"] = rounded.secondary_snapshot_for_creation(clock).unwrap();
    cache
        .set(token, &snapshot.to_string(), Duration::hours(1))
        .await
        .unwrap();
    let accepted = fixture
        .ctx
        .database
        .get_session(token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.created_at(), clock);
    assert!(rounded.created_at() < clock);
}

#[tokio::test]
async fn session_creation_publishes_null_owner_after_index_triggered_deletion_without_synthesizing_user()
 {
    use alibi_core::AuthSession;
    use alibi_core::store::CacheAdapter;
    for (store_in_database, deferred) in [(false, false), (true, false), (true, true)] {
        let cache = RecordingCache::new(false);
        let fixture = Fixture::with_secondary(
            Failure::None,
            Some(cache.clone()),
            store_in_database,
            false,
            false,
        )
        .await;
        *cache.index_mutation.lock().unwrap() = Some(IndexMutation::Delete(
            fixture.raw.clone(),
            fixture.user.id.clone(),
        ));
        let token = if deferred {
            let (_, response) = fixture.change(Some(true)).await;
            let response = response.unwrap();
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            fixture.hooks.armed.store(false, Ordering::SeqCst);
            test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
                .await
                .token
        };
        assert!(
            fixture
                .raw
                .get_user_by_id(&fixture.user.id)
                .await
                .unwrap()
                .is_none()
        );
        let index = cache
            .get(&format!("active-sessions-{}", fixture.user.id))
            .await
            .unwrap()
            .unwrap();
        assert!(index.contains(&token));
        let raw = cache.get(&token).await.unwrap().unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(snapshot["user"].is_null());
        let session = TestSession::from_secondary_snapshot(snapshot["session"].clone()).unwrap();
        assert_eq!(session.token(), token);
        for error in [
            fixture.ctx.database.get_session(&token).await.unwrap_err(),
            fixture
                .ctx
                .database
                .get_session_user(&token)
                .await
                .unwrap_err(),
        ] {
            assert!(
                matches!(error, AuthError::Internal(message) if message == "Secondary session owner is absent")
            );
        }
        cache
            .set(
                &format!("revoked-sessions-before-{}", fixture.user.id),
                &(session.created_at().timestamp_millis() + 1).to_string(),
                Duration::hours(1),
            )
            .await
            .unwrap();
        assert!(
            fixture
                .ctx
                .database
                .get_session(&token)
                .await
                .unwrap()
                .is_none(),
            "revocation precedes null-owner hydration"
        );
        fixture.ctx.database.delete_session(&token).await.unwrap();
        assert!(cache.get(&token).await.unwrap().is_none());
    }
}

fn native_owner_scalars() -> [(&'static str, &'static str, serde_json::Value); 8] {
    [
        ("email_verified", "emailVerified", serde_json::json!(2)),
        (
            "two_factor_enabled",
            "twoFactorEnabled",
            serde_json::json!(-1),
        ),
        ("banned", "banned", serde_json::json!(0.5)),
        ("is_anonymous", "isAnonymous", serde_json::json!("pending")),
        (
            "phone_number_verified",
            "phoneNumberVerified",
            serde_json::json!(-2),
        ),
        (
            "ban_expires",
            "banExpires",
            serde_json::json!(9000000000000000_i64),
        ),
        ("created_at", "createdAt", serde_json::json!(-123.5)),
        ("updated_at", "updatedAt", serde_json::json!(123.25)),
    ]
}

fn assert_native_owner_snapshot(snapshot: &serde_json::Value) {
    for (physical, _, expected) in native_owner_scalars() {
        assert_eq!(snapshot[physical], expected, "{physical}");
    }
}

async fn seed_native_owner(fixture: &Fixture) {
    use alibi_seaorm::sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    fixture.db.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE user SET emailVerified = 2, twoFactorEnabled = -1, banned = 0.5, isAnonymous = 'pending', phoneNumberVerified = -2, banExpires = 9000000000000000, createdAt = -123.5, updatedAt = 123.25 WHERE id = ?",
        [fixture.user.id.clone().into()],
    )).await.unwrap();
}

#[tokio::test]
async fn explicit_null_session_fields_survive_ordinary_inline_and_deferred_creation() {
    use alibi_core::store::CacheAdapter;
    use alibi_core::utils::json::JsValue;
    for (persist, transactional, deferred) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), persist, false, false)
                .await;
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        let mut config = (*fixture.ctx.config).clone();
        config.session.additional_fields.insert(
            "activeTeamId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type": "string"})),
        );
        let database =
            alibi_core::plugin::AuthInitContext::new(Arc::new(config), fixture.raw.clone())
                .database_with_registered_transforms();
        let mut fields = alibi_core::field_policy::FieldValues::new();
        fields.insert("activeTeamId".into(), JsValue::Null);
        let input = CreateSession {
            user_id: fixture.user.id.clone(),
            expires_at: chrono::Utc::now() + Duration::hours(1),
            token: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: fields,
        };
        let session =
            if transactional {
                alibi_core::store::write_transaction(database.as_ref(), move |tx| {
                    Box::pin(async move {
                        tx.create_session_record_with_policy(
                        input,
                        if deferred {
                            alibi_core::session::SessionCreationPolicy::DeferSecondaryStorageWrites
                        } else {
                            alibi_core::session::SessionCreationPolicy::Inline
                        },
                    ).await.map(|record| record.into_stored())
                    })
                })
                .await
                .unwrap()
            } else {
                database.create_session(input).await.unwrap()
            };
        let token = &session.token;
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        assert!(
            !cached["absent_fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "activeTeamId")
        );
        let record = database.get_session_record(token).await.unwrap().unwrap();
        assert_eq!(
            record.raw_snapshot().values()["activeTeamId"],
            serde_json::Value::Null
        );
        assert!(!record.raw_snapshot().field_is_undefined("activeTeamId"));
    }
}

#[tokio::test]
async fn inline_transaction_session_creation_reads_native_owner_on_transaction_connection() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
    seed_native_owner(&fixture).await;
    let user_id = fixture.user.id.clone();
    let created = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        alibi_core::store::write_transaction(fixture.ctx.database.as_ref(), move |tx| {
            Box::pin(async move {
                tx.create_session(CreateSession {
                    user_id,
                    expires_at: chrono::Utc::now() + Duration::hours(1),
                    token: None,
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                    additional_fields: Default::default(),
                })
                .await
            })
        }),
    )
    .await
    .expect("owner lookup must not acquire the occupied root connection")
    .unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(&created.token).await.unwrap().unwrap()).unwrap();
    assert_eq!(snapshot["user"]["email_verified"], false);
    assert_eq!(snapshot["user"]["is_anonymous"], "pending");
    assert_eq!(snapshot["user"]["created_at"], -123.5);
    assert_eq!(snapshot["user"]["ban_expires"], 9000000000000000_i64);
}

#[tokio::test]
async fn session_creation_and_user_refresh_publish_native_owner_scalars() {
    use alibi_core::store::CacheAdapter;
    for (store_in_database, deferred) in [(false, false), (true, false), (true, true)] {
        let cache = RecordingCache::new(false);
        let fixture = Fixture::with_secondary(
            Failure::None,
            Some(cache.clone()),
            store_in_database,
            false,
            false,
        )
        .await;
        seed_native_owner(&fixture).await;
        let token = if deferred {
            let (_, response) = fixture.change(Some(true)).await;
            let response = response.unwrap();
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            fixture.hooks.armed.store(false, Ordering::SeqCst);
            test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
                .await
                .token
        };
        let snapshot: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        for (physical, _, expected) in native_owner_scalars() {
            let expected = if matches!(
                physical,
                "email_verified" | "two_factor_enabled" | "banned" | "phone_number_verified"
            ) {
                serde_json::Value::Bool(false)
            } else {
                expected
            };
            assert_eq!(snapshot["user"][physical], expected, "{physical}");
        }
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        fixture
            .ctx
            .database
            .update_user(
                &fixture.user.id,
                alibi_core::UpdateUser {
                    name: Some("Published new owner".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let snapshot: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        assert_eq!(snapshot["user"]["name"], "Published new owner");
        for (physical, _, expected) in native_owner_scalars() {
            if physical != "updated_at" {
                let expected = if matches!(
                    physical,
                    "email_verified" | "two_factor_enabled" | "banned" | "phone_number_verified"
                ) {
                    serde_json::Value::Bool(false)
                } else {
                    expected
                };
                assert_eq!(snapshot["user"][physical], expected, "{physical}");
            }
        }
    }
}

#[tokio::test]
async fn cached_session_owner_retains_raw_scalars_and_absence_without_database_requery() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let token = &fixture.sessions[0].token;
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    for (physical, _, value) in native_owner_scalars() {
        snapshot["user"][physical] = value;
    }
    snapshot["user"].as_object_mut().unwrap().remove("image");
    snapshot["user"]["name"] = serde_json::Value::Null;
    alibi_seaorm::store::entities::user::Model::from_secondary_snapshot_record(
        snapshot["user"].clone(),
    )
    .expect("cached native owner must decode without losing null name or absent image");
    cache
        .set(
            token,
            &serde_json::to_string(&snapshot).unwrap(),
            Duration::hours(1),
        )
        .await
        .unwrap();
    fixture.raw.delete_user(&fixture.user.id).await.unwrap();
    assert!(
        fixture
            .raw
            .get_user_by_id(&fixture.user.id)
            .await
            .unwrap()
            .is_none()
    );
    let record = fixture
        .ctx
        .database
        .get_session_user_record(token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id(), fixture.user.id);
    for (_, wire, expected) in native_owner_scalars() {
        let expected = match wire {
            "createdAt" => serde_json::json!(alibi_core::utils::datetime::json_date_millis(-123)),
            "updatedAt" => serde_json::json!(alibi_core::utils::datetime::json_date_millis(123)),
            _ => expected,
        };
        assert_eq!(
            record.raw_snapshot().values().get(wire),
            Some(&expected),
            "{wire}"
        );
    }
    assert!(!record.raw_snapshot().values().contains_key("image"));
    assert_eq!(
        record.raw_snapshot().values().get("name"),
        Some(&serde_json::Value::Null)
    );
    fixture
        .ctx
        .database
        .refresh_session(token, chrono::Utc::now() + Duration::hours(2))
        .await
        .unwrap()
        .unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    assert_native_owner_snapshot(&snapshot["user"]);
    assert!(snapshot["user"].get("image").is_none());
    assert!(snapshot["user"]["name"].is_null());
    assert!(
        fixture
            .ctx
            .database
            .get_session_user_record(token)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cached_session_owner_revives_only_created_and_updated_dates() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    let token = &fixture.sessions[0].token;
    let original: serde_json::Value =
        serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
    for (raw, expected) in [
        (
            serde_json::json!(0),
            serde_json::json!("1970-01-01T00:00:00.000Z"),
        ),
        (
            serde_json::json!(-1),
            serde_json::json!("1969-12-31T23:59:59.999Z"),
        ),
        (
            serde_json::json!(1.9),
            serde_json::json!("1970-01-01T00:00:00.001Z"),
        ),
        (serde_json::json!(1e20), serde_json::Value::Null),
        (
            serde_json::Value::Null,
            serde_json::json!("1970-01-01T00:00:00.000Z"),
        ),
        (
            serde_json::Value::Bool(true),
            serde_json::json!("1970-01-01T00:00:00.001Z"),
        ),
        (
            serde_json::json!("2024-01-02T03:04:05.678Z"),
            serde_json::json!("2024-01-02T03:04:05.678Z"),
        ),
        (serde_json::json!({}), serde_json::Value::Null),
    ] {
        let mut snapshot = original.clone();
        snapshot["user"]["created_at"] = raw.clone();
        snapshot["user"]["updated_at"] = raw.clone();
        snapshot["user"]["ban_expires"] = raw.clone();
        cache
            .set(token, &snapshot.to_string(), Duration::hours(1))
            .await
            .unwrap();
        let record = fixture
            .ctx
            .database
            .get_session_user_record(token)
            .await
            .unwrap()
            .unwrap();
        let wire = serde_json::to_value(&record).unwrap();
        assert_eq!(wire["createdAt"], expected);
        assert_eq!(wire["updatedAt"], expected);
        assert_eq!(wire["banExpires"], raw);
        let stored: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(stored["user"]["created_at"], raw);
        assert_eq!(stored["user"]["updated_at"], raw);
    }
}

#[tokio::test]
async fn session_owner_output_transforms_run_only_on_actual_database_publication() {
    use alibi_core::store::CacheAdapter;
    for (store_in_database, deferred) in [(false, false), (true, false), (true, true)] {
        let cache = RecordingCache::new(false);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fixture = Fixture::with_secondary_output_counter(
            Failure::None,
            Some(cache.clone()),
            store_in_database,
            false,
            false,
            Some(calls.clone()),
        )
        .await;
        seed_native_owner(&fixture).await;
        calls.store(0, Ordering::SeqCst);
        let token = if deferred {
            let (_, response) = fixture.change(Some(true)).await;
            serde_json::from_slice::<serde_json::Value>(&response.unwrap().body).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            fixture.hooks.armed.store(false, Ordering::SeqCst);
            test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
                .await
                .token
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for _ in 0..2 {
            let record = fixture
                .ctx
                .database
                .get_session_user_record(&token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                record.raw_snapshot().values()["emailVerified"],
                "false:once"
            );
        }
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        fixture
            .ctx
            .database
            .refresh_session(&token, chrono::Utc::now() + Duration::hours(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"]["email_verified"], "false:once");
        fixture
            .ctx
            .database
            .update_user(
                &fixture.user.id,
                alibi_core::UpdateUser {
                    name: Some("Refreshed".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let record = fixture
            .ctx
            .database
            .get_session_user_record(&token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.raw_snapshot().values()["emailVerified"],
            "false:once"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn session_cache_updates_transform_only_actual_database_output() {
    use alibi_core::store::CacheAdapter;
    use alibi_core::utils::json::JsValue;
    for persist in [false, true] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), persist, false, false)
                .await;
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        let token =
            test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
                .await
                .token;
        let mut snapshot: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        snapshot["session"]["active_organization_id"] = serde_json::json!("already-output");
        cache
            .set(&token, &snapshot.to_string(), Duration::hours(1))
            .await
            .unwrap();
        let inputs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let outputs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut config = (*fixture.ctx.config).clone();
        let input_calls = inputs.clone();
        let output_calls = outputs.clone();
        config.session.additional_fields.insert(
            "activeTeamId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .transform_adapter_input(move |value| {
                    input_calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(value.map(|value| {
                            JsValue::String(format!("{}:input", value.as_str().unwrap()).into())
                        }))
                    }
                })
                .transform_output(move |value| {
                    output_calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(value.map(|value| {
                            JsValue::String(format!("{}:output", value.as_str().unwrap()).into())
                        }))
                    }
                }),
        );
        config.session.additional_fields.insert(
            "activeOrganizationId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .transform_output(|value| async move {
                    assert_ne!(
                        value.as_ref().and_then(JsValue::as_str),
                        Some("already-output"),
                        "replayed untouched cached output"
                    );
                    Ok(value)
                }),
        );
        let database =
            alibi_core::plugin::AuthInitContext::new(Arc::new(config), fixture.raw.clone())
                .database_with_registered_transforms();
        let mut fields = alibi_core::field_policy::FieldValues::new();
        fields.insert("activeTeamId".into(), JsValue::String("new".into()));
        let updated = database
            .update_session_fields_record(&token, fields)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.raw_snapshot().values()["activeTeamId"],
            if persist { "new:input:output" } else { "new" }
        );
        let refreshed = database
            .refresh_session_record(&token, chrono::Utc::now() + Duration::hours(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            refreshed.raw_snapshot().values()["activeTeamId"],
            if persist { "new:input:output" } else { "new" }
        );
        database
            .update_session_active_team_record(&token, Some("ordinary"))
            .await
            .unwrap();
        database
            .update_session_active_organization_record(&token, Some("organization"))
            .await
            .unwrap();
        let tx_token = token.clone();
        alibi_core::store::write_transaction(database.as_ref(), move |tx| {
            Box::pin(async move {
                let team = tx
                    .update_session_active_team_record(&tx_token, Some("transaction"))
                    .await?;
                assert_eq!(
                    team.raw_snapshot().values()["activeTeamId"],
                    if persist {
                        "transaction:input:output"
                    } else {
                        "transaction"
                    }
                );
                tx.update_session_active_organization_record(&tx_token, Some("transaction-org"))
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(inputs.load(Ordering::SeqCst), if persist { 3 } else { 0 });
        assert_eq!(outputs.load(Ordering::SeqCst), if persist { 6 } else { 0 });
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["session"]["active_team_id"], "transaction");
    }
}

struct SessionProjectionObservation {
    cache: Arc<RecordingCache>,
    snapshots: Mutex<Vec<(serde_json::Value, serde_json::Value)>>,
}

#[async_trait]
impl alibi_core::store::AdapterAfterHook<TestSchema> for SessionProjectionObservation {
    async fn after_write(
        &self,
        event: &alibi_core::store::AdapterEvent<TestSchema>,
        _: &dyn alibi_core::store::AuthStore<TestSchema>,
    ) -> AuthResult<()> {
        use alibi_core::store::CacheAdapter;
        if let alibi_core::store::AdapterEvent::SessionCreated(record) = event {
            let cached: serde_json::Value = serde_json::from_str(
                &self
                    .cache
                    .get(alibi_core::AuthSession::token(record))
                    .await?
                    .unwrap(),
            )
            .unwrap();
            self.snapshots.lock().unwrap().push((
                serde_json::to_value(record).unwrap(),
                cached["session"].clone(),
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn session_creation_projects_database_output_once_before_ordinary_inline_and_deferred_publication()
 {
    use alibi_core::store::CacheAdapter;
    use alibi_core::utils::json::JsValue;
    for (persist, transactional, deferred) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), persist, false, false)
                .await;
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        let outputs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inputs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut config = (*fixture.ctx.config).clone();
        let input_calls = inputs.clone();
        let output_calls = outputs.clone();
        let observed_cache = cache.clone();
        config.session.additional_fields.insert(
            "activeTeamId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .transform_adapter_input(move |value| {
                    input_calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok(value.map(|value| {
                            JsValue::String(format!("{}:input", value.as_str().unwrap()).into())
                        }))
                    }
                })
                .transform_output(move |value| {
                    output_calls.fetch_add(1, Ordering::SeqCst);
                    let cache = observed_cache.clone();
                    async move {
                        assert!(
                            cache.get("session-project-before-publish").await?.is_none(),
                            "output transform ran after publication"
                        );
                        Ok(value.map(|value| {
                            JsValue::String(format!("{}:output", value.as_str().unwrap()).into())
                        }))
                    }
                }),
        );
        config.session.additional_fields.insert(
            "activeOrganizationId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .transform_output(|_| async { Ok(None) }),
        );
        config.session.additional_fields.insert(
            "createdAt".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"date"}))
                .transform_output(|_| async {
                    Ok(Some(JsValue::String("2001-01-01T00:00:00.000Z".into())))
                }),
        );
        let observation = Arc::new(SessionProjectionObservation {
            cache: cache.clone(),
            snapshots: Mutex::new(Vec::new()),
        });
        let mut init =
            alibi_core::plugin::AuthInitContext::new(Arc::new(config), fixture.raw.clone());
        init.register_adapter_after_hook(observation.clone());
        let database = init.database_with_registered_transforms();
        let mut fields = alibi_core::field_policy::FieldValues::new();
        fields.insert("activeTeamId".into(), JsValue::String("new".into()));
        let input = CreateSession {
            user_id: fixture.user.id.clone(),
            token: Some("session-project-before-publish".into()),
            expires_at: chrono::Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: fields,
        };
        let before = chrono::Utc::now().timestamp_millis();
        let record = if transactional {
            let cache = cache.clone();
            alibi_core::store::write_transaction(database.as_ref(), move |tx| {
                Box::pin(async move {
                    let policy = if deferred {
                        alibi_core::session::SessionCreationPolicy::DeferSecondaryStorageWrites
                    } else {
                        alibi_core::session::SessionCreationPolicy::Inline
                    };
                    let record = tx.create_session_record_with_policy(input, policy).await?;
                    assert_eq!(
                        cache.get("session-project-before-publish").await?.is_none(),
                        deferred
                    );
                    Ok(record)
                })
            })
            .await
            .unwrap()
        } else {
            database.create_session_record(input).await.unwrap()
        };
        assert_eq!(inputs.load(Ordering::SeqCst), usize::from(persist));
        assert_eq!(outputs.load(Ordering::SeqCst), usize::from(persist));
        assert_eq!(
            record.raw_snapshot().values()["activeTeamId"],
            if persist { "new:input:output" } else { "new" }
        );
        let cached: serde_json::Value = serde_json::from_str(
            &cache
                .get("session-project-before-publish")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        {
            let observed = observation.snapshots.lock().unwrap();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0].0, serde_json::to_value(&record).unwrap());
            assert_eq!(observed[0].1, cached["session"]);
        }
        assert_eq!(
            cached["session"]["active_team_id"],
            if persist { "new:input:output" } else { "new" }
        );
        let cached_model = <TestSession as alibi_core::AuthSession>::from_secondary_snapshot(
            cached["session"].clone(),
        )
        .unwrap();
        assert!(alibi_core::AuthSession::created_at(&cached_model).timestamp_millis() >= before);
        if persist {
            assert!(
                record
                    .raw_snapshot()
                    .field_is_undefined("activeOrganizationId")
            );
            assert!(cached["session"].get("active_organization_id").is_none());
            assert_eq!(
                record.raw_snapshot().values()["createdAt"],
                "2001-01-01T00:00:00.000Z"
            );
            assert_eq!(
                alibi_core::AuthSession::active_team_id(&record),
                Some("new:input")
            );
        }
        let mut with_extra = cached.clone();
        with_extra["session"]["unknownTrustedObject"] = serde_json::json!({"nested":[true,null]});
        cache
            .set(
                "session-project-before-publish",
                &with_extra.to_string(),
                Duration::hours(1),
            )
            .await
            .unwrap();
        let readback = database
            .get_session_record("session-project-before-publish")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            readback.raw_snapshot().values()["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        if persist {
            assert!(
                readback
                    .raw_snapshot()
                    .field_is_undefined("activeOrganizationId")
            );
        }
        let found = database
            .get_sessions_by_tokens_record(&["session-project-before-publish".into()])
            .await
            .unwrap();
        assert_eq!(
            found[0].raw_snapshot().values()["activeTeamId"],
            if persist { "new:input:output" } else { "new" }
        );
        assert_eq!(outputs.load(Ordering::SeqCst), usize::from(persist));
    }
}

#[tokio::test]
async fn session_creation_output_failure_does_not_publish_or_commit_transactional_session() {
    use alibi_core::store::CacheAdapter;
    for deferred in [false, true] {
        let cache = RecordingCache::new(false);
        let fixture =
            Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false).await;
        fixture.hooks.armed.store(false, Ordering::SeqCst);
        let mut config = (*fixture.ctx.config).clone();
        config.session.additional_fields.insert(
            "activeTeamId".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                .transform_output(|_| async {
                    Err(AuthError::internal("session output rejected"))
                }),
        );
        let database =
            alibi_core::plugin::AuthInitContext::new(Arc::new(config), fixture.raw.clone())
                .database_with_registered_transforms();
        let user_id = fixture.user.id.clone();
        let result = alibi_core::store::write_transaction(database.as_ref(), move |tx| {
            Box::pin(async move {
                tx.create_session_record_with_policy(
                    CreateSession {
                        user_id,
                        token: Some("output-failure".into()),
                        expires_at: chrono::Utc::now() + Duration::hours(1),
                        ip_address: None,
                        user_agent: None,
                        impersonated_by: None,
                        active_organization_id: None,
                        active_team_id: None,
                        additional_fields: Default::default(),
                    },
                    if deferred {
                        alibi_core::session::SessionCreationPolicy::DeferSecondaryStorageWrites
                    } else {
                        alibi_core::session::SessionCreationPolicy::Inline
                    },
                )
                .await
            })
        })
        .await;
        assert!(result.is_err());
        assert!(cache.get("output-failure").await.unwrap().is_none());
        assert!(
            fixture
                .raw
                .get_session("output-failure")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !cache
                .get(&format!("active-sessions-{}", fixture.user.id))
                .await
                .unwrap()
                .unwrap_or_default()
                .contains("output-failure")
        );
    }
}

#[tokio::test]
async fn session_secondary_refresh_preserves_unknown_and_undefined_cached_output() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let token =
        test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
            .await
            .token;
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
    snapshot["session"]
        .as_object_mut()
        .unwrap()
        .remove("active_organization_id");
    snapshot["session"]["unknownTrustedObject"] = serde_json::json!({"nested":[true,null]});
    snapshot["absent_fields"] = serde_json::json!(["activeOrganizationId"]);
    cache
        .set(&token, &snapshot.to_string(), Duration::hours(1))
        .await
        .unwrap();
    let record = fixture
        .ctx
        .database
        .refresh_session_record(&token, chrono::Utc::now() + Duration::hours(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.raw_snapshot().values()["unknownTrustedObject"],
        serde_json::json!({"nested":[true,null]})
    );
    assert!(
        record
            .raw_snapshot()
            .field_is_undefined("activeOrganizationId")
    );
    let cached: serde_json::Value =
        serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
    assert_eq!(
        cached["session"]["unknownTrustedObject"],
        serde_json::json!({"nested":[true,null]})
    );
    assert!(cached["session"].get("active_organization_id").is_none());
}

#[tokio::test]
async fn session_transaction_updates_preserve_null_and_nonmodel_cached_owners() {
    use alibi_core::store::CacheAdapter;
    let cache = RecordingCache::new(false);
    let fixture =
        Fixture::with_secondary(Failure::None, Some(cache.clone()), false, false, false).await;
    fixture.hooks.armed.store(false, Ordering::SeqCst);
    let token =
        test_helpers::create_session(&fixture.ctx, fixture.user.id.clone(), Duration::hours(1))
            .await
            .token;
    for user in [
        serde_json::Value::Null,
        serde_json::json!({"notAnOwnerModel":true}),
    ] {
        let mut snapshot: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        snapshot["user"] = user.clone();
        cache
            .set(&token, &snapshot.to_string(), Duration::hours(1))
            .await
            .unwrap();
        let tx_token = token.clone();
        alibi_core::store::write_transaction(fixture.ctx.database.as_ref(), move |tx| {
            Box::pin(async move {
                tx.update_session_active_team_record(&tx_token, Some("team"))
                    .await?;
                tx.update_session_active_organization_record(&tx_token, Some("org"))
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(&token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"], user);
        assert_eq!(cached["session"]["active_team_id"], "team");
        assert_eq!(cached["session"]["active_organization_id"], "org");
    }
}
