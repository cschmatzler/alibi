pub(super) mod handlers;
mod set_password;
#[cfg(test)]
mod transaction_tests {
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
                            .execute_unprepared(
                                "INSERT INTO commit_failure VALUES ('missing-user')",
                            )
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
                    alibi_core::field_policy::FieldConfig::new(
                        serde_json::json!({"type": "boolean"}),
                    )
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
        let result =
            alibi_core::store::write_transaction(fixture.ctx.database.as_ref(), move |tx| {
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
    async fn session_creation_publishes_index_before_loading_owner_in_ordinary_and_deferred_paths()
    {
        use alibi_core::store::CacheAdapter;
        use alibi_core::{AuthSession, AuthUser};
        for deferred in [false, true] {
            let cache = RecordingCache::new(false);
            let fixture =
                Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false)
                    .await;
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
                test_helpers::create_session(
                    &fixture.ctx,
                    fixture.user.id.clone(),
                    Duration::hours(1),
                )
                .await
                .token
            };
            let raw = cache.get(&token).await.unwrap().unwrap();
            let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let owner = <TestSchema as alibi_core::AuthSchema>::User::from_secondary_snapshot(
                snapshot["user"].clone().into(),
            )
            .unwrap();
            assert_eq!(owner.name(), Some("Changed during index publication"));
            let cached =
                TestSession::from_secondary_snapshot(snapshot["session"].clone().into()).unwrap();
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
        snapshot["session"] = rounded
            .secondary_snapshot()
            .unwrap()
            .to_json_value()
            .unwrap();
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
        snapshot["session"] = rounded
            .secondary_snapshot_for_creation(clock)
            .unwrap()
            .to_json_value()
            .unwrap();
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
                test_helpers::create_session(
                    &fixture.ctx,
                    fixture.user.id.clone(),
                    Duration::hours(1),
                )
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
            let session =
                TestSession::from_secondary_snapshot(snapshot["session"].clone().into()).unwrap();
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
            let session = if transactional {
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
                test_helpers::create_session(
                    &fixture.ctx,
                    fixture.user.id.clone(),
                    Duration::hours(1),
                )
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
                        "email_verified"
                            | "two_factor_enabled"
                            | "banned"
                            | "phone_number_verified"
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
            snapshot["user"].clone().into(),
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
                "createdAt" => {
                    serde_json::json!(alibi_core::utils::datetime::json_date_millis(-123))
                }
                "updatedAt" => {
                    serde_json::json!(alibi_core::utils::datetime::json_date_millis(123))
                }
                _ => expected,
            };
            assert_eq!(
                record.raw_snapshot().values().get(wire),
                Some(&alibi_core::utils::json::JsValue::from(expected)),
                "{wire}"
            );
        }
        assert!(!record.raw_snapshot().values().contains_key("image"));
        assert_eq!(
            record.raw_snapshot().values().get("name"),
            Some(&alibi_core::utils::json::JsValue::Null)
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
                test_helpers::create_session(
                    &fixture.ctx,
                    fixture.user.id.clone(),
                    Duration::hours(1),
                )
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
            let token = test_helpers::create_session(
                &fixture.ctx,
                fixture.user.id.clone(),
                Duration::hours(1),
            )
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
                                JsValue::String(
                                    format!("{}:output", value.as_str().unwrap()).into(),
                                )
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
                    tx.update_session_active_organization_record(
                        &tx_token,
                        Some("transaction-org"),
                    )
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
                                JsValue::String(
                                    format!("{}:output", value.as_str().unwrap()).into(),
                                )
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
                cached["session"].clone().into(),
            )
            .unwrap();
            assert!(
                alibi_core::AuthSession::created_at(&cached_model).timestamp_millis() >= before
            );
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
            with_extra["session"]["unknownTrustedObject"] =
                serde_json::json!({"nested":[true,null]});
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
                Fixture::with_secondary(Failure::None, Some(cache.clone()), true, false, false)
                    .await;
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
}

pub(super) mod types;

use super::StatusResponse;
use alibi_core::error::codes;
use alibi_core::utils::password::PasswordHasher;
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    HttpMethod, RequestMeta,
};
use async_trait::async_trait;
use handlers::{
    change_password_core, request_password_reset_core, reset_password_core,
    reset_password_token_core, verify_password_core,
};
pub use set_password::set_password;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use types::ResetPasswordTokenQuery;
pub use types::{
    ChangePasswordRequest, ChangePasswordResponse, RequestPasswordResetRequest,
    RequestPasswordResetResponse, ResetPasswordCallbackQuery, ResetPasswordRequest,
    SetPasswordRequest, VerifyPasswordRequest, VerifyPasswordResponse,
};

const RESET_TOKEN_ROUTE_PREFIX: &str = "/reset-password/";

/// Async callback invoked after a password reset, with the user as JSON.
pub type OnPasswordResetCallback =
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = AuthResult<()>> + Send>> + Send + Sync;

/// Trait for sending password reset emails.
///
/// This callback powers `POST /request-password-reset` and is required to
/// enable that route. The user is provided as a serialized `serde_json::Value`
/// since `AuthUser` is not object-safe.
#[async_trait]
pub trait SendResetPassword: Send + Sync {
    /// Send a password reset notification.
    ///
    /// * `user` - The initialized user schema as a serialized JSON value
    /// * `url` - The full reset URL including the token
    /// * `token` - The raw reset token
    async fn send(&self, user: &serde_json::Value, url: &str, token: &str) -> AuthResult<()>;
}

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

impl std::fmt::Debug for PasswordManagementPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementPlugin")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, alibi_core::PluginConfig)]
#[plugin(name = "PasswordManagementPlugin")]
pub struct PasswordManagementConfig {
    #[config(default = 1)]
    pub reset_token_expiry_hours: i64,
    /// Overrides the legacy hour setting with a precise reset-token duration.
    /// Zero retains the default expiry, matching the upstream option.
    #[config(default = None)]
    pub reset_token_expiry: Option<chrono::Duration>,
    #[config(default = true)]
    pub require_current_password: bool,
    #[config(default = true)]
    pub send_email_notifications: bool,
    /// When true, all existing sessions are revoked on password reset (default: false).
    #[config(default = false)]
    pub revoke_sessions_on_password_reset: bool,
    /// Password reset email sender for `POST /request-password-reset`.
    /// This route is disabled when no sender is configured.
    #[config(default = None)]
    pub send_reset_password: Option<Arc<dyn SendResetPassword>>,
    /// Callback invoked after a password is successfully reset.
    /// The initialized user schema is provided as a serialized JSON value.
    /// Errors propagate after the credential write and before session revocation.
    #[config(default = None)]
    pub on_password_reset: Option<Arc<OnPasswordResetCallback>>,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    /// Resetting a password inherits an initialized email/password hasher first.
    #[config(default = None)]
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl std::fmt::Debug for PasswordManagementConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordManagementConfig")
            .field("reset_token_expiry_hours", &self.reset_token_expiry_hours)
            .field("reset_token_expiry", &self.reset_token_expiry)
            .field("require_current_password", &self.require_current_password)
            .field("send_email_notifications", &self.send_email_notifications)
            .field(
                "revoke_sessions_on_password_reset",
                &self.revoke_sessions_on_password_reset,
            )
            .field(
                "send_reset_password",
                &self.send_reset_password.as_ref().map(|_| "custom"),
            )
            .field(
                "on_password_reset",
                &self.on_password_reset.as_ref().map(|_| "custom"),
            )
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> AuthPlugin<S> for PasswordManagementPlugin {
    route_openapi_metadata!(S);

    fn name(&self) -> &'static str {
        "password-management"
    }

    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        vec![
            crate::endpoint::definition(
                "requestPasswordResetCallback",
                "resetPasswordCallback",
                Some("/reset-password/:token"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "requestPasswordReset",
                "requestPasswordReset",
                Some("/request-password-reset"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "resetPassword",
                "resetPassword",
                Some("/reset-password"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition("setPassword", "setPassword", None, HttpMethod::Post),
            crate::endpoint::definition(
                "changePassword",
                "changePassword",
                Some("/change-password"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "verifyPassword",
                "verifyPassword",
                Some("/verify-password"),
                HttpMethod::Post,
            ),
        ]
    }

    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        use crate::authentication_helpers::RequestBody;
        if call.operation_id() == "resetPasswordCallback" {
            return Ok(alibi_core::endpoint::EndpointInput {
                body: call.body().cloned(),
                query: Some(crate::endpoint::validate_fields(
                    call.query(),
                    "query",
                    ResetPasswordCallbackQuery::FIELDS,
                )?),
            });
        }
        let body = crate::endpoint::validate_fields(
            call.body(),
            "body",
            match call.operation_id() {
                "requestPasswordReset" => RequestPasswordResetRequest::FIELDS,
                "resetPassword" => ResetPasswordRequest::FIELDS,
                "verifyPassword" => VerifyPasswordRequest::FIELDS,
                "setPassword" => SetPasswordRequest::FIELDS,
                _ => ChangePasswordRequest::FIELDS,
            },
        )?;
        let query = if call.operation_id() == "resetPassword" {
            call.query()
                .map(|query| {
                    crate::endpoint::validate_fields(
                        Some(query),
                        "query",
                        &[crate::authentication_helpers::JsonField::string(
                            "token", false,
                        )],
                    )
                })
                .transpose()?
        } else {
            call.query().cloned()
        };
        Ok(alibi_core::endpoint::EndpointInput {
            body: Some(body),
            query,
        })
    }

    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        if call.operation_id() == "resetPasswordCallback" {
            let params = call
                .params()
                .filter(|value| !value.is_null())
                .ok_or_else(|| AuthError::internal("Missing reset password callback parameters"))?;
            let token = params
                .get("token")
                .filter(|value| value.is_truthy())
                .map(|value| value.coerce_string().map_err(AuthError::internal))
                .transpose()?;
            let query: ResetPasswordTokenQuery = call.query_as()?;
            let location =
                reset_password_token_core(token.as_deref(), &query, ctx, call.request()).await?;
            return Ok(alibi_core::endpoint::EndpointResponse::redirect(location));
        }
        if call.operation_id() == "requestPasswordReset" {
            let body: RequestPasswordResetRequest = call.body_as()?;
            let response =
                request_password_reset_core(&body, &self.config, ctx, call.request()).await?;
            return alibi_core::endpoint::EndpointResponse::json(&response);
        }
        if call.operation_id() == "resetPassword" {
            let mut body: ResetPasswordRequest = call.body_as()?;
            if body.token.as_ref().is_none_or(String::is_empty) {
                body.token = call
                    .query()
                    .and_then(|query| query.get("token"))
                    .and_then(alibi_core::utils::json::JsValue::as_str)
                    .map(str::to_owned);
            }
            let response = reset_password_core(&body, &self.config, ctx).await?;
            return alibi_core::endpoint::EndpointResponse::json(&response);
        }
        // Source sensitiveSessionMiddleware catches only its nested session getter.
        let (user, session) = ctx
            .require_authoritative_session_record(call)
            .await
            .map_err(|_| AuthError::Upstream {
                status: 401,
                code: codes::UNAUTHORIZED,
                message: "Unauthorized",
            })?;
        call.record_authenticated_session(ctx.user_view(&user)?, session);
        if call.operation_id() == "setPassword" {
            let body: SetPasswordRequest = call.body_as()?;
            set_password::set_password_for_user(&user, &body.new_password, ctx).await?;
            return alibi_core::endpoint::EndpointResponse::json(&alibi_core::StatusResponse {
                status: true,
            });
        }
        if call.operation_id() == "verifyPassword" {
            let body: VerifyPasswordRequest = call.body_as()?;
            return alibi_core::endpoint::EndpointResponse::json(
                &verify_password_core(&body, &user, &self.config, ctx).await?,
            );
        }
        let body: ChangePasswordRequest = call.body_as()?;

        let headers = call.headers().cloned().unwrap_or_default();
        let meta = RequestMeta {
            ip_address: Some(
                ctx.config
                    .advanced
                    .ip_address
                    .resolve_ip(&headers)
                    .unwrap_or_default(),
            ),
            user_agent: Some(headers.get("user-agent").cloned().unwrap_or_default()),
        };
        let (response, token) =
            change_password_core(&body, &user, &self.config, &meta, ctx).await?;
        let mut response = alibi_core::endpoint::EndpointResponse::json(&response)?;
        if let Some(token) = token {
            response.merge_headers(crate::authentication_helpers::session_cookie_headers(
                &ctx.config,
                &token,
                ctx.session_manager().has_dont_remember_cookie(call),
            )?);
        }
        Ok(response)
    }

    async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/request-password-reset", "request_password_reset"),
            AuthRoute::post("/reset-password", "reset_password"),
            AuthRoute::get("/reset-password/{token}", "reset_password_token"),
            AuthRoute::post("/change-password", "change_password"),
            AuthRoute::post("/verify-password", "verify_password"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let response = match (req.method(), req.path()) {
            (HttpMethod::Post, "/request-password-reset") => {
                self.handle_request_password_reset(req, ctx).await?
            }
            (HttpMethod::Post, "/reset-password") => self.handle_reset_password(req, ctx).await?,
            (HttpMethod::Post, "/change-password") => self.handle_change_password(req, ctx).await?,
            (HttpMethod::Post, "/verify-password") => self.handle_verify_password(req, ctx).await?,
            (HttpMethod::Get, path) if path.starts_with(RESET_TOKEN_ROUTE_PREFIX) => {
                let token = path
                    .get(RESET_TOKEN_ROUTE_PREFIX.len()..)
                    .unwrap_or_default();
                self.handle_reset_password_token(token, req, ctx).await?
            }
            _ => return Ok(None),
        };
        Ok(Some(response))
    }
}

impl PasswordManagementPlugin {
    /// Inspect a reset proof and preserve the intentional redirect API error.
    ///
    /// The proof remains available for `resetPassword`. Logical parameters and
    /// response Location headers remain available to installed hooks and the caller.
    ///
    /// # Errors
    /// Returns an error if logical input cannot be serialized.
    pub fn request_password_reset_callback_endpoint(
        token: &str,
        query: &ResetPasswordCallbackQuery,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<()>> {
        alibi_core::endpoint::ServerEndpoint::new(
            "password-management",
            "requestPasswordResetCallback",
        )
        .with_params(&serde_json::json!({"token": token}))?
        .with_query(query)
    }

    /// Deliver an owned, redeemable reset proof using logical server dispatch.
    ///
    /// The operation does not require a caller session. Redirect trust checks apply
    /// when a physical request is supplied, matching the reference server API.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn request_password_reset_endpoint(
        body: &RequestPasswordResetRequest,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<RequestPasswordResetResponse>> {
        alibi_core::endpoint::ServerEndpoint::new("password-management", "requestPasswordReset")
            .with_body(body)
    }

    /// Reset the proof owner's password without requiring a caller session.
    ///
    /// A nonempty body token takes precedence over the optional logical query token.
    /// Dispatch consumes the proof once and runs the configured reset callback and hooks.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn reset_password_endpoint(
        body: &ResetPasswordRequest,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<alibi_core::StatusResponse>> {
        alibi_core::endpoint::ServerEndpoint::new("password-management", "resetPassword")
            .with_body(body)
    }

    /// Set a password for the authoritative caller without exposing an HTTP route.
    ///
    /// Dispatch uses logical session headers and installed hooks. Existing sessions
    /// remain active, and only the caller's credential account can be created or filled.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn set_password_endpoint(
        body: &SetPasswordRequest,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<alibi_core::StatusResponse>> {
        alibi_core::endpoint::ServerEndpoint::new("password-management", "setPassword")
            .with_body(body)
    }

    /// Verify the current caller's password using genuine logical session headers.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn verify_password_endpoint(
        body: &VerifyPasswordRequest,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<VerifyPasswordResponse>> {
        alibi_core::endpoint::ServerEndpoint::new("password-management", "verifyPassword")
            .with_body(body)
    }

    /// Change the authenticated caller's password and retain every response cookie/header.
    ///
    /// Input is validated after installed before-hook patches. Incoming logical headers
    /// authorize the operation; no physical HTTP request is required.
    ///
    /// # Errors
    /// Returns an error if the logical input cannot be serialized.
    pub fn change_password_endpoint(
        body: &ChangePasswordRequest,
    ) -> AuthResult<
        alibi_core::endpoint::ServerEndpoint<ChangePasswordResponse<alibi_core::UserView>>,
    > {
        alibi_core::endpoint::ServerEndpoint::new("password-management", "changePassword")
            .with_body(body)
    }

    async fn handle_request_password_reset(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: RequestPasswordResetRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let response = request_password_reset_core(&body, &self.config, ctx, Some(req)).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut body: ResetPasswordRequest = match crate::authentication_helpers::parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        if body.token.as_ref().is_none_or(String::is_empty) {
            body.token = req.query.get("token").cloned();
        }
        let response = reset_password_core(&body, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_change_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: ChangePasswordRequest = match crate::authentication_helpers::parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (user, _session) = ctx
            .require_authoritative_session_record(req)
            .await
            .map_err(crate::helpers::unauthorized_if_session_missing)?;
        let meta = RequestMeta::from_request(req);

        let (response, new_token) =
            change_password_core(&body, &user, &self.config, &meta, ctx).await?;

        let auth_response = AuthResponse::json(200, &response)?;
        let Some(token) = new_token else {
            return Ok(auth_response);
        };
        let dont_remember =
            crate::authentication_helpers::dont_remember_preference(req, &ctx.config);
        crate::authentication_helpers::with_session_cookies(
            auth_response,
            &ctx.config,
            &token,
            dont_remember,
        )
    }

    async fn handle_verify_password(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyPasswordRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let Some(user) = Self::get_current_user(req, ctx).await? else {
            // better-call's default body for a session-gated endpoint hit
            // without a session, which upstream returns verbatim.
            return Ok(
                AuthError::AuthenticationFailed("Unauthorized".to_owned()).to_auth_response()
            );
        };
        let response = verify_password_core(&body, &user, &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_reset_password_token(
        &self,
        token: &str,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let callback_url = req.query.get("callbackURL").ok_or(AuthError::Upstream {
            status: 400,
            code: codes::VALIDATION_ERROR,
            message: "[query.callbackURL] Invalid input: expected string, received undefined",
        })?;
        let query = ResetPasswordTokenQuery {
            callback_url: Some(callback_url.clone()),
        };
        let url =
            reset_password_token_core((!token.is_empty()).then_some(token), &query, ctx, Some(req))
                .await?;
        let mut headers = alibi_core::Headers::new();
        _ = headers.insert("Location", url);
        _ = headers.insert("content-type", "application/json");
        Ok(AuthResponse {
            status: 302,
            headers,
            body: Vec::new(),
        })
    }

    async fn get_current_user<S: alibi_core::AuthSchema>(
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<S::User>> {
        let session_manager = ctx.session_manager();

        if let Some(token) = session_manager.extract_session_token(req)
            && let Some(session) = session_manager.get_session(&token).await?
        {
            return ctx.session_user(&session).await;
        }

        Ok(None)
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::types::RequestPasswordResetResponse;
    use super::*;
    use crate::test_helpers;
    use alibi_core::AuthContext;
    use alibi_core::config::{AuthConfig, PasswordConfig};
    use alibi_core::utils::password::{hash_password, verify_password};
    use alibi_core::wire::{SessionView, UserView};
    use alibi_core::{CreateAccount, CreateUser, CreateVerification};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    const PASSWORD_RESET_SUCCESS_MESSAGE: &str =
        "If this email exists in our system, check your email for the reset link";

    struct NoopResetSender;

    #[async_trait::async_trait]
    impl SendResetPassword for NoopResetSender {
        async fn send(
            &self,
            _user: &serde_json::Value,
            _url: &str,
            _token: &str,
        ) -> AuthResult<()> {
            Ok(())
        }
    }

    fn plugin_with_reset_sender() -> PasswordManagementPlugin {
        PasswordManagementPlugin::new().send_reset_password(Arc::new(NoopResetSender))
    }

    async fn create_test_context_with_user() -> (AuthContext<TestSchema>, UserView, SessionView) {
        let mut config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        config.password = PasswordConfig {
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
        };

        let ctx = test_helpers::create_test_context_with_config(config).await;

        // Create test user with hashed password
        let password_hash = hash_password(None, "Password123!").await.unwrap();

        let create_user = CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User");
        let user = test_helpers::create_user(&ctx, create_user).await;
        _ = ctx
            .database
            .create_account(CreateAccount {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                user_id: user.id.clone(),
                account_id: user.id.clone().into(),
                provider_id: "credential".to_owned(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some(password_hash),
            })
            .await
            .unwrap();
        let session =
            test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(24)).await;

        (ctx, user, session)
    }

    async fn create_test_context_with_oauth_only_user()
    -> (AuthContext<TestSchema>, UserView, SessionView) {
        let (ctx, user, session) = create_test_context_with_user().await;

        let existing_accounts = ctx.database.get_user_accounts(&user.id).await.unwrap();
        for account in existing_accounts {
            ctx.database.delete_account(&account.id).await.unwrap();
        }

        _ = ctx
            .database
            .create_account(CreateAccount {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                user_id: user.id.clone(),
                account_id: "google-account-id".to_owned().into(),
                provider_id: "google".to_owned(),
                access_token: Some("oauth-access-token".to_owned()),
                refresh_token: Some("oauth-refresh-token".to_owned()),
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: Some("email profile".to_owned()),
                password: None,
            })
            .await
            .unwrap();

        (ctx, user, session)
    }

    /// Helper: create a reset-password verification token for the given user
    /// and store it in the database. Returns the token string.
    async fn create_reset_token(
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        user_id: &str,
    ) -> String {
        let reset_token = uuid::Uuid::new_v4().simple().to_string();
        let create_verification = CreateVerification {
            identifier: format!("reset-password:{reset_token}"),
            value: user_id.to_owned(),
            expires_at: Utc::now() + Duration::hours(24),
        };
        ctx.database
            .create_verification(create_verification)
            .await
            .unwrap();
        reset_token
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_request_password_reset_success() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "email": "test@example.com",
            "redirectTo": "http://localhost:3000/reset"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin
            .handle_request_password_reset(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_request_password_reset_unknown_email() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "email": "unknown@example.com"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin
            .handle_request_password_reset(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: RequestPasswordResetResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
        assert_eq!(response_data.message, PASSWORD_RESET_SUCCESS_MESSAGE);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);

        // Verify password was updated
        let accounts = ctx.database.get_user_accounts(&user.id).await.unwrap();
        let stored_hash = accounts
            .iter()
            .find(|account| account.provider_id == "credential")
            .and_then(|account| account.password.as_deref())
            .unwrap();
        assert!(
            verify_password(None, "NewPassword123!", stored_hash)
                .await
                .is_ok()
        );

        let verification_check = ctx
            .database
            .get_verification_by_identifier(&format!("reset-password:{reset_token}"))
            .await
            .unwrap();
        assert!(verification_check.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": "invalid_token"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_weak_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "weak",
            "token": reset_token
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_reset_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn change_password_validates_new_length_before_account_lookup() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _, session) = create_test_context_with_oauth_only_user().await;
        for (password, code) in [
            ("short".to_owned(), "PASSWORD_TOO_SHORT"),
            ("A".repeat(129), "PASSWORD_TOO_LONG"),
        ] {
            let req = test_helpers::create_auth_request_no_query(
                HttpMethod::Post,
                "/change-password",
                Some(&session.token),
                Some(
                    serde_json::to_vec(&serde_json::json!({
                        "currentPassword": "Password123!", "newPassword": password
                    }))
                    .unwrap(),
                ),
            );
            let error = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.error_payload().1.as_deref(), Some(code));
        }
    }

    #[tokio::test]
    async fn change_password_rejects_oversized_current_password_before_account_lookup() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _, session) = create_test_context_with_oauth_only_user().await;
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "currentPassword": "🍵".repeat(65), "newPassword": "NewPassword123!"
                }))
                .unwrap(),
            ),
        );
        let error = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(
            error.error_payload().1.as_deref(),
            Some("PASSWORD_TOO_LONG")
        );
    }

    #[tokio::test]
    async fn change_password_treats_empty_credential_hash_as_missing() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, session) = create_test_context_with_user().await;
        let account = ctx
            .database
            .get_user_accounts(&user.id)
            .await
            .unwrap()
            .remove(0);
        ctx.database
            .update_account(
                &account.id,
                alibi_core::UpdateAccount {
                    password: Some(String::new()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "currentPassword": "Password123!", "newPassword": "NewPassword123!"
                }))
                .unwrap(),
            ),
        );
        let error = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(
            error.error_payload().1.as_deref(),
            Some("CREDENTIAL_ACCOUNT_NOT_FOUND")
        );
        assert_eq!(
            ctx.database.get_user_accounts(&user.id).await.unwrap()[0]
                .password
                .as_deref(),
            Some("")
        );
    }

    #[tokio::test]
    async fn change_password_uses_context_password_provider() {
        struct ContextHasher;
        #[async_trait::async_trait]
        impl PasswordHasher for ContextHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                assert_eq!(password, "NewPassword123!");
                Ok("context-provider-hash".into())
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                assert!(hash.contains(':'));
                assert_eq!(password, "Password123!");
                Ok(true)
            }
        }
        let (mut ctx, user, session) = create_test_context_with_user().await;
        let mut init =
            alibi_core::AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        crate::EmailPasswordPlugin::new()
            .password_hasher(Arc::new(ContextHasher))
            .on_init(&mut init)
            .await
            .unwrap();
        ctx.extensions = init.into_parts().extensions;
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "currentPassword": "Password123!", "newPassword": "NewPassword123!"
                }))
                .unwrap(),
            ),
        );
        let response = PasswordManagementPlugin::new()
            .handle_change_password(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            ctx.database.get_user_accounts(&user.id).await.unwrap()[0]
                .password
                .as_deref(),
            Some("context-provider-hash")
        );
    }

    #[tokio::test]
    async fn change_password_preserves_password_verifier_failures() {
        struct FailingVerifier;
        #[async_trait::async_trait]
        impl PasswordHasher for FailingVerifier {
            async fn hash(&self, _: &str) -> AuthResult<String> {
                Ok("unused-new-hash".into())
            }
            async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
                Err(AuthError::internal("password provider unavailable"))
            }
        }
        let (ctx, user, session) = create_test_context_with_user().await;
        let before = ctx.database.get_user_accounts(&user.id).await.unwrap()[0]
            .password
            .clone();
        let mut plugin = PasswordManagementPlugin::new();
        plugin.config.password_hasher = Some(Arc::new(FailingVerifier));
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "currentPassword": "Password123!", "newPassword": "NewPassword123!"
                }))
                .unwrap(),
            ),
        );
        let error = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(error.status_code(), 500);
        assert!(error.to_string().contains("password provider unavailable"));
        assert_eq!(
            ctx.database.get_user_accounts(&user.id).await.unwrap()[0].password,
            before
        );
    }

    #[tokio::test]
    async fn test_change_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": false
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_null()
        ); // No new token when not revoking sessions

        // Verify password was updated by checking the database directly
        let user_id = (*(*(response_data)
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("id")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap();
        let accounts = ctx.database.get_user_accounts(user_id).await.unwrap();
        let stored_hash = accounts
            .iter()
            .find(|account| account.provider_id == "credential")
            .and_then(|account| account.password.as_deref())
            .unwrap();
        assert!(
            verify_password(None, "NewPassword123!", stored_hash)
                .await
                .is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_with_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_string()
        ); // New token when revoking sessions
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_sets_cookie_on_session_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is present
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_some(),
            "Set-Cookie header must be set when revokeOtherSessions is true"
        );

        let cookie_value = set_cookie.unwrap();
        assert!(
            cookie_value.contains(&ctx.config.session.cookie_name),
            "Cookie must contain the session cookie name"
        );
        assert!(
            cookie_value.contains("Path=/"),
            "Cookie must contain Path=/"
        );
        assert!(
            cookie_value.contains("Max-Age=604800"),
            "Cookie must retain the configured session lifetime"
        );
        assert!(
            !cookie_value.contains("Expires="),
            "Source does not synthesize Expires from Max-Age"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_no_cookie_without_revocation() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify Set-Cookie header is NOT present when not revoking sessions
        let set_cookie = response.headers.get("Set-Cookie");
        assert!(
            set_cookie.is_none(),
            "Set-Cookie header must not be set when revokeOtherSessions is not true"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_revoke_with_boolean() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        // Send revokeOtherSessions as a boolean (as better-auth TS SDK does)
        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!",
            "revokeOtherSessions": true
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_change_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert!(
            (*(response_data)
                .get("token")
                .unwrap_or(&serde_json::Value::Null))
            .is_string(),
            "New token must be returned when revokeOtherSessions is boolean true"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_wrong_current_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "WrongPassword123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_change_password_unauthorized() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_change_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 401);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
    // a valid session and the correct credential password succeeds.
    #[tokio::test]
    async fn test_verify_password_success() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: StatusResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.status);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword with
    // a bad password returns BAD_REQUEST / Invalid password.
    #[tokio::test]
    async fn test_verify_password_invalid_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "wrong-password"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.to_string(), "Invalid password");
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.ts :: verifyPassword returns
    // Invalid password when the signed-in user does not have a credential account.
    #[tokio::test]
    async fn test_verify_password_oauth_only_user_returns_invalid_password() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, session) = create_test_context_with_oauth_only_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let err = plugin.handle_verify_password(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.to_string(), "Invalid password");
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: verifyPassword
    // requires an authenticated session.
    #[tokio::test]
    async fn test_verify_password_requires_session() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let body = serde_json::json!({
            "password": "Password123!"
        });

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/verify-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_verify_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        // Upstream returns better-call's default 401 body rather than an empty one.
        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("code").unwrap_or(&serde_json::Value::Null)),
            "UNAUTHORIZED"
        );
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Unauthorized"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_redirects_with_callback_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );

        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains("http://localhost:3000/reset"),
            "redirect must preserve the callback URL"
        );
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains(&format!("token={reset_token}")),
            "redirect must contain the reset token"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_with_callback() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );

        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token(&reset_token, &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);

        // Check redirect URL
        let location_header = response
            .headers
            .iter()
            .find(|(key, _)| *key == "Location")
            .map(|(_, value)| value);
        assert!(location_header.is_some());
        assert!(
            location_header
                .unwrap()
                .contains("http://localhost:3000/reset")
        );
        assert!(location_header.unwrap().contains(&reset_token));
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_reset_password_token_endpoint_invalid_token() {
        let plugin = PasswordManagementPlugin::new();
        let (ctx, _user, _session) = create_test_context_with_user().await;

        let mut query = HashMap::new();
        query.insert(
            "callbackURL".to_owned(),
            "http://localhost:3000/reset".to_owned(),
        );
        let req = AuthRequest::from_parts(
            HttpMethod::Get,
            "/reset-password/token".to_owned(),
            HashMap::new(),
            None,
            query,
        );

        let response = plugin
            .handle_reset_password_token("invalid_token", &req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            (*(response.headers)
                .get("Location")
                .expect("fixture contains the requested index"))
            .contains("error=INVALID_TOKEN")
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = PasswordManagementPlugin::new();
        let routes = AuthPlugin::<
            alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::routes(&plugin);

        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/request-password-reset" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/reset-password/{token}" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/verify-password" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/change-password" && r.method == HttpMethod::Post)
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = plugin_with_reset_sender();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let body = serde_json::json!({"email": "test@example.com"});
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/request-password-reset",
            None,
            Some(body.to_string().into_bytes()),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);

        // Test change password
        let body_2 = serde_json::json!({
            "currentPassword": "Password123!",
            "newPassword": "NewPassword123!"
        });
        let req_2 = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/change-password",
            Some(&session.token),
            Some(body_2.to_string().into_bytes()),
        );
        let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap();
        assert!(response_2.is_some());
        assert_eq!(response_2.unwrap().status, 200);

        // Test invalid route
        let req_3 = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/invalid-route",
            None,
            None,
        );
        let response_3 = plugin.on_request(&req_3, &ctx).await.unwrap();
        assert!(response_3.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_configuration() {
        let config = PasswordManagementConfig {
            reset_token_expiry_hours: 48,
            require_current_password: false,
            send_email_notifications: false,
            ..Default::default()
        };

        let plugin = PasswordManagementPlugin::with_config(config);
        assert_eq!(plugin.config.reset_token_expiry_hours, 48);
        assert!(!plugin.config.require_current_password);
        assert!(!plugin.config.send_email_notifications);
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_send_reset_password_custom_sender() {
        use alibi_core::{BackgroundTaskCompletion, BackgroundTaskHandler};
        use std::sync::{
            Mutex,
            atomic::{AtomicU32, Ordering},
        };

        struct Sender {
            calls: Arc<AtomicU32>,
            fail: bool,
            token: Arc<Mutex<Option<String>>>,
        }
        #[async_trait::async_trait]
        impl SendResetPassword for Sender {
            async fn send(&self, _: &serde_json::Value, _: &str, token: &str) -> AuthResult<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self.token.lock().unwrap() = Some(token.to_owned());
                if self.fail {
                    Err(AuthError::internal("Email queue unavailable"))
                } else {
                    Ok(())
                }
            }
        }
        #[derive(Default)]
        struct Observer(Mutex<Option<BackgroundTaskCompletion>>);
        impl BackgroundTaskHandler for Observer {
            fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
                *self.0.lock().unwrap() = Some(completion);
                Ok(())
            }
        }
        for (fail, background) in [(false, false), (true, false), (true, true)] {
            let calls = Arc::new(AtomicU32::new(0));
            let token = Arc::new(Mutex::new(None));
            let plugin = PasswordManagementPlugin::new().send_reset_password(Arc::new(Sender {
                calls: Arc::clone(&calls),
                fail,
                token: Arc::clone(&token),
            }));
            let (mut ctx, user, _) = create_test_context_with_user().await;
            let observer = Arc::new(Observer::default());
            if background {
                Arc::make_mut(&mut ctx.config).background_tasks = Some(observer.clone());
            }
            let req = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                "/request-password-reset",
                None,
                Some(serde_json::json!({"email":"test@example.com"})),
            );
            let result = plugin.handle_request_password_reset(&req, &ctx).await;
            if fail && !background {
                assert_eq!(result.unwrap_err().status_code(), 500);
            } else {
                assert_eq!(result.unwrap().status, 200);
            }
            if background {
                let completion = observer.0.lock().unwrap().take().unwrap();
                completion.await.unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let token = token.lock().unwrap().take().unwrap();
            let proof = ctx
                .database
                .get_verification_by_identifier(&format!("reset-password:{token}"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(proof.value, user.id);
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_on_password_reset_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let callback_called = Arc::new(AtomicBool::new(false));
        let called_clone = std::sync::Arc::clone(&callback_called);

        let callback: Arc<OnPasswordResetCallback> = Arc::new(move |_user_value| {
            let called = std::sync::Arc::clone(&called_clone);
            Box::pin(async move {
                called.store(true, Ordering::SeqCst);
                Ok(())
            })
        });

        let plugin = PasswordManagementPlugin::new().on_password_reset(callback);
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // The on_password_reset callback should have been called
        assert!(
            callback_called.load(Ordering::SeqCst),
            "on_password_reset callback should be invoked after password reset"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_revoke_sessions_on_password_reset_false() {
        let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(false);
        let (ctx, user, session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Session should still exist since revoke_sessions_on_password_reset=false
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(
            !sessions.is_empty(),
            "Sessions should remain when revoke_sessions_on_password_reset=false"
        );
        assert!(
            sessions.iter().any(|s| s.token == session.token),
            "The original session should still exist"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: describe("forget password") and packages/better-auth/src/api/routes/password.ts; adapted to the Rust password-management plugin.
    #[tokio::test]
    async fn test_revoke_sessions_on_password_reset_true() {
        let plugin = PasswordManagementPlugin::new().revoke_sessions_on_password_reset(true);
        let (ctx, user, _session) = create_test_context_with_user().await;

        let reset_token = create_reset_token(&ctx, &user.id).await;

        let body = serde_json::json!({
            "newPassword": "NewPassword123!",
            "token": reset_token
        });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_reset_password(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Sessions should be revoked since revoke_sessions_on_password_reset=true (default)
        let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert!(
            sessions.is_empty(),
            "Sessions should be revoked when revoke_sessions_on_password_reset=true"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/password.test.ts :: "still revokes sessions when onPasswordReset throws".
    #[tokio::test]
    async fn failing_reset_callback_runs_after_revocation_and_the_password_write() {
        let observed = Arc::new(std::sync::Mutex::new(None));
        let (ctx, user, _session) = create_test_context_with_user().await;
        let database = Arc::clone(&ctx.database);
        let user_id = user.id.clone();
        let seen = Arc::clone(&observed);
        let callback: Arc<OnPasswordResetCallback> = Arc::new(move |_user_value| {
            let database = Arc::clone(&database);
            let user_id = user_id.clone();
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                let sessions = database.get_user_sessions(&user_id).await?;
                *seen.lock().unwrap() = Some(sessions.len());
                Err(AuthError::internal("hook failed"))
            })
        });
        let plugin = PasswordManagementPlugin::new()
            .revoke_sessions_on_password_reset(true)
            .on_password_reset(callback);
        let reset_token = create_reset_token(&ctx, &user.id).await;
        let body = serde_json::json!({ "newPassword": "NewPassword123!", "token": reset_token });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/reset-password",
            None,
            Some(body.to_string().into_bytes()),
        );

        assert!(plugin.handle_reset_password(&req, &ctx).await.is_err());
        assert_eq!(*observed.lock().unwrap(), Some(0));
        assert_eq!(
            ctx.database
                .get_user_sessions(&user.id)
                .await
                .unwrap()
                .len(),
            0
        );
        let hash = crate::helpers::get_credential_account(&ctx, &user.id)
            .await
            .unwrap()
            .and_then(|account| account.password)
            .unwrap();
        verify_password(None, "NewPassword123!", &hash)
            .await
            .unwrap();
    }
}
// LCOV_EXCL_STOP
