//! Plugin adapter transforms affect every trusted facade and real transactions.

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::store::{AccountStore, AdapterAfterHook, AdapterEvent, AuthStore};
use better_auth_core::{AuthAccount, CreateAccount};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthUser, CreateUser, UpdateUser,
    store::{UserStore, transaction},
};
use better_auth_seaorm::{
    Database, DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore,
};
use std::sync::{Arc, Mutex};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[derive(Debug, PartialEq)]
struct DefaultsObserved {
    email: String,
    two_factor: Option<bool>,
    banned: Option<bool>,
    role: Option<String>,
    in_transaction: bool,
}

struct ApplicationDefaultsObserver {
    seen: Arc<Mutex<Vec<DefaultsObserved>>>,
}

#[async_trait]
impl DatabaseHooks<Schema, SeaOrmBackend> for ApplicationDefaultsObserver {
    async fn before_create_user(
        &self,
        input: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.seen.lock().unwrap().push(DefaultsObserved {
            email: input.email.clone().unwrap(),
            two_factor: input.two_factor_enabled,
            banned: input.banned,
            role: input.role.clone(),
            in_transaction: ctx.tx.is_some(),
        });
        Ok(HookControl::Continue)
    }
}

struct UserTransforms;

#[async_trait]
impl AuthPlugin<Schema> for UserTransforms {
    fn name(&self) -> &'static str {
        "user-store-transforms"
    }

    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        ctx.register_user_create_transform(|mut input| {
            if input.email.as_deref() == Some("rejected@transforms.fixture.test") {
                return Err(AuthError::forbidden("creation rejected"));
            }
            input.name = Some(format!("{}:first", input.name.unwrap_or_default()));
            Ok(input)
        });
        ctx.register_user_create_transform(|mut input| {
            input.name = Some(format!("{}:second", input.name.unwrap_or_default()));
            Ok(input)
        });
        ctx.register_user_update_transform(|_id, mut input| {
            if input.name.as_deref() == Some("reject update") {
                return Err(AuthError::forbidden("update rejected"));
            }
            if matches!(input.phone_number, Some(None)) {
                input.phone_number_verified = Some(false);
            }
            Ok(input)
        });
        Ok(())
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn store() -> (AuthConfig, Arc<SeaOrmStore<Schema>>) {
    let config = AuthConfig::new("plugin-transform-fixture-secret-minimum-32-characters");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
    (config, store)
}

struct DirectRecordObserver {
    seen: Arc<Mutex<Vec<serde_json::Value>>>,
}

#[async_trait]
impl AdapterAfterHook<Schema> for DirectRecordObserver {
    async fn after_write(
        &self,
        event: &AdapterEvent<Schema>,
        database: &dyn AuthStore<Schema>,
    ) -> AuthResult<()> {
        let observation = match event {
            AdapterEvent::UserCreated(record) => {
                let stored = database.get_user_by_id(&record.id()).await?.unwrap();
                assert_eq!(stored.role(), record.role());
                serde_json::json!({"entity":"user","id":stored.id(),"role":record.raw_snapshot().values().get("role")})
            }
            AdapterEvent::AccountCreated(record) => {
                let stored = database.get_user_accounts(&record.user_id()).await?;
                assert!(stored.iter().any(
                    |account| account.id() == record.id() && account.scope() == record.scope()
                ));
                serde_json::json!({"entity":"account","id":record.id(),"scope":record.raw_snapshot().values().get("scope")})
            }
            _ => {
                return Err(AuthError::internal(
                    "Unexpected direct initialization write",
                ));
            }
        };
        self.seen.lock().unwrap().push(observation);
        Ok(())
    }
}

struct CommittedSessionObserver {
    raw: Arc<SeaOrmStore<Schema>>,
    seen: Arc<Mutex<Vec<String>>>,
    fail: bool,
}
#[async_trait]
impl better_auth_core::store::SessionCreatedHook<Schema> for CommittedSessionObserver {
    async fn after_create(
        &self,
        session: &<Schema as better_auth_core::AuthSchema>::Session,
        database: &dyn better_auth_core::store::AuthStore<Schema>,
    ) -> AuthResult<()> {
        use better_auth_core::AuthSession;
        use better_auth_core::store::SessionStore;
        assert!(self.raw.get_session(session.token()).await?.is_some());
        drop(
            database
                .update_user(
                    session.user_id().as_ref(),
                    UpdateUser {
                        phone_number: Some(None),
                        ..Default::default()
                    },
                )
                .await?,
        );
        self.seen.lock().unwrap().push(session.token().to_owned());
        if self.fail {
            return Err(AuthError::internal(
                "post-commit application callback failed",
            ));
        }
        Ok(())
    }
}
struct SessionLifecyclePlugin(Arc<CommittedSessionObserver>);
#[async_trait]
impl AuthPlugin<Schema> for SessionLifecyclePlugin {
    fn name(&self) -> &'static str {
        "committed-session-observer"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        ctx.register_session_created_hook(self.0.clone());
        Ok(())
    }
}
fn session_input(user_id: String, token: &str) -> better_auth_core::CreateSession {
    better_auth_core::CreateSession {
        user_id,
        token: Some(token.into()),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        additional_fields: Default::default(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_initialization_preserves_configured_adapter_output_and_committed_observers() {
        use better_auth_core::field_policy::FieldConfig;
        use better_auth_core::utils::json::JsValue;

        let (plain, raw) = store().await;
        let mut configured = plain.clone();
        for (fields, name) in [
            (&mut configured.user.additional_fields, "role"),
            (&mut configured.account.additional_fields, "scope"),
        ] {
            drop(fields.insert(
                name.into(),
                FieldConfig::new(serde_json::json!({"type":"string"})).transform_output(
                    |value| async move {
                        let value = value.map(|value| value.to_json_value()).transpose()?;
                        Ok(Some(JsValue::from(serde_json::json!({"stored":value}))))
                    },
                ),
            ));
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut init = AuthInitContext::<Schema>::new(Arc::new(configured), raw.clone());
        init.register_adapter_after_hook(Arc::new(DirectRecordObserver { seen: seen.clone() }));
        let database = init.database_with_registered_transforms();
        let mut input = CreateUser::new().with_email("direct-output@transforms.fixture.test");
        input.role = Some("member".into());
        let user = database.create_user_record(input).await.unwrap();
        assert_eq!(user.role(), Some("member"));
        assert_eq!(
            user.raw_snapshot().values().get("role"),
            Some(&serde_json::json!({"stored":"member"}))
        );
        let account = database
            .create_account_record(CreateAccount {
                user_id: user.id().into_owned(),
                account_id: "direct-subject".into(),
                provider_id: "application".into(),
                scope: Some("read write".into()),
                additional_fields: Default::default(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                password: None,
            })
            .await
            .unwrap();
        assert_eq!(account.scope(), Some("read write"));
        assert_eq!(
            account.raw_snapshot().values().get("scope"),
            Some(&serde_json::json!({"stored":"read write"}))
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                serde_json::json!({"entity":"user","id":user.id(),"role":{"stored":"member"}}),
                serde_json::json!({"entity":"account","id":account.id(),"scope":{"stored":"read write"}}),
            ]
        );

        let mut observer_only = AuthInitContext::<Schema>::new(Arc::new(plain), raw.clone());
        observer_only
            .register_adapter_after_hook(Arc::new(DirectRecordObserver { seen: seen.clone() }));
        let untransformed = observer_only
            .database_with_registered_transforms()
            .create_user_record(
                CreateUser::new().with_email("direct-observer@transforms.fixture.test"),
            )
            .await
            .unwrap();
        assert_eq!(
            seen.lock().unwrap().last(),
            Some(&serde_json::json!({"entity":"user","id":untransformed.id(),"role":null}))
        );
        assert_eq!(raw.get_user_accounts(&user.id()).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn transforms_are_ordered_and_local_to_each_auth_instance() {
        let (config, raw) = store().await;
        let enabled = AuthBuilder::new(config.clone())
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(UserTransforms)
            .build()
            .await
            .unwrap();
        let disabled = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .build()
            .await
            .unwrap();
        assert!(Arc::ptr_eq(enabled.store(), &enabled.context().database));

        for (index, writer) in [enabled.store(), &enabled.context().database]
            .into_iter()
            .enumerate()
        {
            let mut input = CreateUser::new()
                .with_email(format!("enabled-{index}@transforms.fixture.test"))
                .with_name("original");
            input.phone_number = Some(format!("+120255500{index:02}"));
            input.phone_number_verified = Some(true);
            let created = writer.create_user(input).await.unwrap();
            assert_eq!(created.name(), Some("original:first:second"));
            let cleared = writer
                .update_user(
                    &created.id(),
                    UpdateUser {
                        phone_number: Some(None),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(cleared.phone_number(), None);
            assert_eq!(cleared.phone_number_verified(), Some(false));
            let actual = raw.get_user_by_id(&created.id()).await.unwrap().unwrap();
            assert_eq!(actual.name(), created.name());
            assert_eq!(actual.phone_number_verified(), Some(false));
        }

        let mut input = CreateUser::new()
            .with_email("disabled@transforms.fixture.test")
            .with_name("original");
        input.phone_number = Some("+12025550100".into());
        input.phone_number_verified = Some(true);
        let created = disabled.store().create_user(input).await.unwrap();
        assert_eq!(created.name(), Some("original"));
        let cleared = disabled
            .store()
            .update_user(
                &created.id(),
                UpdateUser {
                    phone_number: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(cleared.phone_number_verified(), Some(true));
    }

    #[tokio::test]
    async fn rejected_transforms_never_write_user_data() {
        let (config, raw) = store().await;
        let auth = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(UserTransforms)
            .build()
            .await
            .unwrap();
        let email = "rejected@transforms.fixture.test";
        assert!(
            auth.store()
                .create_user(CreateUser::new().with_email(email))
                .await
                .is_err()
        );
        assert!(raw.get_user_by_email(email).await.unwrap().is_none());

        let actual = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("valid@transforms.fixture.test")
                    .with_name("original"),
            )
            .await
            .unwrap();
        assert!(
            auth.context()
                .database
                .update_user(
                    &actual.id(),
                    UpdateUser {
                        name: Some("reject update".into()),
                        email: Some("replacement@transforms.fixture.test".into()),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
        let persisted = raw.get_user_by_id(&actual.id()).await.unwrap().unwrap();
        assert_eq!(persisted.name(), actual.name());
        assert_eq!(persisted.email(), actual.email());
        assert!(
            raw.get_user_by_email("replacement@transforms.fixture.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn transactional_creation_uses_transforms_and_preserves_commit_and_rollback() {
        let (config, raw) = store().await;
        let auth = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(UserTransforms)
            .build()
            .await
            .unwrap();
        let committed = transaction(auth.store().as_ref(), |tx| {
            Box::pin(async move {
                tx.create_user(
                    CreateUser::new()
                        .with_email("committed@transforms.fixture.test")
                        .with_name("original"),
                )
                .await
            })
        })
        .await
        .unwrap();
        assert_eq!(committed.name(), Some("original:first:second"));
        let persisted = raw
            .get_user_by_email("committed@transforms.fixture.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.id(), committed.id());
        assert_eq!(persisted.name(), committed.name());

        let result: AuthResult<()> = transaction(auth.context().database.as_ref(), |tx| {
            Box::pin(async move {
                let pending = tx
                    .create_user(
                        CreateUser::new()
                            .with_email("rolled-back@transforms.fixture.test")
                            .with_name("original"),
                    )
                    .await?;
                assert_eq!(pending.name(), Some("original:first:second"));
                Err(AuthError::forbidden("force rollback after real insertion"))
            })
        })
        .await;
        assert!(result.is_err());
        assert!(
            raw.get_user_by_email("rolled-back@transforms.fixture.test")
                .await
                .unwrap()
                .is_none()
        );
        assert!(raw.get_user_by_id(&committed.id()).await.unwrap().is_some());
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn enabled_plugin_defaults_preserve_explicit_flags_and_existing_nulls() {
        use better_auth::plugins::{AdminPlugin, TwoFactorPlugin};

        let (config, raw) = store().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let raw = Arc::new(
            Arc::try_unwrap(raw)
                .ok()
                .unwrap()
                .hook(ApplicationDefaultsObserver {
                    seen: Arc::clone(&seen),
                }),
        );
        let existing = raw
            .create_user(CreateUser::new().with_email("existing-null@transforms.fixture.test"))
            .await
            .unwrap();
        assert_eq!(existing.two_factor_enabled_value(), None);
        assert_eq!(existing.banned_value(), None);

        let enabled = AuthBuilder::new(config.clone())
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(AdminPlugin::new())
            .plugin(TwoFactorPlugin::new())
            .build()
            .await
            .unwrap();
        let disabled = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .build()
            .await
            .unwrap();
        let json = serde_json::to_value(enabled.context().user_view(&existing)).unwrap();
        assert_eq!(json.get("twoFactorEnabled"), Some(&serde_json::Value::Null));
        assert_eq!(json.get("banned"), Some(&serde_json::Value::Null));
        assert!(!existing.two_factor_enabled());
        assert!(!existing.banned());

        for (index, writer) in [enabled.store(), &enabled.context().database]
            .into_iter()
            .enumerate()
        {
            let created = writer
                .create_user(
                    CreateUser::new()
                        .with_email(format!("default-{index}@transforms.fixture.test")),
                )
                .await
                .unwrap();
            assert_eq!(created.two_factor_enabled_value(), Some(false));
            assert_eq!(created.banned_value(), Some(false));
            assert_eq!(created.role(), Some("user"));
            let persisted = raw.get_user_by_id(&created.id()).await.unwrap().unwrap();
            assert_eq!(persisted.two_factor_enabled_value(), Some(false));
            assert_eq!(persisted.banned_value(), Some(false));
        }
        let committed = transaction(enabled.store().as_ref(), |tx| {
            Box::pin(async move {
                tx.create_user(CreateUser::new().with_email("default-tx@transforms.fixture.test"))
                    .await
            })
        })
        .await
        .unwrap();
        assert_eq!(committed.two_factor_enabled_value(), Some(false));
        assert_eq!(committed.banned_value(), Some(false));
        let stored = raw.get_user_by_id(&committed.id()).await.unwrap().unwrap();
        assert_eq!(stored.two_factor_enabled_value(), Some(false));
        assert_eq!(stored.banned_value(), Some(false));

        let mut explicit = CreateUser::new()
            .with_email("explicit-true@transforms.fixture.test")
            .with_role("admin");
        explicit.two_factor_enabled = Some(true);
        explicit.banned = Some(true);
        let explicit = enabled.store().create_user(explicit).await.unwrap();
        assert_eq!(explicit.two_factor_enabled_value(), Some(true));
        assert_eq!(explicit.banned_value(), Some(true));
        assert_eq!(explicit.role(), Some("admin"));
        let hidden = serde_json::to_value(disabled.context().user_view(&explicit)).unwrap();
        assert!(hidden.get("twoFactorEnabled").is_none());
        assert!(hidden.get("banned").is_none());
        assert!(hidden.get("role").is_none());

        let still_unset = disabled
            .store()
            .create_user(CreateUser::new().with_email("disabled-null@transforms.fixture.test"))
            .await
            .unwrap();
        assert_eq!(still_unset.two_factor_enabled_value(), None);
        assert_eq!(still_unset.banned_value(), None);
        let retained = raw.get_user_by_id(&existing.id()).await.unwrap().unwrap();
        assert_eq!(retained.two_factor_enabled_value(), None);
        assert_eq!(retained.banned_value(), None);
        assert_eq!(
            *seen.lock().unwrap(),
            [
                DefaultsObserved {
                    email: "existing-null@transforms.fixture.test".into(),
                    two_factor: None,
                    banned: None,
                    role: None,
                    in_transaction: false,
                },
                DefaultsObserved {
                    email: "default-0@transforms.fixture.test".into(),
                    two_factor: Some(false),
                    banned: Some(false),
                    role: Some("user".into()),
                    in_transaction: false,
                },
                DefaultsObserved {
                    email: "default-1@transforms.fixture.test".into(),
                    two_factor: Some(false),
                    banned: Some(false),
                    role: Some("user".into()),
                    in_transaction: false,
                },
                DefaultsObserved {
                    email: "default-tx@transforms.fixture.test".into(),
                    two_factor: Some(false),
                    banned: Some(false),
                    role: Some("user".into()),
                    in_transaction: true,
                },
                DefaultsObserved {
                    email: "explicit-true@transforms.fixture.test".into(),
                    two_factor: Some(true),
                    banned: Some(true),
                    role: Some("admin".into()),
                    in_transaction: false,
                },
                DefaultsObserved {
                    email: "disabled-null@transforms.fixture.test".into(),
                    two_factor: None,
                    banned: None,
                    role: None,
                    in_transaction: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn session_callbacks_observe_real_commit_and_finalized_transforms_but_never_sql_rollback()
    {
        use better_auth_core::{AuthSession, store::SessionStore};
        use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
        let (config, raw) = store().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let auth = AuthBuilder::new(config.clone())
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(UserTransforms)
            .plugin(SessionLifecyclePlugin(Arc::new(CommittedSessionObserver {
                raw: Arc::clone(&raw),
                seen: Arc::clone(&seen),
                fail: false,
            })))
            .build()
            .await
            .unwrap();
        let mut input = CreateUser::new().with_email("commit-owner@lifecycle.fixture.test");
        input.phone_number = Some("+12025550199".into());
        input.phone_number_verified = Some(true);
        let owner = auth.store().create_user(input).await.unwrap();
        let ordinary = auth
            .store()
            .create_session(session_input(owner.id().to_string(), "ordinary-session"))
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), &[ordinary.token()]);
        let actual = raw.get_user_by_id(&owner.id()).await.unwrap().unwrap();
        assert_eq!(actual.phone_number(), None);
        assert_eq!(actual.phone_number_verified(), Some(false));

        let owner_id = owner.id().to_string();
        let committed = transaction(auth.store().as_ref(), |tx| {
            Box::pin(async move {
                tx.create_session(session_input(owner_id, "committed-session"))
                    .await
            })
        })
        .await
        .unwrap();
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[ordinary.token(), committed.token()]
        );
        let _trigger = raw.connection().execute_raw(Statement::from_string(DbBackend::Sqlite,
        "CREATE TRIGGER reject_lifecycle_user BEFORE INSERT ON users WHEN NEW.email='sql-rejected@lifecycle.fixture.test' BEGIN SELECT RAISE(ABORT,'application rejected insert'); END"
    )).await.unwrap();
        let before = raw.get_user_sessions(&owner.id()).await.unwrap();
        let owner_id = owner.id().to_string();
        let rejected: AuthResult<()> = transaction(auth.store().as_ref(), |tx| {
            Box::pin(async move {
                drop(
                    tx.create_session(session_input(owner_id, "rolled-back-session"))
                        .await?,
                );
                drop(
                    tx.create_user(
                        CreateUser::new().with_email("sql-rejected@lifecycle.fixture.test"),
                    )
                    .await?,
                );
                Ok(())
            })
        })
        .await;
        assert!(matches!(rejected, Err(AuthError::Database(_))));
        assert!(
            raw.get_session("rolled-back-session")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            raw.get_user_by_email("sql-rejected@lifecycle.fixture.test")
                .await
                .unwrap()
                .is_none()
        );
        let after = raw.get_user_sessions(&owner.id()).await.unwrap();
        assert_eq!(
            before
                .iter()
                .map(better_auth_core::AuthSession::token)
                .collect::<Vec<_>>(),
            after
                .iter()
                .map(better_auth_core::AuthSession::token)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[ordinary.token(), committed.token()]
        );

        let failure = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(SessionLifecyclePlugin(Arc::new(CommittedSessionObserver {
                raw: Arc::clone(&raw),
                seen: Arc::clone(&seen),
                fail: true,
            })))
            .build()
            .await
            .unwrap();
        let owner_id = owner.id().to_string();
        let result = transaction(failure.store().as_ref(), |tx| {
            Box::pin(async move {
                tx.create_session(session_input(owner_id, "persisted-before-callback-error"))
                    .await
            })
        })
        .await;
        assert!(matches!(result, Err(AuthError::Internal(_))));
        assert!(
            raw.get_session("persisted-before-callback-error")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            seen.lock().unwrap().last().unwrap(),
            "persisted-before-callback-error"
        );
    }

    #[tokio::test]
    async fn last_login_database_tracking_requires_actual_request_context_for_trusted_store_calls()
    {
        use better_auth::plugins::LastLoginMethodConfig;
        use better_auth::plugins::LastLoginMethodPlugin;
        let (config, raw) = store().await;
        let auth = AuthBuilder::new(config)
            .store_arc(Arc::<SeaOrmStore<Schema>>::clone(&raw))
            .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
                store_in_database: true,
                ..Default::default()
            }))
            .build()
            .await
            .unwrap();
        let user = auth
            .store()
            .create_user(CreateUser::new().with_email("server-owner@tracking.fixture.test"))
            .await
            .unwrap();
        drop(
            auth.store()
                .create_session(session_input(user.id().to_string(), "trusted-session"))
                .await
                .unwrap(),
        );
        assert_eq!(
            raw.get_user_by_id(&user.id())
                .await
                .unwrap()
                .unwrap()
                .last_login_method(),
            None
        );
    }
}
