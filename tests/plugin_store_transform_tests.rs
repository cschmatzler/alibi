//! Plugin adapter transforms affect every trusted facade and real transactions.
#![expect(
    clippy::unwrap_used,
    reason = "regressions require real persisted results"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthUser, CreateUser, UpdateUser,
    store::{UserStore, transaction},
};
use better_auth_seaorm::{Database, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};

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
impl SeaOrmHooks<Schema> for ApplicationDefaultsObserver {
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

#[tokio::test]
async fn transforms_are_ordered_and_local_to_each_auth_instance() {
    let (config, raw) = store().await;
    let enabled = AuthBuilder::new(config.clone())
        .store_arc(raw.clone())
        .plugin(UserTransforms)
        .build()
        .await
        .unwrap();
    let disabled = AuthBuilder::new(config)
        .store_arc(raw.clone())
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
        assert_eq!(created.name().as_deref(), Some("original:first:second"));
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
    assert_eq!(created.name().as_deref(), Some("original"));
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
        .store_arc(raw.clone())
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
        .store_arc(raw.clone())
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
    assert_eq!(committed.name().as_deref(), Some("original:first:second"));
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
            assert_eq!(pending.name().as_deref(), Some("original:first:second"));
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
async fn enabled_plugin_defaults_preserve_explicit_flags_and_existing_nulls() {
    use better_auth::plugins::{AdminPlugin, TwoFactorPlugin};

    let (config, raw) = store().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let raw = Arc::new(
        Arc::try_unwrap(raw)
            .ok()
            .unwrap()
            .hook(ApplicationDefaultsObserver { seen: seen.clone() }),
    );
    let existing = raw
        .create_user(CreateUser::new().with_email("existing-null@transforms.fixture.test"))
        .await
        .unwrap();
    assert_eq!(existing.two_factor_enabled_value(), None);
    assert_eq!(existing.banned_value(), None);

    let enabled = AuthBuilder::new(config.clone())
        .store_arc(raw.clone())
        .plugin(AdminPlugin::new())
        .plugin(TwoFactorPlugin::new())
        .build()
        .await
        .unwrap();
    let disabled = AuthBuilder::new(config)
        .store_arc(raw.clone())
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
                CreateUser::new().with_email(format!("default-{index}@transforms.fixture.test")),
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
