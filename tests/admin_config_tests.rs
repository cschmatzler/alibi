//! Rust build-time admin configuration validation follows the pinned factory.
#![expect(
    clippy::unwrap_used,
    reason = "real installed SQLite configuration evidence"
)]
use async_trait::async_trait;
use better_auth::plugins::{AdminConfig, AdminPlugin, RolePermissions};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::store::{SessionStore, UserStore};
use better_auth_core::{
    AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthUser,
    CreateSession, CreateUser,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use std::{collections::HashMap, sync::Arc};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct ApplicationBootstrap(String);
#[async_trait]
impl AuthPlugin<Schema> for ApplicationBootstrap {
    fn name(&self) -> &'static str {
        "application-bootstrap"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        let _ = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email(&self.0)
                    .with_name("Application bootstrap"),
            )
            .await?;
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &better_auth_core::AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
#[expect(
    clippy::panic,
    reason = "negative controls require exact structured configuration failures"
)]
async fn admin_explicit_role_validation_rejects_before_application_bootstrap_and_preserves_implicit_defaults()
 {
    let config = AuthConfig::new("admin-role-contract-secret-at-least-32-characters");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
    let seeded = store
        .create_user(
            CreateUser::new()
                .with_email("existing-owner@roles.fixture.test")
                .with_name("Existing owner")
                .with_role("user"),
        )
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            token: None,
            active_team_id: None,
            user_id: seeded.id.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let session_before = better_auth_core::utils::json::to_value(&session).unwrap();
    let seeded_before = better_auth_core::utils::json::to_value(&seeded).unwrap();
    let custom = HashMap::from([(
        "manager".into(),
        RolePermissions::new().allow("user", ["get"]),
    )]);
    let cases = [
        ("omitted-empty", Some(HashMap::new()), None, None),
        (
            "explicit-empty",
            Some(HashMap::new()),
            Some(Vec::new()),
            None,
        ),
        (
            "invalid-empty",
            Some(HashMap::new()),
            Some(vec!["admin".into()]),
            Some("admin"),
        ),
        ("omitted-custom", Some(custom.clone()), None, None),
        (
            "valid-custom",
            Some(custom.clone()),
            Some(vec!["manager".into()]),
            None,
        ),
        (
            "case-custom",
            Some(custom.clone()),
            Some(vec!["MANAGER".into()]),
            None,
        ),
        (
            "space-custom",
            Some(custom),
            Some(vec![" manager".into()]),
            Some(" manager"),
        ),
        (
            "duplicate-missing",
            None,
            Some(vec!["foreign".into(), "missing".into(), "foreign".into()]),
            Some("foreign, missing, foreign"),
        ),
        ("case-builtins", None, Some(vec!["ADMIN".into()]), None),
    ];
    for (name, roles, admin_roles, invalid) in cases {
        let marker = format!("{name}@bootstrap.fixture.test");
        let result = AuthBuilder::<Schema>::new(config.clone())
            .store_arc(store.clone())
            .plugin(AdminPlugin::with_config(AdminConfig {
                roles,
                admin_roles,
                ..AdminConfig::default()
            }))
            .plugin(ApplicationBootstrap(marker.clone()))
            .build()
            .await;
        if let Some(invalid) = invalid {
            match result {
                Err(AuthError::Config(message)) => assert_eq!(
                    message,
                    format!(
                        "Invalid admin roles: {invalid}. Admin roles must be defined in the 'roles' configuration."
                    )
                ),
                Err(error) => panic!("{name}: wrong error {error}"),
                Ok(_) => panic!("{name}: invalid role configuration initialized"),
            }
            assert!(
                store.get_user_by_email(&marker).await.unwrap().is_none(),
                "invalid configuration must not run application bootstrap"
            );
        } else {
            let auth = result.unwrap();
            assert!(store.get_user_by_email(&marker).await.unwrap().is_some());
            let created = auth
                .store()
                .create_user(
                    CreateUser::new()
                        .with_email(format!("{name}@owner.roles.fixture.test"))
                        .with_name("Actual application owner"),
                )
                .await
                .unwrap();
            assert_eq!(created.role(), Some("user"));
            assert!(!created.banned());
            assert_eq!(
                auth.store()
                    .get_user_by_id(created.id().as_ref())
                    .await
                    .unwrap()
                    .unwrap()
                    .id(),
                created.id()
            );
        }
        assert_eq!(
            better_auth_core::utils::json::to_value(
                &store.get_session(&session.token).await.unwrap().unwrap()
            )
            .unwrap(),
            session_before
        );
        assert_eq!(
            better_auth_core::utils::json::to_value(
                &store.get_user_by_id(&seeded.id).await.unwrap().unwrap()
            )
            .unwrap(),
            seeded_before
        );
    }
}
