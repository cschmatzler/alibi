#![cfg(test)]
//! Plugin adapter transforms affect every trusted facade and real transactions.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "plugin_store_transform_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::store::{AccountStore, AdapterAfterHook, AdapterEvent, AuthStore};
use better_auth_core::{AuthAccount, CreateAccount};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthUser, CreateUser, UpdateUser,
    store::{UserStore, transaction},
};
use better_auth_seaorm::{Database, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
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
