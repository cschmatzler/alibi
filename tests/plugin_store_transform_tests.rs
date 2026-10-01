#![cfg(test)]
//! Plugin adapter transforms affect every trusted facade and real transactions.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "plugin_store_transform_tests/tests.rs"]
mod tests;

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
