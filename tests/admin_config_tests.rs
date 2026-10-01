#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Rust build-time admin configuration validation follows the pinned factory.

#[cfg(test)]
#[path = "admin_config_tests/tests.rs"]
mod tests;

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
        drop(
            ctx.database
                .create_user(
                    CreateUser::new()
                        .with_email(&self.0)
                        .with_name("Application bootstrap"),
                )
                .await?,
        );
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

struct StoredUserMessage;

#[async_trait]
impl better_auth::plugins::AdminBannedUserMessage<better_auth_seaorm::store::entities::user::Model>
    for StoredUserMessage
{
    async fn message(
        &self,
        user: &better_auth_seaorm::store::entities::user::Model,
    ) -> AuthResult<String> {
        Ok(user.ban_reason().unwrap_or_default().to_owned())
    }
}

struct ProjectedUserMessage;

#[async_trait]
impl better_auth::plugins::AdminBannedUserMessage<better_auth_core::wire::UserView>
    for ProjectedUserMessage
{
    async fn message(&self, _user: &better_auth_core::wire::UserView) -> AuthResult<String> {
        Ok("projected callback must not initialize".into())
    }
}
