#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Direct server API callers retain typed real storage/application failures.
#![expect(
    clippy::panic_in_result_fn,
    reason = "the actual failing public helper operations must return errors"
)]
#[cfg(test)]
#[path = "organization_member_addition_tests/tests.rs"]
mod tests;

use async_trait::async_trait;

use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationMemberAddedContext, OrganizationMemberAdditionHooks,
    OrganizationPlugin,
    types::{AddOrganizationMemberRequest, RoleInput},
};

use better_auth::{AuthConfig, AuthError, AuthResult};

use better_auth_core::{
    AuthContext, CreateOrganization, CreateUser,
    store::{MemberStore, OrganizationStore, UserStore},
};

use better_auth_seaorm::{
    Database, SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};

use std::{collections::HashMap, sync::Arc};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug)]
struct RejectAfter;

#[async_trait]
impl OrganizationMemberAdditionHooks for RejectAfter {
    async fn after_add_member(&self, _: &OrganizationMemberAddedContext) -> AuthResult<()> {
        Err(AuthError::Api {
            status: 500,
            code: Some("APPLICATION_AFTER_ERROR".into()),
            message: "Explicit application after error".into(),
        })
    }
}
