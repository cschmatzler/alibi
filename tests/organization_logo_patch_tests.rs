#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! The public storage patch distinguishes omission, SQL NULL, and an empty string.

#[cfg(test)]
#[path = "organization_logo_patch_tests/tests.rs"]
mod tests;

use better_auth::AuthConfig;
use better_auth_core::store::OrganizationStore;
use better_auth_core::{CreateOrganization, UpdateOrganization};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
