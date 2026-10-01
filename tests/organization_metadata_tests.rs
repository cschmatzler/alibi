#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! The differential identity harness cannot represent a deliberately blank ID.
//! Preserve that pinned-runtime request contract at the real SQL-backed handler.

#[cfg(test)]
#[path = "organization_metadata_tests/tests.rs"]
mod tests;

use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthRequest, AuthSession, HttpMethod};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
