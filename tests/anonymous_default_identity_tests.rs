//! The random default has a public native shape contract, not a nonce exemption.
#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library and integration targets"
)]
#![allow(clippy::unwrap_used, reason = "native lifecycle setup must succeed")]
#[cfg(test)]
#[path = "anonymous_default_identity_tests/tests.rs"]
mod tests;

use better_auth::plugins::AnonymousPlugin;

use better_auth::plugins::anonymous::AnonymousConfig;

use better_auth::{AuthBuilder, AuthConfig};

use better_auth_core::{AuthRequest, AuthSession, AuthUser, HttpMethod};

use better_auth_seaorm::{Database, SeaOrmStore};

use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
