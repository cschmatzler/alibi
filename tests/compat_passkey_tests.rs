#![cfg(test)]
//! Passkey plugin endpoint validation tests.
//!
//! Tests passkey registration, authentication, and management endpoints
//! against the `OpenAPI` spec. Note: `WebAuthn` flows require browser interaction,
//! so we validate response shapes for the options-generation endpoints and
//! error shapes for verification endpoints (which need real attestation data).
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "passkey contract tests use direct JSON indexing for concise response assertions"
)]

mod compat;

#[cfg(test)]
#[path = "compat_passkey_tests/tests.rs"]
mod tests;

use compat::helpers::*;
use compat::schema::OpenApiProfile;
use compat::validator::SpecValidator;
