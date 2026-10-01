#![cfg(test)]
//! Organization plugin endpoint validation tests.
//!
//! Tests the full Organization lifecycle: create, update, delete, members,
//! invitations, and permissions against the `OpenAPI` spec.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "organization compatibility tests intentionally use direct JSON assertions over generated fixtures"
)]

#[path = "support/compat/mod.rs"]
mod compat;

#[cfg(test)]
#[path = "compat_organization_tests/tests.rs"]
mod tests;

use compat::helpers::*;
use compat::schema::OpenApiProfile;
use compat::shapes::check_camel_case_fields;
use compat::validator::SpecValidator;
use std::collections::HashSet;
