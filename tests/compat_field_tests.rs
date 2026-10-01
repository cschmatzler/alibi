#![cfg(test)]
//! Field-level smoke tests for camelCase enforcement and representative type signatures.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "field-level compatibility tests use direct JSON indexing for concise response shape assertions"
)]

mod compat;

#[cfg(test)]
#[path = "compat_field_tests/tests.rs"]
mod tests;

use better_auth::prelude::CreateAccount;

use compat::helpers::*;

use compat::shapes::{check_camel_case_fields, extract_type_signature};
