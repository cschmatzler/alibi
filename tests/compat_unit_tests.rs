#![cfg(test)]
//! Unit tests for the compatibility framework's internal logic.
//!
//! These are pure (non-async) tests that verify shape comparison, camelCase
//! detection, type-signature extraction, and schema resolution without
//! spinning up an auth instance.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests intentionally use panic-on-failure assertions and direct indexing for compact fixture checks"
)]

mod compat;

#[cfg(test)]
#[path = "compat_unit_tests/tests.rs"]
mod tests;

use compat::schema::{
    OpenApiProfile, extract_success_schema, load_openapi_spec, load_openapi_spec_with_profile,
    resolve_object_schema,
};

use compat::shapes::{check_camel_case_fields, compare_shapes, extract_type_signature};
