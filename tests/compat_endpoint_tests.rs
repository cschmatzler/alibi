#![cfg(test)]
//! Endpoint validation smoke tests for selected schema-covered endpoints.
//!
//! These tests exercise each API endpoint and validate responses against the
//! `OpenAPI` spec schema.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "endpoint smoke tests intentionally use direct JSON assertions against the generated spec"
)]

mod compat;

#[cfg(test)]
#[path = "compat_endpoint_tests/tests.rs"]
mod tests;

use std::collections::HashSet;

use better_auth::prelude::CreateAccount;

use compat::helpers::*;

use compat::schema::extract_success_schema;

use compat::shapes::check_camel_case_fields;

use compat::validation::{DiffKind, ShapeDiff, json_type_name};

use compat::validator::{EndpointResult, SpecValidator};
