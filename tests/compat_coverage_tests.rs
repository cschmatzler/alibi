#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Enforced runtime route inventory. Behavioral evidence is checked by the Bun suite.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test fixture validation fails immediately"
)]
mod compat;

#[cfg(test)]
#[path = "compat_coverage_tests/tests.rs"]
mod tests;

use compat::helpers::{TestAuthOptions, create_test_auth_with_options};
use serde_json::Value;
use std::collections::BTreeSet;

fn canonical(path: &str) -> String {
    path.split('/')
        .map(|part| {
            if part.starts_with(':') || part.starts_with('{') {
                "{}"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
