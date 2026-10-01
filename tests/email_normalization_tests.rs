#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "email normalization tests intentionally use panic-on-failure assertions and direct JSON indexing for concise behavior checks"
)]

mod compat;

#[cfg(test)]
#[path = "email_normalization_tests/tests.rs"]
mod tests;

use better_auth::prelude::{CreateUser, UpdateUser};
use compat::helpers::*;
use serde_json::json;
