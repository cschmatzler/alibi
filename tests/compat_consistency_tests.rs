#![cfg(test)]
//! Cross-endpoint consistency tests — verify user/session objects are
//! structurally identical across different API responses.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "consistency tests use direct JSON indexing to compare response object shapes"
)]

#[path = "support/compat/mod.rs"]
mod compat;

#[cfg(test)]
#[path = "compat_consistency_tests/tests.rs"]
mod tests;

use compat::helpers::*;
use compat::shapes::compare_shapes;
