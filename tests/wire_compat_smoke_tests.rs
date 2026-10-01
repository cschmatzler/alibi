#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "wire smoke tests use direct JSON indexing for concise transport assertions"
)]

mod compat;

#[cfg(test)]
#[path = "wire_compat_smoke_tests/tests.rs"]
mod tests;

use compat::dual_server::*;
use compat::helpers::*;
