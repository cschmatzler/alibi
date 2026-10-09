#![cfg(test)]
//! Repository invariants: banned legacy symbols and README/crate consistency.
#![allow(
    clippy::pedantic,
    reason = "test code favors explicit, linear scenarios over pedantic style"
)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

mod architecture_guard;
mod public_docs_consistency;
