#![cfg(test)]
//! Repository invariants: banned legacy symbols and README/crate consistency.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

mod architecture_guard;
mod public_docs_consistency;
