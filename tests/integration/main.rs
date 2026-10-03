#![cfg(test)]
//! Integration tests: the Rust implementation exercised through its public
//! builder, router, stores and framework integrations, on its own terms.
//!
//! Modules mirror the SDK scenario tree under `tests/compat/client-tests/tests`:
//! `core/<area>` for upstream's core API and `plugins/<plugin>` per plugin.
//! Parity with upstream is established by the `compat` target, not here.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[path = "../support/openapi_contract/mod.rs"]
mod contract;

#[cfg(feature = "axum")]
mod axum_integration;
mod core;
mod plugins;
mod storage;

#[cfg(feature = "poem")]
mod poem_integration;
