#![cfg(test)]
//! Compatibility tests against the pinned upstream `better-auth` release.
//!
//! - `sdk`: starts the TypeScript reference server and the Rust fixture server
//!   and runs the official-client differential suite in `client-tests/`
//!   against both. This is the parity gate; every scenario compares both runtimes.
//! - `route_inventory`: the Rust router's routes must equal `capabilities.json`.
//! - `upstream_pin`: every manifest, lockfile and fixture names one release.
//! - `openapi_contract`: in-process response shapes against upstream's
//!   generated `OpenAPI` document; fast drift detection, not parity.
#![allow(
    clippy::pedantic,
    reason = "test code favors explicit, linear scenarios over pedantic style"
)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[path = "../support/openapi_contract/mod.rs"]
mod contract;

mod openapi_contract;
mod route_inventory;
mod sdk;
mod upstream_pin;
