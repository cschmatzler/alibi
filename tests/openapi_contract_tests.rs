#![cfg(test)]
//! Response-shape checks against the upstream `OpenAPI` contract generated
//! from the pinned Better Auth package, run in-process against the Rust
//! router. They catch route, field-name and schema drift quickly; behavioral
//! parity is established by the differential SDK suite in `tests/compat`.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[path = "support/openapi_contract/mod.rs"]
mod contract;

#[path = "openapi_contract/admin.rs"]
mod admin;
#[path = "openapi_contract/admin_stateful.rs"]
mod admin_stateful;
#[path = "openapi_contract/consistency.rs"]
mod consistency;
#[path = "openapi_contract/endpoints.rs"]
mod endpoints;
#[path = "openapi_contract/field_names.rs"]
mod field_names;
#[path = "openapi_contract/framework.rs"]
mod framework;
#[path = "openapi_contract/organization.rs"]
mod organization;
#[path = "openapi_contract/passkey.rs"]
mod passkey;
#[path = "openapi_contract/reference_surface.rs"]
mod reference_surface;
