//! Response-shape checks against the upstream `OpenAPI` contract generated
//! from the pinned Better Auth package, run in-process against the Rust
//! router. They catch route, field-name and schema drift quickly; behavioral
//! parity is established by the differential SDK suite in `tests/compat`.

mod admin;
mod admin_stateful;
mod consistency;
mod endpoints;
mod field_names;
mod framework;
mod organization;
mod passkey;
mod reference_surface;
