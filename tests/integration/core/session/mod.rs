/// The application-owned session schema the Rust fixture server also serves.
#[cfg(feature = "seaorm2")]
#[path = "../../../compat/rust-server/src/session_field_model.rs"]
mod application_model;

#[cfg(feature = "seaorm2")]
mod cookie_cache;
#[cfg(feature = "seaorm2")]
mod fields;
mod policy_error;
mod refresh;
