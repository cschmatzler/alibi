//! `SeaORM` integration for Alibi.

extern crate self as alibi_seaorm;

mod conversions;

pub mod rate_limit;
pub use rate_limit::SeaOrmRateLimitStorage;

pub mod hooks;

pub mod json_metadata;

pub mod schema;

pub mod store;

pub mod additional_fields;

#[doc(hidden)]
pub use alibi_core as __private_core;
pub use alibi_seaorm_macros::AuthEntity;
pub use hooks::{
    DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, current_request_hook_context,
};
pub use json_metadata::JsonMetadata;
pub use schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use sea_orm;
pub use sea_orm::{Database, DatabaseConnection};
pub use store::SeaOrmStore;
