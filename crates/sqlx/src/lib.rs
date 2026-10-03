//! `SQLx` integration for Better Auth.
//!
//! [`SqlxStore`] persists every auth table through an application's own
//! SQLite or PostgreSQL pool. Application-owned models derive
//! `sqlx::FromRow` and [`AuthEntity`].

#![expect(
    unused_results,
    reason = "SQL statements are built by chaining `&mut Sql` builder calls"
)]

extern crate self as better_auth_sqlx;

mod error;

pub mod hooks;

pub mod json_metadata;

pub mod model;

pub mod pool;

pub mod rate_limit;

pub mod schema;

pub mod session_fields;

mod sql;

pub mod store;

pub mod value;

#[doc(hidden)]
pub use better_auth_core as __private_core;
pub use better_auth_sqlx_macros::AuthEntity;
pub use hooks::{
    DatabaseHooks, HookControl, Sqlx, SqlxHookContext, SqlxHooks, current_request_hook_context,
};
pub use json_metadata::JsonMetadata;
pub use model::{ActiveRow, ActiveValue, ColumnDef, SqlxModel};
pub use pool::{SqlxBackend, SqlxPool, SqlxRow, SqlxTransaction, SqlxTransactionGuard};
pub use rate_limit::SqlxRateLimitStorage;
pub use schema::{SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel};
pub use sqlx;
pub use store::SqlxStore;
pub use value::{ColumnKind, SqlValue, SqlxValue};
