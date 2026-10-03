//! `SQLx` integration re-exports, gated behind the default `sqlx` feature.

pub use better_auth_sqlx::schema::{
    SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
pub use better_auth_sqlx::session_fields;
pub use better_auth_sqlx::{
    ActiveRow, ActiveValue, AuthEntity, ColumnDef, ColumnKind, DatabaseHooks, HookControl,
    JsonMetadata, SqlValue, Sqlx, SqlxBackend, SqlxHookContext, SqlxHooks, SqlxModel, SqlxPool,
    SqlxRateLimitStorage, SqlxRow, SqlxStore, SqlxTransaction, SqlxTransactionGuard, SqlxValue,
    current_request_hook_context, sqlx,
};
pub use better_auth_sqlx::{json_metadata, model, pool, value};
