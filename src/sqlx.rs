//! `SQLx` integration re-exports, gated behind the default `sqlx` feature or
//! one of its engines, `sqlx-sqlite` and `sqlx-postgres`.

pub use alibi_sqlx::additional_fields;
pub use alibi_sqlx::schema::{
    SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
pub use alibi_sqlx::{
    ActiveRow, ActiveValue, AuthEntity, ColumnDef, ColumnKind, DatabaseHooks, Engine, HookControl,
    JsonMetadata, OrganizationModels, SqlValue, SqlxBackend, SqlxHookContext, SqlxModel, SqlxPool,
    SqlxRateLimitStorage, SqlxRow, SqlxStore, SqlxTransaction, SqlxTransactionGuard, SqlxValue,
    current_request_hook_context, sqlx,
};
pub use alibi_sqlx::{json_metadata, model, organization_models, pool, value};
