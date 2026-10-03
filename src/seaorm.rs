//! `SeaORM` integration re-exports, gated behind the `seaorm2` feature.

pub use better_auth_seaorm::json_metadata;
pub use better_auth_seaorm::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use better_auth_seaorm::session_fields;
pub use better_auth_seaorm::{
    AuthEntity, Database, DatabaseConnection, DatabaseHooks, HookControl, JsonMetadata, SeaOrm,
    SeaOrmHookContext, SeaOrmHooks, SeaOrmRateLimitStorage, SeaOrmStore,
    current_request_hook_context, sea_orm,
};
