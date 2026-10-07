//! `SeaORM` integration re-exports, gated behind the `seaorm` feature.

pub use alibi_seaorm::additional_fields;
pub use alibi_seaorm::json_metadata;
pub use alibi_seaorm::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use alibi_seaorm::{
    AuthEntity, Database, DatabaseConnection, DatabaseHooks, HookControl, JsonMetadata,
    SeaOrmBackend, SeaOrmHookContext, SeaOrmRateLimitStorage, SeaOrmStore,
    current_request_hook_context, sea_orm,
};
