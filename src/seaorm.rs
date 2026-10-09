//! `SeaORM` integration re-exports, gated behind the `seaorm` feature.

pub use alibi_seaorm::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use alibi_seaorm::*;
