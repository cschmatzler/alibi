//! `SQLx` integration re-exports, gated behind the default `sqlx` feature or
//! one of its engines, `sqlx-sqlite` and `sqlx-postgres`.

pub use alibi_sqlx::schema::{
    SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
pub use alibi_sqlx::*;
