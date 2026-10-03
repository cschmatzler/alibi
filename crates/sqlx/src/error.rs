//! Map `SQLx` failures to auth errors.

use better_auth_core::error::{AuthError, DatabaseError};

/// Classify unique and foreign-key violations; everything else is a query error.
///
/// SQLite reports unique violations as extended codes 1555/2067 and foreign-key
/// violations as 787; PostgreSQL uses SQLSTATE 23505/23503.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
pub(crate) fn map_sqlx_err(error: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(database) = &error {
        let code = database.code().unwrap_or_default();
        let constraint = if database
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .is_some()
        {
            matches!(code.as_ref(), "23505" | "23503")
        } else if database
            .try_downcast_ref::<sqlx::sqlite::SqliteError>()
            .is_some()
        {
            matches!(code.as_ref(), "1555" | "2067" | "787")
        } else {
            false
        };
        if constraint {
            return AuthError::Database(DatabaseError::Constraint(database.message().to_owned()));
        }
    }
    AuthError::Database(DatabaseError::Query(error.to_string()))
}

/// A model write matched no row.
pub(crate) fn record_not_updated() -> AuthError {
    AuthError::Database(DatabaseError::Query(
        "None of the records are updated".to_owned(),
    ))
}

/// A row-returning insert produced no row.
pub(crate) fn record_not_inserted() -> AuthError {
    AuthError::Database(DatabaseError::Query(
        "None of the records are inserted".to_owned(),
    ))
}

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}
