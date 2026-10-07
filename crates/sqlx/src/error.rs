//! Map `SQLx` failures to auth errors.

use alibi_core::error::{AuthError, DatabaseError};

/// Unique and foreign-key violations become constraint errors; everything
/// else is a query error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
pub(crate) fn map_sqlx_err(error: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(database) = &error
        && (database.is_unique_violation() || database.is_foreign_key_violation())
    {
        return AuthError::Database(DatabaseError::Constraint(database.message().to_owned()));
    }
    AuthError::Database(DatabaseError::Query(error.to_string()))
}

/// A model update matched no row.
pub(crate) fn record_not_updated() -> AuthError {
    AuthError::Database(DatabaseError::Query("the update matched no row".to_owned()))
}

/// A row-returning insert produced no row.
pub(crate) fn record_not_inserted() -> AuthError {
    AuthError::Database(DatabaseError::Query(
        "the insert returned no row".to_owned(),
    ))
}
