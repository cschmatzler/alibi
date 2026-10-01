//! Preserve numeric pagination until the actual database validates its binding.
use crate::error::AuthResult;
use sea_orm::{DbBackend, Statement, Value, Values};
pub(super) fn bind_page(
    mut statement: Statement,
    limit: Option<f64>,
    offset: Option<f64>,
) -> AuthResult<Statement> {
    for (clause, number) in [("LIMIT", limit), ("OFFSET", offset)] {
        if let Some(number) = number {
            let values = statement.values.get_or_insert_with(|| Values(Vec::new()));
            let placeholder = match statement.db_backend {
                DbBackend::Postgres => format!("${}", values.0.len() + 1),
                DbBackend::Sqlite | DbBackend::MySql => "?".into(),
                _ => {
                    return Err(crate::error::AuthError::not_implemented(
                        "Raw numeric pages are not supported by this database backend",
                    ));
                }
            };
            statement.sql.push_str(&format!(" {clause} {placeholder}"));
            values.0.push(Value::Double(Some(number)));
        }
    }
    Ok(statement)
}
