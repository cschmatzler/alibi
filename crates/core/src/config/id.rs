//! Policies for identifiers assigned by database adapters.
use crate::{AuthError, AuthResult};
use std::sync::Arc;

/// A callback returning `None` rejects creation rather than generating a fallback.
pub trait DatabaseIdGenerator: Send + Sync {
    fn generate(&self, model: &str, size: Option<usize>) -> AuthResult<Option<String>>;
}
impl<F> DatabaseIdGenerator for F
where
    F: Fn(&str, Option<usize>) -> AuthResult<Option<String>> + Send + Sync,
{
    fn generate(&self, model: &str, size: Option<usize>) -> AuthResult<Option<String>> {
        self(model, size)
    }
}

#[derive(Clone)]
pub enum DatabaseIdStrategy {
    Uuid,
    Serial,
    Custom(Arc<dyn DatabaseIdGenerator>),
}
impl std::fmt::Debug for DatabaseIdStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Uuid => "Uuid",
            Self::Serial => "Serial",
            Self::Custom(_) => "Custom(..)",
        })
    }
}
impl super::AdvancedDatabaseConfig {
    #[must_use]
    pub fn serial_ids(&self) -> bool {
        matches!(self.generate_id, Some(DatabaseIdStrategy::Serial))
            || (self.generate_id.is_none() && self.use_number_id)
    }
    /// `None` leaves generation to the model or the database's serial allocator.
    pub fn generated_id(&self, model: &str) -> AuthResult<Option<String>> {
        match &self.generate_id {
            Some(DatabaseIdStrategy::Uuid) => Ok(Some(uuid::Uuid::new_v4().to_string())),
            Some(DatabaseIdStrategy::Custom(generator)) => generator
                .generate(model, None)
                .map_err(crate::store::adapter::callback_error)?
                .map(Some)
                .ok_or_else(|| {
                    AuthError::CallbackFailure(Box::new(AuthError::internal(
                        "Application ID generator returned no identifier",
                    )))
                }),
            _ => Ok(None),
        }
    }
}

/// Statements for a persistent atomic per-model sequence, also usable with text IDs.
/// Allocation must run on the same connection/transaction as the record creation.
#[doc(hidden)]
pub fn serial_id_statements(table: &str, column: &str, postgres: bool) -> [String; 2] {
    let quote = |value: &str| format!("\"{}\"", value.replace('"', "\"\""));
    let table_sql = quote(table);
    let column_sql = quote(column);
    let key = format!("'{table}'", table = table.replace('\'', "''"));
    let numeric = if postgres {
        format!(" WHERE CAST({column_sql} AS TEXT) ~ '^[0-9]+$'")
    } else {
        " WHERE 1 = 1".into()
    };
    let next = if postgres {
        "GREATEST(alibi_id_sequences.value + 1, EXCLUDED.value)"
    } else {
        "MAX(alibi_id_sequences.value + 1, EXCLUDED.value)"
    };
    [
        "CREATE TABLE IF NOT EXISTS alibi_id_sequences (model TEXT PRIMARY KEY, value BIGINT NOT NULL)".into(),
        format!("INSERT INTO alibi_id_sequences (model, value) SELECT {key}, COALESCE(MAX(CAST(CAST({column_sql} AS TEXT) AS BIGINT)), 0) + 1 FROM {table_sql}{numeric} ON CONFLICT (model) DO UPDATE SET value = {next} RETURNING value"),
    ]
}
