use crate::error::AuthResult;
use async_trait::async_trait;

/// Installs a bundled schema and records it in its migration ledger.
///
/// The `SeaORM` and `SQLx` adapters implement this over the same tables and
/// ledger, so either can migrate a database the other created. Applications
/// that own their auth tables run their own migrations instead.
#[async_trait]
pub trait SchemaMigrator: Send + Sync {
    /// Apply every pending migration; already applied migrations are skipped.
    ///
    /// # Errors
    ///
    /// Returns the database error. A failed migration is not recorded.
    async fn migrate(&self) -> AuthResult<()>;
}
