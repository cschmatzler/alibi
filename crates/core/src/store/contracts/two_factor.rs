use crate::{AuthError, AuthResult, CreateTwoFactor, TwoFactor, UpdateTwoFactor};
use async_trait::async_trait;
#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>>;
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
    async fn update_two_factor(
        &self,
        _id: &str,
        _update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Exact factor updates are not supported by this store",
        ))
    }
    /// Atomically increment the stored counter, returning the winning row.
    /// SQL-backed adapters preserve NULL, matching the pinned Kysely adapter.
    async fn increment_two_factor_failure(&self, _id: &str) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Atomic factor failure increments are not supported by this store",
        ))
    }
    async fn set_two_factor_lock_if_count_at_least(
        &self,
        _id: &str,
        _threshold: f64,
        _until: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Conditional factor locking is not supported by this store",
        ))
    }
    async fn clear_expired_two_factor_lock(
        &self,
        _id: &str,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Conditional factor unlocking is not supported by this store",
        ))
    }
    async fn reset_two_factor_failures(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Factor failure reset is not supported by this store",
        ))
    }
    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        _id: &str,
        _expected: &str,
        _replacement: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::not_implemented(
            "Atomic factor backup consumption is not supported by this store",
        ))
    }
}
