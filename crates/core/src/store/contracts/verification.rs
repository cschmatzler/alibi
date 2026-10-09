use super::*;
#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
    /// Create through before hooks, optional physical persistence, secondary
    /// publication, then after hooks. Unsupported adapters must fail closed.
    async fn create_verification_record(
        &self,
        _data: VerificationCreation,
        _publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        Err(AuthError::NotImplemented(
            "Verification publication phases are not supported by this store".into(),
        ))
    }
    /// Atomically remove the newest generation and all siblings, returning the
    /// actual winning snapshot even when expired. This keeps legacy fallback
    /// from resurrecting an older logical generation.
    async fn consume_verification_snapshot(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::NotImplemented(
            "Raw atomic verification consumption is not supported by this store".into(),
        ))
    }
    /// Update every physical match, with one actual adapter result snapshot.
    async fn update_verification_by_identifier(
        &self,
        _identifier: &str,
        _data: crate::UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        Err(AuthError::NotImplemented(
            "Verification identifier updates are not supported by this store".into(),
        ))
    }
    /// Reserve by the original logical identifier while storing its configured
    /// transformed identifier. Return the actual newly inserted model only.
    async fn reserve_verification_record(
        &self,
        _logical_identifier: &str,
        _data: CreateVerification,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::NotImplemented(
            "Configured verification reservation is not supported by this store".into(),
        ))
    }
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    /// Fetch the newest generation, including expired records. The caller
    /// decides whether cleanup and a distinct expiry error are required.
    async fn get_latest_verification_by_identifier(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::internal(
            "raw verification lookup is not supported by this store",
        ))
    }
    /// Atomically invalidate an identifier and return its newest generation.
    /// Exactly one concurrent caller can receive a row. Expired records are
    /// removed along with every sibling and return `None`.
    async fn consume_verification_by_identifier(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::internal(
            "atomic verification consumption is not supported by this store",
        ))
    }
    async fn delete_verifications_by_identifier(&self, _identifier: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "verification invalidation is not supported by this store",
        ))
    }
    /// Update a generation only when its value still matches the snapshot.
    async fn compare_and_swap_verification(
        &self,
        _id: &str,
        _expected_value: &str,
        _value: &str,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "atomic verification updates are not supported by this store",
        ))
    }
    /// Insert a deterministic reservation exactly once. An expired marker
    /// remains reserved until it is cleaned up or explicitly consumed.
    async fn reserve_verification(&self, _verification: CreateVerification) -> AuthResult<bool> {
        Err(AuthError::internal(
            "verification reservation is not supported by this store",
        ))
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// Upstream's deterministic database key for first-writer verification claims.
#[must_use]
pub fn verification_reservation_key(identifier: &str) -> (String, [u8; 32]) {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"reserve:");
    hash.update(identifier.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        digest,
    )
}
