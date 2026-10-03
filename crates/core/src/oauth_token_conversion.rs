//! Physical, operator-controlled OAuth token replacement; never a runtime upgrade.

use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;

/// Exact physical values reviewed in a trusted ownership manifest.
///
/// Ciphertext authentication does **not** prove historical ownership. Operators
/// must establish that separately before constructing this snapshot. Do not log
/// snapshots: they may contain plaintext credentials.
#[derive(Clone)]
pub struct OAuthTokenSnapshot {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub account_id: String,
    pub tokens: OAuthTokenValues,
}

/// Nullable physical access, refresh and ID token columns. Deliberately not Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokenValues {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

/// Administrative storage capability, separate from live account operations.
/// Use a physical adapter, without output transforms or account-update hooks.
#[async_trait]
pub trait OAuthTokenConversionStore<S: AuthSchema>: Send + Sync {
    /// Replace all three token columns in one atomic statement only if the row
    /// identity, owner and every nullable token equal `observed` exactly.
    /// Return false for a missing/changed row; leave all other columns untouched.
    ///
    /// # Errors
    /// Returns a storage error without committing a partial token replacement.
    async fn compare_and_swap_oauth_tokens(
        &self,
        observed: &OAuthTokenSnapshot,
        replacement: &OAuthTokenValues,
    ) -> AuthResult<bool>;
}
