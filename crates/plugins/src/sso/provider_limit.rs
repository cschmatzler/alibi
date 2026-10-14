//! Application policies for per-user SSO registration limits.
use alibi_core::{AuthResult, wire::UserView};
use std::sync::Arc;

#[async_trait::async_trait]
pub trait SsoProviderLimitResolver: Send + Sync {
    /// Return a JavaScript-compatible numeric limit; zero disables registration.
    async fn limit(&self, user: UserView) -> AuthResult<f64>;
}

#[derive(Clone)]
pub struct SsoProviderLimit(pub Arc<dyn SsoProviderLimitResolver>);
impl std::fmt::Debug for SsoProviderLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoProviderLimit")
            .finish_non_exhaustive()
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "the reference compares collection length as a JavaScript number"
)]
pub(super) fn reached(count: usize, limit: f64) -> bool {
    count as f64 >= limit
}
