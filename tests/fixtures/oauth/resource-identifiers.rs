//! Application-owned asynchronous seed validation, shared by native and paired owners.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub(super) struct Identifiers {
    pub calls: AtomicUsize,
    pub fail_next: AtomicBool,
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthResourceIdentifierValidator for Identifiers {
    async fn validate(&self, identifier: &str) -> alibi::AuthResult<bool> {
        _ = self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(alibi::AuthError::Forbidden(
                "Resource validation denied".into(),
            ));
        }
        Ok(identifier == "local-resource")
    }
}
