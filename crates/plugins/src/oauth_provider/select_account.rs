use alibi_core::AuthResult;
use async_trait::async_trait;
use std::sync::Arc;

pub type OAuthSelectAccountContext<'a> = super::OAuthInteractionContext<'a>;

/// Additional account selection on initial authorization only, after authentication.
#[async_trait]
pub trait OAuthSelectAccountPolicy: Send + Sync + std::fmt::Debug {
    async fn should_redirect(&self, input: OAuthSelectAccountContext<'_>) -> AuthResult<bool>;
}

#[derive(Debug, Clone)]
pub struct OAuthSelectAccountConfig {
    /// Policy redirects fall back to the legacy page, then the login page.
    /// Explicit `prompt=select_account` requires a nonempty selection page.
    pub page: Option<String>,
    pub should_redirect: Arc<dyn OAuthSelectAccountPolicy>,
}
