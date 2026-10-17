use alibi_core::{AuthResult, SessionView, UserView};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

/// Authenticated post-login policy input. The pinned callback does not receive
/// a client argument; admission has already validated the requesting client.
pub struct OAuthPostLoginContext<'a> {
    pub headers: &'a HashMap<String, String>,
    pub user: &'a UserView,
    pub session: &'a SessionView,
    pub scopes: &'a [String],
}

#[async_trait]
pub trait OAuthPostLoginPolicy: Send + Sync + std::fmt::Debug {
    async fn should_redirect(&self, input: OAuthPostLoginContext<'_>) -> AuthResult<bool>;
}

/// Application interaction after signup policy and before consent.
#[derive(Debug, Clone)]
pub struct OAuthPostLoginConfig {
    pub page: String,
    pub should_redirect: Arc<dyn OAuthPostLoginPolicy>,
}
