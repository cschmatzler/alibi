use alibi_core::{AuthResult, SessionView, UserView};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

/// Authenticated input to the application's additional registration decision.
/// Headers come from the physical authorization request, not logical API headers.
pub struct OAuthSignupContext<'a> {
    pub headers: &'a HashMap<String, String>,
    pub user: &'a UserView,
    pub session: &'a SessionView,
    pub scopes: &'a [String],
}

/// Better Auth's boolean-or-string signup decision. An empty page string, like
/// `false`, continues authorization; `true` uses the configured page fallback.
#[derive(Debug, Clone)]
pub enum OAuthSignupRedirect {
    Continue,
    ConfiguredPage,
    Page(String),
}

#[async_trait]
pub trait OAuthSignupPolicy: Send + Sync + std::fmt::Debug {
    async fn should_redirect(
        &self,
        input: OAuthSignupContext<'_>,
    ) -> AuthResult<OAuthSignupRedirect>;
}

#[derive(Debug, Clone, Default)]
pub struct OAuthSignupConfig {
    pub page: Option<String>,
    pub should_redirect: Option<Arc<dyn OAuthSignupPolicy>>,
}
