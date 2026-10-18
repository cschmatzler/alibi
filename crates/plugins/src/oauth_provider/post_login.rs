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

/// Consent authority selection after post-login interaction. No request headers
/// or client are supplied by the pinned callback contract.
pub struct OAuthConsentReferenceContext<'a> {
    pub user: &'a UserView,
    pub session: &'a SessionView,
    pub scopes: &'a [String],
}

#[async_trait]
pub trait OAuthConsentReference: Send + Sync + std::fmt::Debug {
    async fn consent_reference_id(
        &self,
        input: OAuthConsentReferenceContext<'_>,
    ) -> AuthResult<Option<String>>;
}

/// Application interaction after signup policy and before consent.
#[derive(Debug, Clone)]
pub struct OAuthPostLoginConfig {
    pub page: String,
    pub should_redirect: Arc<dyn OAuthPostLoginPolicy>,
    /// Select an additional consent partition within the authenticated user's
    /// grants. `None` or an empty returned string omits the reference filter;
    /// neither changes user ownership of consent-management operations.
    pub consent_reference_id: Option<Arc<dyn OAuthConsentReference>>,
}

impl super::OAuthProviderPlugin {
    pub(super) async fn consent_reference_id(
        &self,
        user: &UserView,
        session: &SessionView,
        scopes: &[String],
    ) -> AuthResult<Option<String>> {
        let Some(reference) = self
            .config
            .post_login
            .as_ref()
            .and_then(|config| config.consent_reference_id.as_ref())
        else {
            return Ok(None);
        };
        reference
            .consent_reference_id(OAuthConsentReferenceContext {
                user,
                session,
                scopes,
            })
            .await
            .map_err(|error| {
                if alibi_core::endpoint::is_endpoint_api_error(&error) {
                    error
                } else {
                    alibi_core::AuthError::CallbackFailure(Box::new(error))
                }
            })
    }
}
