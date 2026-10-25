use alibi_core::{AuthResult, SessionView, UserView};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

/// Authenticated post-login policy input. The pinned callback does not receive
/// a client argument; admission has already validated the requesting client.
pub struct OAuthInteractionContext<'a> {
    pub headers: &'a HashMap<String, String>,
    pub user: &'a UserView,
    pub session: &'a SessionView,
    pub scopes: &'a [String],
}

/// Post-login policy input: the interaction context plus whether the user is
/// returning from the post-login page.
pub struct OAuthPostLoginContext<'a> {
    pub headers: &'a HashMap<String, String>,
    pub user: &'a UserView,
    pub session: &'a SessionView,
    pub scopes: &'a [String],
    /// `true` when the user returns from the post-login page through
    /// `/oauth2/continue`. The client chooses to send that request, so it does
    /// not prove a selection was made: validate the session before returning
    /// `false`.
    pub is_continuation: bool,
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
    /// grants. Consent is stored per reference; `None` or an empty returned
    /// string uses consent given without one. Neither changes user ownership of
    /// consent-management operations.
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
            .map(|reference| reference.filter(|reference| !reference.is_empty()))
            .map_err(|error| {
                if alibi_core::endpoint::is_endpoint_api_error(&error) {
                    error
                } else {
                    alibi_core::AuthError::CallbackFailure(Box::new(error))
                }
            })
    }
}
/// Whether stored consent belongs to exactly this reference. Without one, only
/// consent stored without a reference (missing, null or empty) matches.
pub(super) fn consent_matches_reference(metadata: &serde_json::Value, reference: Option<&str>) -> bool {
    let stored = metadata
        .get("referenceId")
        .and_then(serde_json::Value::as_str)
        .filter(|stored| !stored.is_empty());
    stored == reference
}
