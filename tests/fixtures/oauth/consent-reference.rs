use alibi::plugins::{
    OAuthConsentReference, OAuthConsentReferenceContext, OAuthPostLoginContext,
    OAuthPostLoginPolicy,
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Mutex};

/// Application selections keyed by genuine authenticated session IDs.
#[derive(Debug, Default)]
pub(super) struct ConsentReferencePolicy {
    pub references: Mutex<HashMap<String, String>>,
    pub reference_calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthPostLoginPolicy for ConsentReferencePolicy {
    async fn should_redirect(&self, _: OAuthPostLoginContext<'_>) -> alibi::AuthResult<bool> {
        Ok(false)
    }
}

#[async_trait::async_trait]
impl OAuthConsentReference for ConsentReferencePolicy {
    async fn consent_reference_id(
        &self,
        input: OAuthConsentReferenceContext<'_>,
    ) -> alibi::AuthResult<Option<String>> {
        self.reference_calls.lock().unwrap().push(json!({
            "user":{"id":input.user.id,"email":input.user.email,"name":input.user.name},
            "session":{"id":input.session.id,"userId":input.session.user_id,"token":input.session.token},
            "scopes":input.scopes,
        }));
        let selected = self
            .references
            .lock()
            .unwrap()
            .get(&input.session.id)
            .cloned();
        match selected.as_deref() {
            Some("ordinary-error") => Err(alibi::AuthError::internal("consent reference failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden("Consent reference denied")),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("CONSENT_REFERENCE_DENIED".into()),
                message: "Consent reference denied".into(),
            }),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "CONSENT_REFERENCE_UNAVAILABLE",
                message: "Consent reference unavailable",
            }),
            _ => Ok(selected),
        }
    }
}
