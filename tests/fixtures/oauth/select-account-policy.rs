use alibi::plugins::{
    OAuthPostLoginContext, OAuthPostLoginPolicy, OAuthSelectAccountContext,
    OAuthSelectAccountPolicy, OAuthSignupContext, OAuthSignupPolicy, OAuthSignupRedirect,
};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct SelectAccountPolicy {
    pub calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthSelectAccountPolicy for SelectAccountPolicy {
    async fn should_redirect(
        &self,
        input: OAuthSelectAccountContext<'_>,
    ) -> alibi::AuthResult<bool> {
        let decision = input
            .headers
            .get("x-selection-decision")
            .map(String::as_str);
        self.calls.lock().unwrap().push(json!({
            "stage":"selectAccount", "caller":input.headers.get("x-policy-caller"), "decision":decision,
            "user":{"id":input.user.id,"email":input.user.email,"name":input.user.name},
            "session":{"id":input.session.id,"userId":input.session.user_id,"token":input.session.token},
            "scopes":input.scopes,
        }));
        match decision {
            Some("ordinary-error") => Err(alibi::AuthError::internal("selection policy failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden("Selection denied")),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("SELECTION_DENIED".into()),
                message: "Selection denied".into(),
            }),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "SELECTION_UNAVAILABLE",
                message: "Selection unavailable",
            }),
            _ => Ok(decision == Some("true")),
        }
    }
}

#[async_trait::async_trait]
impl OAuthSignupPolicy for SelectAccountPolicy {
    async fn should_redirect(
        &self,
        input: OAuthSignupContext<'_>,
    ) -> alibi::AuthResult<OAuthSignupRedirect> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"stage":"signup","sessionId":input.session.id}));
        Ok(
            if input
                .headers
                .get("x-signup-decision")
                .is_some_and(|v| v == "true")
            {
                OAuthSignupRedirect::ConfiguredPage
            } else {
                OAuthSignupRedirect::Continue
            },
        )
    }
}

#[async_trait::async_trait]
impl OAuthPostLoginPolicy for SelectAccountPolicy {
    async fn should_redirect(&self, input: OAuthPostLoginContext<'_>) -> alibi::AuthResult<bool> {
        self.calls
            .lock()
            .unwrap()
            .push(json!({"stage":"postLogin","sessionId":input.session.id}));
        Ok(input
            .headers
            .get("x-postlogin-decision")
            .is_some_and(|v| v == "true"))
    }
}
