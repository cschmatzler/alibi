use alibi::plugins::{
    OAuthPostLoginContext, OAuthPostLoginPolicy, OAuthSignupContext, OAuthSignupPolicy,
    OAuthSignupRedirect,
};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct PostLoginPolicy {
    pub calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthPostLoginPolicy for PostLoginPolicy {
    async fn should_redirect(&self, input: OAuthPostLoginContext<'_>) -> alibi::AuthResult<bool> {
        let decision = input
            .headers
            .get("x-postlogin-decision")
            .map(String::as_str);
        self.calls.lock().unwrap().push(json!({
            "stage":"postLogin", "caller":input.headers.get("x-policy-caller"), "decision":decision,
            "user":{"id":input.user.id,"email":input.user.email,"name":input.user.name},
            "session":{"id":input.session.id,"userId":input.session.user_id,"token":input.session.token},
            "scopes":input.scopes,
        }));
        match decision {
            Some("ordinary-error") => Err(alibi::AuthError::internal("post-login policy failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden("Post-login denied")),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("POSTLOGIN_DENIED".into()),
                message: "Post-login denied".into(),
            }),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "POSTLOGIN_UNAVAILABLE",
                message: "Post-login unavailable",
            }),
            _ => Ok(decision != Some("false")),
        }
    }
}

#[async_trait::async_trait]
impl OAuthSignupPolicy for PostLoginPolicy {
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
                .is_some_and(|value| value == "true")
            {
                OAuthSignupRedirect::ConfiguredPage
            } else {
                OAuthSignupRedirect::Continue
            },
        )
    }
}
