use alibi::plugins::{OAuthSignupContext, OAuthSignupPolicy, OAuthSignupRedirect};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(super) struct SignupPolicy {
    pub calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl OAuthSignupPolicy for SignupPolicy {
    async fn should_redirect(
        &self,
        input: OAuthSignupContext<'_>,
    ) -> alibi::AuthResult<OAuthSignupRedirect> {
        let decision = input.headers.get("x-signup-decision").map(String::as_str);
        self.calls.lock().unwrap().push(json!({
            "caller":input.headers.get("x-signup-caller"),
            "decision":decision,
            "user":{"id":input.user.id,"email":input.user.email,"name":input.user.name},
            "session":{"id":input.session.id,"userId":input.session.user_id,"token":input.session.token},
            "scopes":input.scopes,
        }));
        match decision {
            Some("true") => Ok(OAuthSignupRedirect::ConfiguredPage),
            Some("page") => Ok(OAuthSignupRedirect::Page("/registration/step".into())),
            Some("fragment") => Ok(OAuthSignupRedirect::Page(
                "/registration/step#fragment".into(),
            )),
            Some("empty") => Ok(OAuthSignupRedirect::Page(String::new())),
            Some("ordinary-error") => Err(alibi::AuthError::internal("signup policy failed")),
            Some("native-error") => Err(alibi::AuthError::forbidden(
                "Signup denied by native policy",
            )),
            Some("upstream-error") => Err(alibi::AuthError::Upstream {
                status: 503,
                code: "SIGNUP_UNAVAILABLE",
                message: "Signup policy unavailable",
            }),
            Some("api-error") => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("SIGNUP_DENIED".into()),
                message: "Signup denied by application".into(),
            }),
            _ => Ok(OAuthSignupRedirect::Continue),
        }
    }
}
