//! Application policy observes real SSO identity provenance at admission.
use alibi::AuthResult;
use alibi::user_validation::{
    UserInfoValidator, UserValidationAction, UserValidationData, UserValidationRejection,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone, Default)]
pub(super) struct Policy {
    pub events: Arc<Mutex<Vec<serde_json::Value>>>,
    pub deny_returning: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl UserInfoValidator for Policy {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        context: &alibi::user_validation::UserValidationContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        if data.source.method != "oauth" && !data.source.method.starts_with("sso-") {
            return Ok(None);
        }
        self.events.lock().unwrap().push(
            serde_json::json!({"source":data.source,"name":data.user.name,"email":data.user.email,"requestPresent":context.request.is_some(),"path":context.endpoint.as_ref().and_then(alibi::endpoint::EndpointCall::path)}),
        );
        if !matches!(data.source.method.as_str(), "sso-oidc" | "sso-saml")
            || data.source.sso.is_none()
            || data.source.oauth.is_some()
        {
            return Ok(Some(UserValidationRejection {
                error: "wrong_sso_source".into(),
                error_description: Some("SSO provenance required".into()),
            }));
        }
        if data.source.action == UserValidationAction::SignIn
            && self.deny_returning.load(Ordering::SeqCst)
        {
            return Ok(Some(UserValidationRejection {
                error: "sso_validation_denied".into(),
                error_description: Some("SSO identity rejected".into()),
            }));
        }
        if data.source.action == UserValidationAction::CreateUser {
            data.user.name = Some("Policy SSO user".into());
        }
        Ok(None)
    }
}
