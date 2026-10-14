//! Actual application resolver writes through the supplied transaction context.
use alibi::plugins::{SsoUserResolution, SsoUserResolutionInput, SsoUserResolver};
use alibi::{AuthResult, AuthSchema, AuthTransaction, CreateVerification};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
pub(crate) struct Policy {
    pub(crate) decision: Arc<Mutex<serde_json::Value>>,
    pub(crate) events: Arc<Mutex<Vec<serde_json::Value>>>,
    pub(crate) deny_sessions: Arc<AtomicBool>,
    pub(crate) fail_after_user: Arc<AtomicBool>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            decision: Arc::new(Mutex::new(serde_json::json!({"action":"continue"}))),
            events: Arc::new(Mutex::new(Vec::new())),
            deny_sessions: Arc::new(AtomicBool::new(false)),
            fail_after_user: Arc::new(AtomicBool::new(false)),
        }
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> SsoUserResolver<S> for Policy {
    async fn resolve(
        &self,
        input: SsoUserResolutionInput,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<SsoUserResolution> {
        let index = self.events.lock().unwrap().len() + 1;
        let identifier = format!("sso-resolver-write:{index}");
        _ = database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: input.provider_id.clone(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            })
            .await?;
        self.events
            .lock()
            .unwrap()
            .push(serde_json::json!({"input":input,"identifier":identifier}));
        let decision = self.decision.lock().unwrap().clone();
        if decision["action"] == "throw" {
            return Err(alibi::AuthError::internal(
                "Private application resolver detail",
            ));
        }
        serde_json::from_value(decision)
            .map_err(|error| alibi::AuthError::internal(error.to_string()))
    }
}

#[async_trait::async_trait]
impl<S: AuthSchema, B: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, B> for Policy {
    async fn before_create_session(
        &self,
        _: &mut alibi::CreateSession,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<alibi::store::HookControl> {
        if self.deny_sessions.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::Api {
                status: 403,
                code: Some("SESSION_POLICY_DENIED".into()),
                message: "Session policy rejected".into(),
            });
        }
        Ok(alibi::store::HookControl::Continue)
    }
    async fn after_create_user(
        &self,
        _: &S::User,
        _: &alibi::store::DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        if self.fail_after_user.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal(
                "Committed application user hook failed",
            ));
        }
        Ok(())
    }
}
