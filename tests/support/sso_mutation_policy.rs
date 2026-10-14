//! Real application policy whose database writes belong to the mutation transaction.
use alibi::plugins::{SsoMutationAction, SsoProviderMutation, SsoProviderMutationGuard};
use alibi::{AuthResult, AuthSchema, AuthTransaction, CreateVerification};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
pub(crate) struct Policy {
    pub(crate) denied: Arc<AtomicBool>,
    pub(crate) events: Arc<Mutex<Vec<serde_json::Value>>>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            denied: Arc::new(AtomicBool::new(true)),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> SsoProviderMutationGuard<S> for Policy {
    async fn guard(
        &self,
        mutation: SsoProviderMutation,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<()> {
        let row = database
            .lock_sso_provider(&mutation.provider.id, &mutation.provider.provider_id)
            .await?
            .ok_or_else(|| alibi::AuthError::internal("Locked provider missing"))?;
        let index = self.events.lock().unwrap().len() + 1;
        let action = if mutation.action == SsoMutationAction::Update {
            "update"
        } else {
            "delete"
        };
        let identifier = format!("sso-guard-write:{action}:{index}");
        _ = database
            .create_verification(CreateVerification {
                identifier: identifier.clone(),
                value: row.domain.clone(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            })
            .await?;
        self.events.lock().unwrap().push(
            serde_json::json!({"mutation":mutation,"domain":row.domain,"identifier":identifier}),
        );
        if self.denied.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal(
                "Application policy rejected with private detail",
            ));
        }
        Ok(())
    }
}
