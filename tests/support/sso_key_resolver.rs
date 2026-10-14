//! An actual application signing-key resolver with captured invocation context.
use alibi::plugins::{SsoPrivateKey, SsoPrivateKeyContext, SsoPrivateKeyResolver};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone)]
pub(crate) struct Policy {
    pub(crate) enabled: Arc<AtomicBool>,
    pub(crate) events: Arc<Mutex<Vec<serde_json::Value>>>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
#[async_trait::async_trait]
impl SsoPrivateKeyResolver for Policy {
    async fn resolve(
        &self,
        context: SsoPrivateKeyContext,
    ) -> alibi::AuthResult<Option<SsoPrivateKey>> {
        self.events.lock().unwrap().push(serde_json::json!({"providerId":context.provider_id,"keyId":context.key_id,"issuer":context.issuer}));
        Ok(Some(if self.enabled.load(Ordering::SeqCst) {
            SsoPrivateKey {
                private_key_pem: Some(
                    include_str!("../compat/fixtures/salesforce-transport/key.pem").into(),
                ),
                kid: Some("resolved-kid".into()),
                algorithm: Some("PS256".into()),
                ..Default::default()
            }
        } else {
            SsoPrivateKey::default()
        }))
    }
}
