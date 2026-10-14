//! An application callback observes successful provisioning, not fixture receipts.
use alibi::plugins::{SsoProvisioningData, SsoUserProvisioner};
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
pub(crate) struct Policy {
    pub(crate) events: Arc<Mutex<Vec<serde_json::Value>>>,
}
#[async_trait::async_trait]
impl SsoUserProvisioner for Policy {
    async fn provision(&self, data: SsoProvisioningData) -> alibi::AuthResult<()> {
        self.events.lock().unwrap().push(serde_json::json!({
            "userId":data.user.id,
            "email":data.user.email,
            "name":data.user.name,
            "userInfo":data.user_info,
            "providerId":data.provider.provider_id,
            "tokenPresent":data.token.is_some(),
            "accessToken":data.token.and_then(|token|token.access_token),
        }));
        Ok(())
    }
}
