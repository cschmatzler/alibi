//! An application callback observes successful provisioning, not fixture receipts.
use alibi::plugins::{SsoProvisioningData, SsoUserProvisioner};
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
pub(crate) struct Policy {
    pub(crate) roles: Arc<Mutex<Vec<serde_json::Value>>>,
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

#[async_trait::async_trait]
impl alibi::plugins::SsoOrganizationRoleResolver for Policy {
    async fn get_role(&self, data: SsoProvisioningData) -> alibi::AuthResult<String> {
        self.roles.lock().unwrap().push(serde_json::json!({
            "userId":data.user.id, "email":data.user.email, "providerId":data.provider.provider_id,
            "organizationId":data.provider.organization_id, "profile":data.user_info,
            "tokenPresent":data.token.is_some(),
        }));
        Ok("admin".into())
    }
}
