use crate::types::UpdatePasskeyAuthentication;
use crate::{AuthResult, CreatePasskey, Passkey};
use async_trait::async_trait;
#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    /// Update the verified credential, returning `None` if application code removed its row.
    /// Storage failures remain errors; an absent row does not invalidate completed verification.
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}
