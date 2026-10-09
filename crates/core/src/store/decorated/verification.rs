use crate::store::{PluginStore, VerificationStore};
use crate::verification::{VerificationCreation, VerificationPublication, VerificationSnapshot};
use crate::{AuthResult, AuthSchema, CreateVerification};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> VerificationStore<S> for PluginStore<S> {
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.inner
            .create_verification_record(data, publication)
            .await
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.consume_verification_snapshot(identifier).await
    }
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: crate::UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.inner
            .update_verification_by_identifier(identifier, data)
            .await
    }
    async fn reserve_verification_record(
        &self,
        logical_identifier: &str,
        data: CreateVerification,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .reserve_verification_record(logical_identifier, data)
            .await
    }
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.inner.create_verification(verification).await
    }
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification(identifier, value).await
    }
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification_by_value(value).await
    }
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification_by_identifier(identifier).await
    }
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.consume_verification(identifier, value).await
    }
    async fn get_latest_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .get_latest_verification_by_identifier(identifier)
            .await
    }
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .consume_verification_by_identifier(identifier)
            .await
    }
    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.inner
            .delete_verifications_by_identifier(identifier)
            .await
    }
    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        self.inner
            .compare_and_swap_verification(id, expected_value, value, expires_at)
            .await
    }
    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        self.inner.reserve_verification(verification).await
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_verification(id).await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.inner.delete_expired_verifications().await
    }
}
