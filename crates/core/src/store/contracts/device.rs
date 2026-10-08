use super::*;
/// Persistence for OAuth device authorization codes.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    /// Persist a newly-issued device code.
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode>;
    /// Atomically persist a grant with application-owned fields.
    async fn create_device_code_with_fields(&self, input: CreateDeviceCode, fields: serde_json::Map<String, serde_json::Value>) -> AuthResult<DeviceCode> {
        if fields.is_empty() {self.create_device_code(input).await} else {Err(AuthError::not_implemented("Application device-grant fields are unsupported by this store"))}
    }
    /// Read the durable application fields belonging to a device record.
    async fn device_code_fields(&self, _id: &str) -> AuthResult<serde_json::Map<String, serde_json::Value>> {Ok(serde_json::Map::new())}
    /// Consume exactly one approved grant matching all application ownership predicates.
    async fn consume_device_code(&self, _id: &str, _status: &str, _ownership: &serde_json::Map<String, serde_json::Value>) -> AuthResult<Option<DeviceCode>> {
        Err(AuthError::not_implemented("Atomic application device-grant redemption is unsupported by this store"))
    }
    /// Fetch a device code by its opaque device-facing token.
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>>;
    /// Fetch a device code by its user-facing verification code.
    async fn get_device_code_by_user_code(&self, user_code: &str)
    -> AuthResult<Option<DeviceCode>>;
    /// Update mutable device-code state such as approval status or poll time.
    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode>;
    /// Update a device code only when it still has the expected status.
    ///
    /// Returns `true` when the compare-and-swap succeeds, or `false` when the
    /// row was already moved to a different state.
    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool>;
    /// Bind a still-pending, still-unclaimed device code to a user.
    ///
    /// Returns `true` when this call performed the claim, and `false` when the
    /// row was already claimed or no longer pending. The status and
    /// unclaimed checks are part of the write so two concurrent verifiers
    /// cannot both claim the same code.
    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool>;
    /// Delete a device code record.
    async fn delete_device_code(&self, id: &str) -> AuthResult<()>;
    /// Delete a device code only when it still has the expected status.
    ///
    /// Returns `true` when a matching row was deleted and `false` otherwise.
    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool>;
}
