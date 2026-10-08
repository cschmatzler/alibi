//! Native device grants share the no-database identity lifetime.
use super::*;

#[async_trait]
impl DeviceCodeStore for StatelessStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.create_device_code_with_fields(input,serde_json::Map::new()).await
    }
    async fn create_device_code_with_fields(&self, input: CreateDeviceCode, fields: serde_json::Map<String, serde_json::Value>) -> AuthResult<DeviceCode> {
        let device_code = DeviceCode {
            id: uuid::Uuid::new_v4().to_string(),
            device_code: input.device_code,
            user_code: input.user_code,
            user_id: input.user_id,
            expires_at: input.expires_at,
            status: input.status,
            last_polled_at: input.last_polled_at,
            polling_interval: input.polling_interval,
            client_id: input.client_id,
            scope: input.scope,
        };
        let mut state = self.lock()?;
        _ = state.device_code_fields.insert(device_code.id.clone(),fields);
        _ = state.device_codes.insert(device_code.id.clone(),device_code.clone());
        Ok(device_code)
    }
    async fn device_code_fields(&self, id: &str) -> AuthResult<serde_json::Map<String, serde_json::Value>> {Ok(self.lock()?.device_code_fields.get(id).cloned().unwrap_or_default())}
    async fn consume_device_code(&self, id: &str, status: &str, ownership: &serde_json::Map<String, serde_json::Value>) -> AuthResult<Option<DeviceCode>> {
        let mut state = self.lock()?;
        let matches = state.device_codes.get(id).is_some_and(|row| row.status == status) && ownership.iter().all(|(key,value)| state.device_code_fields.get(id).and_then(|fields| fields.get(key)) == Some(value));
        if !matches {return Ok(None);}
        _ = state.device_code_fields.shift_remove(id);
        Ok(state.device_codes.shift_remove(id))
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()?
            .device_codes
            .values()
            .find(|value| value.device_code == device_code)
            .cloned())
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Ok(self
            .lock()?
            .device_codes
            .values()
            .find(|value| value.user_code == user_code)
            .cloned())
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut state = self.lock()?;
        let device_code = state
            .device_codes
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Device code not found"))?;

        if let Some(status) = update.status {
            device_code.status = status;
        }
        if let Some(user_id) = update.user_id {
            device_code.user_id = user_id;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            device_code.last_polled_at = last_polled_at;
        }

        let locked_result = Ok(device_code.clone());
        drop(state);
        locked_result
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let Some(device_code) = state.device_codes.get_mut(id) else {
            return Ok(false);
        };

        if device_code.status != current_status {
            return Ok(false);
        }

        if let Some(status) = update.status {
            device_code.status = status;
        }
        if let Some(user_id) = update.user_id {
            device_code.user_id = user_id;
        }
        if let Some(last_polled_at) = update.last_polled_at {
            device_code.last_polled_at = last_polled_at;
        }
        drop(state);

        Ok(true)
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let Some(device_code) = state.device_codes.get_mut(id) else {
            return Ok(false);
        };

        if device_code.status != "pending" || device_code.user_id.is_some() {
            return Ok(false);
        }

        device_code.user_id = Some(user_id.to_owned());
        drop(state);

        Ok(true)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        let mut state=self.lock()?;
        drop(state.device_codes.shift_remove(id));
        drop(state.device_code_fields.shift_remove(id));
        Ok(())
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let should_delete = state
            .device_codes
            .get(id)
            .is_some_and(|device_code| device_code.status == status);

        if should_delete {
            drop(state.device_codes.shift_remove(id));
            drop(state.device_code_fields.shift_remove(id));
        }

        let locked_result = Ok(should_delete);
        drop(state);
        locked_result
    }
}
