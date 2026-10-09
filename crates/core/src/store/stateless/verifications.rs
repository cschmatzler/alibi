use crate::store::VerificationStore;
use crate::store::stateless::{StatelessSchema, StatelessStore};
use crate::{AuthError, AuthResult, CreateVerification, VerificationView};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[async_trait]
impl VerificationStore<StatelessSchema> for StatelessStore {
    async fn create_verification_record(
        &self,
        data: crate::verification::VerificationCreation,
        publication: crate::verification::VerificationPublication,
    ) -> AuthResult<Option<crate::verification::VerificationSnapshot>> {
        let snapshot = if publication.store_in_database {
            let model = VerificationView {
                id: data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                identifier: data.identifier,
                value: data.value,
                expires_at: data.expires_at,
                created_at: data.created_at,
                updated_at: data.updated_at,
            };
            let mut state = self.lock()?;
            if state.verifications.contains_key(&model.id) {
                return Err(AuthError::internal("duplicate verification primary ID"));
            }
            _ = state.verifications.insert(model.id.clone(), model.clone());
            drop(state);
            crate::verification::VerificationSnapshot::from_model(&model)
        } else {
            data.snapshot()
        };
        publication.publish(&snapshot).await?;
        Ok(Some(snapshot))
    }

    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let mut state = self.lock()?;
        let found = state
            .verifications
            .values()
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .cloned();
        state
            .verifications
            .retain(|_, sibling| sibling.identifier != identifier);
        drop(state);
        Ok(found)
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: crate::UpdateVerification,
    ) -> AuthResult<Option<crate::verification::VerificationSnapshot>> {
        let mut state = self.lock()?;
        let mut found = None;
        for model in state.verifications.values_mut() {
            if model.identifier == identifier {
                model.updated_at = Utc::now();
                if let Some(value) = &data.value {
                    model.value.clone_from(value);
                }
                if let Some(expiry) = data.expires_at {
                    model.expires_at = expiry;
                }
                if found.is_none() {
                    found = Some(crate::verification::VerificationSnapshot::from_model(model));
                }
            }
        }
        drop(state);
        Ok(found)
    }

    async fn reserve_verification_record(
        &self,
        logical_identifier: &str,
        data: CreateVerification,
    ) -> AuthResult<Option<VerificationView>> {
        let (id, _) = crate::store::verification_reservation_key(logical_identifier);
        let mut state = self.lock()?;
        let indexmap::map::Entry::Vacant(entry) = state.verifications.entry(id.clone()) else {
            return Ok(None);
        };
        let now = Utc::now();
        let model = VerificationView {
            id,
            identifier: data.identifier,
            value: data.value,
            expires_at: data.expires_at,
            created_at: now,
            updated_at: now,
        };
        _ = entry.insert(model.clone());
        drop(state);
        Ok(Some(model))
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<VerificationView> {
        let now = Utc::now();
        let verification = VerificationView {
            id: uuid::Uuid::new_v4().to_string(),
            identifier: verification.identifier,
            value: verification.value,
            expires_at: verification.expires_at,
            created_at: now,
            updated_at: now,
        };
        _ = self
            .lock()?
            .verifications
            .insert(verification.id.clone(), verification.clone());
        Ok(verification)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .filter(|verification| {
                verification.identifier == identifier
                    && verification.value == value
                    && verification.expires_at >= Utc::now()
            })
            .max_by_key(|verification| verification.created_at)
            .cloned())
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .filter(|verification| {
                verification.value == value && verification.expires_at >= Utc::now()
            })
            .max_by_key(|verification| verification.created_at)
            .cloned())
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .filter(|verification| {
                verification.identifier == identifier && verification.expires_at >= Utc::now()
            })
            .max_by_key(|verification| verification.created_at)
            .cloned())
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let mut state = self.lock()?;
        let found = state
            .verifications
            .values()
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .cloned();
        if let Some(verification) = &found {
            if verification.value != value {
                return Ok(None);
            }
            state
                .verifications
                .retain(|_, sibling| sibling.identifier != identifier);
        }
        drop(state);

        Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
    }

    async fn get_latest_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .cloned())
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let mut state = self.lock()?;
        let found = state
            .verifications
            .values()
            .filter(|verification| verification.identifier == identifier)
            .max_by_key(|verification| verification.created_at)
            .cloned();
        state
            .verifications
            .retain(|_, sibling| sibling.identifier != identifier);
        drop(state);

        Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
    }

    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.lock()?
            .verifications
            .retain(|_, verification| verification.identifier != identifier);
        Ok(())
    }

    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let Some(verification) = state.verifications.get_mut(id) else {
            return Ok(false);
        };
        if verification.value != expected_value {
            return Ok(false);
        }
        value.clone_into(&mut verification.value);
        verification.expires_at = expires_at;
        verification.updated_at = Utc::now();
        drop(state);

        Ok(true)
    }

    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        let (id, _) = crate::store::verification_reservation_key(&verification.identifier);
        let mut state = self.lock()?;
        let indexmap::map::Entry::Vacant(entry) = state.verifications.entry(id.clone()) else {
            return Ok(false);
        };

        let now = Utc::now();
        _ = entry.insert(VerificationView {
            id,
            identifier: verification.identifier,
            value: verification.value,
            expires_at: verification.expires_at,
            created_at: now,
            updated_at: now,
        });
        drop(state);
        Ok(true)
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        _ = self.lock()?.verifications.shift_remove(id);
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.lock()?;
        let before = state.verifications.len();
        state.verifications.retain(|_, verification| {
            verification.expires_at.timestamp_millis() >= now.timestamp_millis()
        });
        Ok(before - state.verifications.len())
    }
}
