//! Native optional record storage for the no-database schema.
//!
//! Mutations lock only an individual adapter operation, never an entire plugin
//! workflow or callback. Earlier successful writes survive later failures, and
//! restarting the store loses every record. Expiry remains the plugin's policy.
use crate::store::stateless::StatelessStore;
use crate::store::{PasskeyStore, TwoFactorStore};
use crate::types::UpdatePasskeyAuthentication;
use crate::{
    AuthError, AuthResult, CreatePasskey, CreateTwoFactor, Passkey, TwoFactor, UpdateTwoFactor,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Mutate an exact stored generation; never recreate a concurrently deleted row.
fn mutate_record<T: Clone>(
    records: &mut indexmap::IndexMap<String, T>,
    id: &str,
    update: impl FnOnce(&mut T) -> bool,
) -> Option<T> {
    let record = records.get_mut(id)?;
    update(record).then(|| record.clone())
}

#[async_trait]
impl TwoFactorStore for StatelessStore {
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        let record = TwoFactor {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: input.user_id,
            secret: input.secret,
            backup_codes: input.backup_codes,
            verified: input.verified,
            failed_verification_count: input.failed_verification_count,
            locked_until: input.locked_until,
            created_at: now,
            updated_at: now,
        };
        _ = self
            .lock()?
            .two_factors
            .insert(record.id.clone(), record.clone());
        Ok(record)
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(self
            .lock()?
            .two_factors
            .values()
            .find(|record| record.user_id == user_id)
            .cloned())
    }
    async fn update_two_factor(
        &self,
        id: &str,
        update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        Ok(mutate_record(&mut self.lock()?.two_factors, id, |record| {
            if let Some(secret) = update.secret {
                record.secret = secret;
            }
            if let Some(codes) = update.backup_codes {
                record.backup_codes = codes;
            }
            if let Some(verified) = update.verified {
                record.verified = Some(verified);
            }
            true
        }))
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut state = self.lock()?;
        let record = state
            .two_factors
            .values_mut()
            .find(|record| record.user_id == user_id)
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        record.backup_codes = backup_codes.to_owned();
        record.updated_at = Utc::now();
        Ok(record.clone())
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.lock()?
            .two_factors
            .retain(|_, record| record.user_id != user_id);
        Ok(())
    }
    async fn increment_two_factor_failure(&self, id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(mutate_record(&mut self.lock()?.two_factors, id, |record| {
            // Source memory incrementOne treats a non-number (including NULL)
            // as zero. Keep SQL's separate NULL arithmetic behavior unchanged.
            record.failed_verification_count =
                Some(record.failed_verification_count.unwrap_or(0.0) + 1.0);
            true
        }))
    }
    async fn set_two_factor_lock_if_count_at_least(
        &self,
        id: &str,
        threshold: f64,
        until: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Ok(mutate_record(&mut self.lock()?.two_factors, id, |record| {
            // Memory comparison follows JavaScript: null >= n compares as 0.
            if record.failed_verification_count.unwrap_or(0.0) >= threshold {
                record.locked_until = Some(until);
                true
            } else {
                false
            }
        }))
    }
    async fn clear_expired_two_factor_lock(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Ok(mutate_record(&mut self.lock()?.two_factors, id, |record| {
            if record.locked_until.is_some_and(|until| until <= now) {
                record.failed_verification_count = Some(0.0);
                record.locked_until = None;
                true
            } else {
                false
            }
        }))
    }
    async fn reset_two_factor_failures(&self, id: &str) -> AuthResult<()> {
        _ = mutate_record(&mut self.lock()?.two_factors, id, |record| {
            record.failed_verification_count = Some(0.0);
            record.locked_until = None;
            true
        });
        Ok(())
    }
    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        id: &str,
        expected: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        Ok(mutate_record(&mut self.lock()?.two_factors, id, |record| {
            if record.backup_codes == expected {
                record.backup_codes = replacement.to_owned();
                true
            } else {
                false
            }
        })
        .is_some())
    }
}

#[async_trait]
impl PasskeyStore for StatelessStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let now = Utc::now();
        let record = Passkey {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: input.user_id,
            name: input.name,
            credential_id: input.credential_id,
            public_key: input.public_key,
            counter: input.counter,
            device_type: input.device_type,
            backed_up: input.backed_up,
            transports: input.transports,
            credential: input.credential,
            aaguid: input.aaguid,
            created_at: now,
            updated_at: now,
        };
        _ = self
            .lock()?
            .passkeys
            .insert(record.id.clone(), record.clone());
        Ok(record)
    }
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        Ok(self.lock()?.passkeys.get(id).cloned())
    }
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Ok(self
            .lock()?
            .passkeys
            .values()
            .find(|record| record.credential_id == credential_id)
            .cloned())
    }
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        // Source's unsorted memory query preserves insertion order.
        Ok(self
            .lock()?
            .passkeys
            .values()
            .filter(|record| record.user_id == user_id)
            .cloned()
            .collect())
    }
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>> {
        Ok(mutate_record(&mut self.lock()?.passkeys, id, |record| {
            record.counter = update.counter;
            record.backed_up = update.backed_up;
            record.device_type = update.device_type;
            record.credential = update.credential;
            record.updated_at = Utc::now();
            true
        }))
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        mutate_record(&mut self.lock()?.passkeys, id, |record| {
            record.name = Some(name.to_owned());
            record.updated_at = Utc::now();
            true
        })
        .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        _ = self.lock()?.passkeys.shift_remove(id);
        Ok(())
    }
}
