use crate::{AuthError, AuthResult, AuthSchema, CreateAccount, UpdateAccount};
use async_trait::async_trait;
#[async_trait]
pub trait AccountStore<S: AuthSchema>: Send + Sync {
    /// Apply the physical token TEXT column's scalar affinity before persistence.
    /// SQL adapters override this for their own boolean/numeric representation.
    async fn provider_token_text(&self, value: &serde_json::Value) -> AuthResult<Option<String>> {
        if value.is_null() {
            return Ok(None);
        }
        if value.is_object() || value.is_array() {
            return Err(AuthError::internal(
                "Unsupported provider token SQL parameter",
            ));
        }
        crate::utils::json::JsValue::from(value.clone())
            .coerce_string()
            .map(Some)
            .map_err(AuthError::internal)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        crate::AdapterRecord::physical(self.create_account(create_account).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_account_record(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        self.get_account(provider, provider_account_id)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    /// Retain the selected physical credential result. Initialization applies
    /// output policy only to that selected row, never unrelated linked accounts.
    async fn get_credential_account_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        use crate::AuthAccount;
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| {
                account.provider_id() == "credential" && account.account_id() == user_id
            })
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    async fn get_user_accounts_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Account>>> {
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_account_record(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        crate::AdapterRecord::physical(self.update_account(id, update).await?)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    /// Resolve a global provider identity only when exactly one physical row matches.
    /// Duplicate rows (including duplicates owned by one user) must return
    /// `DatabaseError::AmbiguousAccount`; choosing a row would make ownership arbitrary.
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>>;
    /// Return all scoped physical rows in the adapter's native order. Do not
    /// select or collapse duplicate provider identities, or sort by mutable dates.
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}
