use crate::{AdapterRecord, AuthAccount};
use crate::{AuthError, AuthResult, AuthSchema, CreateAccount, UpdateAccount};
use async_trait::async_trait;
#[cfg(test)]
mod utf16_tests {
    use super::*;
    use crate::AccountView;
    use crate::utils::json::{JsString, to_js_value};
    use std::marker::PhantomData;
    use std::sync::Mutex;

    struct Observed<S, T> {
        inner: T,
        calls: Mutex<Vec<(&'static str, JsString)>>,
        schema: PhantomData<fn() -> S>,
    }
    #[async_trait]
    impl<S, T> AccountStore<S> for Observed<S, T>
    where
        S: AuthSchema<Account = AccountView>,
        T: AccountStore<S>,
    {
        async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
            self.calls
                .lock()
                .unwrap()
                .push(("create", input.account_id.clone()));
            self.inner.create_account(input).await
        }
        async fn get_account(
            &self,
            provider: &str,
            key: &JsString,
        ) -> AuthResult<Option<AccountView>> {
            self.calls.lock().unwrap().push(("query", key.clone()));
            self.inner.get_account(provider, key).await
        }
        async fn get_user_accounts(&self, user: &str) -> AuthResult<Vec<AccountView>> {
            self.inner.get_user_accounts(user).await
        }
        async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
            self.inner.update_account(id, update).await
        }
        async fn delete_account(&self, id: &str) -> AuthResult<()> {
            self.inner.delete_account(id).await
        }
    }
    fn input(id: JsString) -> CreateAccount {
        CreateAccount {
            additional_fields: Default::default(),
            user_id: "owner".into(),
            account_id: id,
            provider_id: "fixture".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        }
    }
    async fn exercise<S, T>(inner: T)
    where
        S: AuthSchema<Account = AccountView>,
        T: AccountStore<S>,
    {
        let store = Observed::<S, T> {
            inner,
            calls: Default::default(),
            schema: PhantomData,
        };
        let keys = [
            JsString::from_code_units(vec![0x61, 0xd800, 0x62]),
            JsString::from_code_units(vec![0x61, 0xdc00, 0x62]),
            JsString::from("a\u{fffd}b"),
        ];
        let mut rows = Vec::new();
        for key in &keys {
            let row = store.create_account(input(key.clone())).await.unwrap();
            assert_eq!(row.account_id(), *key);
            assert_eq!(
                to_js_value(&row).unwrap()["accountId"].as_js_string(),
                Some(key)
            );
            rows.push(row);
        }
        for (key, expected) in keys.iter().zip(&rows) {
            let selected = store.get_account("fixture", key).await.unwrap().unwrap();
            assert_eq!(selected.id, expected.id);
            assert_eq!(selected.account_id(), *key);
        }
        let trace = store.calls.lock().unwrap();
        assert_eq!(trace.len(), 6);
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(trace[index], ("create", key.clone()));
            assert_eq!(trace[index + 3], ("query", key.clone()));
        }
        assert_ne!(rows[0].id, rows[1].id);
        assert_ne!(rows[1].id, rows[2].id);
    }
    #[tokio::test]
    async fn memory_account_queries_and_writes_preserve_distinct_utf16_keys() {
        let store =
            crate::test_store::MemoryStore::new(std::sync::Arc::new(crate::AuthConfig::default()));
        exercise::<crate::test_store::BundledSchema, _>(store).await;
    }
    #[tokio::test]
    async fn stateless_account_queries_and_writes_preserve_distinct_utf16_keys() {
        exercise::<crate::store::stateless::StatelessSchema, _>(
            crate::store::stateless::StatelessStore::default(),
        )
        .await;
    }
}

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
    ) -> AuthResult<AdapterRecord<S::Account>> {
        AdapterRecord::physical(self.create_account(create_account).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_account_record(
        &self,
        provider: &str,
        provider_account_id: &crate::utils::json::JsString,
    ) -> AuthResult<Option<AdapterRecord<S::Account>>> {
        self.get_account(
            provider,
            &crate::utils::json::JsString::from(provider_account_id),
        )
        .await?
        .map(AdapterRecord::physical)
        .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    /// Retain the selected physical credential result. Initialization applies
    /// output policy only to that selected row, never unrelated linked accounts.
    async fn get_credential_account_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<AdapterRecord<S::Account>>> {
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| {
                account.provider_id() == "credential" && account.account_id() == user_id
            })
            .map(AdapterRecord::physical)
            .transpose()
    }

    async fn get_user_accounts_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Account>>> {
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .map(AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_account_record(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<AdapterRecord<S::Account>> {
        AdapterRecord::physical(self.update_account(id, update).await?)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    /// Resolve a global provider identity only when exactly one physical row matches.
    /// Duplicate rows (including duplicates owned by one user) must return
    /// `DatabaseError::AmbiguousAccount`; choosing a row would make ownership arbitrary.
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &crate::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>>;
    /// Return all scoped physical rows in the adapter's native order. Do not
    /// select or collapse duplicate provider identities, or sort by mutable dates.
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}
