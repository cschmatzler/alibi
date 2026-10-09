use crate::store::{AccountStore, AdapterEvent, PluginStore};
use crate::{AuthResult, AuthSchema, CreateAccount, UpdateAccount};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> AccountStore<S> for PluginStore<S> {
    async fn provider_token_text(&self, value: &serde_json::Value) -> AuthResult<Option<String>> {
        self.inner.provider_token_text(value).await
    }

    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        let record = self
            .account_record(self.create_account(create_account).await?)
            .await?;
        self.observe(AdapterEvent::AccountCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_account_record(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        let Some(model) = self.get_account(provider, provider_account_id).await? else {
            return Ok(None);
        };
        let record = self.account_record(model).await?;
        Ok(Some(record))
    }

    async fn get_credential_account_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        use crate::AuthAccount;
        let model = self
            .get_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| {
                account.provider_id() == "credential" && account.account_id() == user_id
            });
        match model {
            Some(model) => self.account_record(model).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Account>>> {
        let mut records = Vec::new();
        for model in self.get_user_accounts(user_id).await? {
            records.push(self.account_record(model).await?);
        }
        Ok(records)
    }

    async fn update_account_record(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        let record = self
            .account_record(self.update_account(id, update).await?)
            .await?;
        self.observe(AdapterEvent::AccountUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_account(&self, mut create_account: CreateAccount) -> AuthResult<S::Account> {
        self.field_policies()
            .account
            .attach(&mut create_account.additional_fields, true);
        self.inner.create_account(create_account).await
    }
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        self.inner.get_account(provider, provider_account_id).await
    }
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        self.inner.get_user_accounts(user_id).await
    }
    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        self.field_policies()
            .account
            .attach(&mut update.additional_fields, false);
        self.inner.update_account(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }
}
