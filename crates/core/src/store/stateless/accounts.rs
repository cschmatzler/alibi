use super::*;
#[async_trait]
impl AccountStore<StatelessSchema> for StatelessStore {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
        let now = Utc::now();
        let account = AccountView {
            id: uuid::Uuid::new_v4().to_string(),
            account_id: create_account.account_id,
            provider_id: create_account.provider_id,
            user_id: create_account.user_id,
            access_token: create_account.access_token,
            refresh_token: create_account.refresh_token,
            id_token: create_account.id_token,
            access_token_expires_at: create_account.access_token_expires_at,
            refresh_token_expires_at: create_account.refresh_token_expires_at,
            scope: create_account.scope,
            password: create_account.password,
            created_at: now,
            updated_at: now,
        };
        _ = self
            .lock()?
            .accounts
            .insert(account.id.clone(), account.clone());
        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        let storage = self.lock()?;
        let mut matches = storage.accounts.values().filter(|account| {
            account.provider_id == provider && account.account_id == provider_account_id
        });
        let first = matches.next().cloned();
        if matches.next().is_some() {
            return Err(AuthError::Database(
                crate::DatabaseError::AmbiguousAccount {
                    provider: provider.to_owned(),
                },
            ));
        }
        Ok(first)
    }

    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
        Ok(self
            .lock()?
            .accounts
            .values()
            .filter(|account| account.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        let mut state = self.lock()?;
        let account = state
            .accounts
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Account not found"))?;
        if let Some(access_token) = update.access_token {
            account.access_token = Some(access_token);
        }
        if let Some(refresh_token) = update.refresh_token {
            account.refresh_token = Some(refresh_token);
        }
        if let Some(id_token) = update.id_token {
            account.id_token = Some(id_token);
        }
        if let Some(access_token_expires_at) = update.access_token_expires_at {
            account.access_token_expires_at = Some(access_token_expires_at);
        }
        if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
            account.refresh_token_expires_at = Some(refresh_token_expires_at);
        }
        if let Some(scope) = update.scope {
            account.scope = Some(scope);
        }
        if let Some(password) = update.password {
            account.password = Some(password);
        }
        account.updated_at = Utc::now();
        let locked_result = Ok(account.clone());
        drop(state);
        locked_result
    }

    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        _ = self.lock()?.accounts.shift_remove(id);
        Ok(())
    }
}
