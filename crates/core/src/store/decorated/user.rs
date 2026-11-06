use crate::store::{
    AccountStore, AdapterEvent, NumericTextInput, PluginStore, SessionStore, UserStore,
    create_user_data,
};
use crate::user_validation::{PreparedUserCreation, UserValidationSource, prepare_creation};
use crate::{AdapterRecord, AuthAccount};
use crate::{AuthResult, AuthSchema, CreateUser, ListUsersParams, UpdateUser};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> UserStore<S> for PluginStore<S> {
    fn supports_native_json(&self) -> bool {
        self.inner.supports_native_json()
    }
    async fn native_user_output_for(
        &self,
        user: &S::User,
    ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
        self.inner.native_user_output_for(user).await
    }

    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
        self.inner.native_user_output(id).await
    }

    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        self.inner.provider_verification_output(id).await
    }

    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user(create_user).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user_with_source(create_user, source).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user_prepared(prepared).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_user_by_id_record(&self, id: &str) -> AuthResult<Option<AdapterRecord<S::User>>> {
        let user = self.get_user_by_id(id).await?;
        self.optional_user_record(user).await
    }

    async fn get_user_by_email_record(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        let user = self
            .get_user_by_email(&crate::utils::json::JsString::from(email))
            .await?;
        self.optional_user_record(user).await
    }

    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        let user = self.get_user_by_username(username).await?;
        self.optional_user_record(user).await
    }

    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        let user = self.get_user_by_phone_number(phone_number).await?;
        self.optional_user_record(user).await
    }

    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let users = self.list_users_by_ids(ids).await?;
        self.user_records(users).await
    }

    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let users = self.list_users_by_ids_page(ids, limit).await?;
        self.user_records(users).await
    }

    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let record = self
            .user_record(self.update_user(id, update).await?)
            .await?;
        self.observe(AdapterEvent::UserUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn list_users_record(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<AdapterRecord<S::User>>, usize)> {
        let (users, count) = self.list_users(params).await?;
        Ok((self.user_records(users).await?, count))
    }

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        self.field_policies()
            .user
            .attach(&mut create_user.additional_fields, true);
        if self.config.user_validation.is_some() {
            let prepared = prepare_creation(&self.config, create_user, None).await?;
            return self.create_user_prepared(prepared).await;
        }
        let create_user = create_user_data(
            create_user,
            &self.transforms.creates,
            &self.projection_context,
            None,
        )
        .await?;
        self.inner.create_user(create_user).await
    }
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<S::User> {
        if self.config.user_validation.is_none() {
            return self.create_user(create_user).await;
        }
        let prepared = prepare_creation(&self.config, create_user, Some(source)).await?;
        self.create_user_prepared(prepared).await
    }
    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let mut data = create_user_data(
            prepared.into_data(),
            &self.transforms.creates,
            &self.projection_context,
            None,
        )
        .await?;
        self.field_policies()
            .user
            .attach(&mut data.additional_fields, true);
        self.inner
            .create_user_prepared(
                PreparedUserCreation::from_data(data)
                    .with_defaults(self.transforms.adapter_defaults.clone()),
            )
            .await
    }
    async fn coerce_user_text_number(&self, input: NumericTextInput) -> AuthResult<String> {
        self.inner.coerce_user_text_number(input).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        self.inner.list_users_by_ids(ids).await
    }
    async fn list_users_by_ids_page(&self, ids: &[String], limit: f64) -> AuthResult<Vec<S::User>> {
        self.inner.list_users_by_ids_page(ids, limit).await
    }
    async fn get_user_by_email(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        use crate::AuthUser;
        Ok(self
            .inner
            .get_user_by_email(&crate::utils::json::JsString::from(email))
            .await?
            .filter(|user| user.email().is_some_and(|stored| same_email(stored, email))))
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_username(username).await
    }

    async fn get_user_by_username_value(
        &self,
        username: &crate::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_username_value(username).await
    }
    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_phone_number(phone_number).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        let mut update = update;
        self.field_policies()
            .user
            .attach(&mut update.additional_fields, false);
        update = crate::store::contracts::update_user_data(
            id,
            update,
            &self.transforms.updates,
            &self.projection_context,
            None,
        )
        .await?;
        let user = self.inner.update_user(id, update).await?;
        if self.refresh_cached_user(&user).await.is_err() {
            tracing::error!("Failed to refresh committed user sessions in secondary storage");
        }
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let tokens = self.cached_user_tokens(id).await?;
        self.delete_user_sessions(id).await?;
        for account in self.get_user_accounts(id).await? {
            self.delete_account(account.id().as_ref()).await?;
        }
        self.inner.delete_user(id).await?;
        self.remove_cached_user_sessions(id, tokens).await?;
        Ok(())
    }
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        self.inner.list_users(params).await
    }
}

pub(super) fn same_email(left: &str, right: &crate::utils::json::JsString) -> bool {
    use unicode_normalization::UnicodeNormalization;
    let normalize = |value: &str| value.nfc().collect::<String>().to_lowercase();
    right
        .as_str()
        .is_some_and(|right| normalize(left) == normalize(right))
}
