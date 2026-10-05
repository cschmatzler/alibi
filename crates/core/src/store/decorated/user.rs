use super::*;
#[async_trait]
impl<S: AuthSchema> UserStore<S> for PluginStore<S> {
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        self.inner.provider_verification_output(id).await
    }

    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
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
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
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
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user_prepared(prepared).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_user_by_id_record(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_id(id).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_email_record(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_email(email).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_username(username).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_phone_number(phone_number).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for model in self.list_users_by_ids(ids).await? {
            records.push(self.user_record(model).await?);
        }
        Ok(records)
    }

    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for model in self.list_users_by_ids_page(ids, limit).await? {
            records.push(self.user_record(model).await?);
        }
        Ok(records)
    }

    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
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
    ) -> AuthResult<(Vec<crate::AdapterRecord<S::User>>, usize)> {
        let (models, count) = self.list_users(params).await?;
        let mut records = Vec::new();
        for model in models {
            records.push(self.user_record(model).await?);
        }
        Ok((records, count))
    }

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        self.field_policies()
            .user
            .attach(&mut create_user.additional_fields, true);
        if self.config.user_validation.is_some() {
            let prepared = prepare_creation(&self.config, create_user, None).await?;
            return self.create_user_prepared(prepared).await;
        }
        let create_user = create_data(create_user, &self.transforms.creates)?;
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
        let mut data = create_data(prepared.into_data(), &self.transforms.creates)?;
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
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_phone_number(phone_number).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        let mut update = update;
        self.field_policies()
            .user
            .attach(&mut update.additional_fields, false);
        for transform in &self.transforms.updates {
            update = transform(id, update)?;
        }
        let user = self.inner.update_user(id, update).await?;
        if self.refresh_cached_user(&user).await.is_err() {
            tracing::error!("Failed to refresh committed user sessions in secondary storage");
        }
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let tokens = self.cached_user_tokens(id).await?;
        self.inner.delete_user(id).await?;
        self.remove_cached_user_sessions(id, tokens).await?;
        Ok(())
    }
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        self.inner.list_users(params).await
    }
}
