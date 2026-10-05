use super::*;
/// Numeric binding used when a registered user text field accepts a JSON number.
/// The HTTP caller first rounds it to a JavaScript number, preserving negative zero.
#[derive(Clone, Copy, Debug)]
pub enum NumericTextInput {
    Integer(i64),
    Real(f64),
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    /// Read the provider verification column using the adapter's physical scalar
    /// rules. This is retained output, not authorization input; typed models
    /// continue to supply the canonical boolean accessor.
    async fn provider_verification_output(
        &self,
        _id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        Ok(None)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user(create_user).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user_with_source(create_user, source).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user_prepared(prepared).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_id_record(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_id(id)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_email_record(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_email(email)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_username(username)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_phone_number(phone_number)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        self.list_users_by_ids(ids)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        self.list_users_by_ids_page(ids, limit)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.update_user(id, update).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_record(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::AdapterRecord<S::User>>, usize)> {
        let (models, count) = self.list_users(params).await?;
        Ok((
            models
                .into_iter()
                .map(crate::AdapterRecord::physical)
                .collect::<AuthResult<Vec<_>>>()?,
            count,
        ))
    }

    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    /// Create with endpoint-owned identity provenance, retaining the finalized
    /// instance's validation and database-hook ordering.
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        _source: UserValidationSource,
    ) -> AuthResult<S::User> {
        self.create_user(create_user).await
    }
    /// Persist a normalized, admitted candidate without normalizing trusted
    /// callback mutations again. Unsupported custom adapters fail closed.
    async fn create_user_prepared(&self, _prepared: PreparedUserCreation) -> AuthResult<S::User> {
        Err(AuthError::NotImplemented(
            "Prepared user creation is not supported by this store".into(),
        ))
    }
    /// Coerce a numeric binding with the configured adapter's text semantics.
    /// Custom adapters must implement this explicitly when accepting such input.
    async fn coerce_user_text_number(&self, _input: NumericTextInput) -> AuthResult<String> {
        Err(AuthError::NotImplemented(
            "Numeric user-field text coercion is not supported by this store".into(),
        ))
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>>;
    /// Fetch multiple users by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>>;
    /// Apply the adapter's raw numeric page to actual matching users. Unsupported
    /// stores fail closed rather than rounding, capping, or delegating to an unpaged read.
    async fn list_users_by_ids_page(
        &self,
        _ids: &[String],
        _limit: f64,
    ) -> AuthResult<Vec<S::User>> {
        Err(AuthError::NotImplemented(
            "Raw numeric user pages are not supported by this store".into(),
        ))
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_phone_number(&self, _phone_number: &str) -> AuthResult<Option<S::User>> {
        Err(AuthError::internal(
            "phone-number lookup is not supported by this store",
        ))
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
}
