use crate::AdapterRecord;
use crate::user_validation::{PreparedUserCreation, UserValidationSource};
use crate::{AuthError, AuthResult, AuthSchema, CreateUser, ListUsersParams, UpdateUser};
use async_trait::async_trait;
/// Numeric binding used when a registered user text field accepts a JSON number.
/// The HTTP caller first rounds it to a JavaScript number, preserving negative zero.
#[derive(Clone, Copy, Debug)]
pub enum NumericTextInput {
    Integer(i64),
    Real(f64),
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    /// Build an undecorated retained record without discarding physical scalar output.
    async fn native_user_record(&self, user: S::User) -> AuthResult<AdapterRecord<S::User>> {
        use crate::AuthUser as _;
        let scalars = self.native_user_output(&user.id()).await?;
        let mut record = AdapterRecord::physical(user)?;
        record.retain_native_scalars(scalars);
        Ok(record)
    }

    /// Retain native scalar output independently of typed authorization accessors.
    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, serde_json::Value>> {
        Ok(self
            .provider_verification_output(id)
            .await?
            .map(|value| ("emailVerified".to_owned(), value))
            .into_iter()
            .collect())
    }

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
    ) -> AuthResult<AdapterRecord<S::User>> {
        self.native_user_record(self.create_user(create_user).await?)
            .await
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<AdapterRecord<S::User>> {
        self.native_user_record(self.create_user_with_source(create_user, source).await?)
            .await
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<AdapterRecord<S::User>> {
        self.native_user_record(self.create_user_prepared(prepared).await?)
            .await
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_id_record(&self, id: &str) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match self.get_user_by_id(id).await? {
            Some(user) => self.native_user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_email_record(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match self
            .get_user_by_email(&crate::utils::json::JsString::from(email))
            .await?
        {
            Some(user) => self.native_user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match self.get_user_by_username(username).await? {
            Some(user) => self.native_user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match self.get_user_by_phone_number(phone_number).await? {
            Some(user) => self.native_user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for user in self.list_users_by_ids(ids).await? {
            records.push(self.native_user_record(user).await?);
        }
        Ok(records)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for user in self.list_users_by_ids_page(ids, limit).await? {
            records.push(self.native_user_record(user).await?);
        }
        Ok(records)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<AdapterRecord<S::User>> {
        self.native_user_record(self.update_user(id, update).await?)
            .await
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_record(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<AdapterRecord<S::User>>, usize)> {
        let (models, count) = self.list_users(params).await?;
        let mut records = Vec::new();
        for user in models {
            records.push(self.native_user_record(user).await?);
        }
        Ok((records, count))
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
    async fn get_user_by_email(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    /// Look up an untyped username using the adapter's actual parameter semantics.
    async fn get_user_by_username_value(
        &self,
        username: &crate::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        if let Some(username) = username.as_str() {
            return self.get_user_by_username(username).await;
        }
        Err(AuthError::NotImplemented(
            "Raw username lookup is unsupported by this store".into(),
        ))
    }
    async fn get_user_by_phone_number(&self, _phone_number: &str) -> AuthResult<Option<S::User>> {
        Err(AuthError::internal(
            "phone-number lookup is not supported by this store",
        ))
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
}
