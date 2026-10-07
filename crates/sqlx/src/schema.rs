//! `SQLx` model bindings for Alibi schemas.

use crate::model::{ActiveRow, SqlxModel};
use crate::pool::Engine;
use crate::value::SqlValue;
use alibi_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use alibi_core::error::AuthResult;
pub use alibi_core::schema::AuthSchema;
use alibi_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::{DateTime, Utc};

pub trait SqlxUserModel: AuthUser + SqlxModel {
    /// Bind configured fields to actual model columns while retaining raw numbers.
    ///
    /// # Errors
    ///
    /// Returns an error if configured additional fields cannot be bound to model columns.
    fn additional_field_bindings(
        fields: &alibi_core::field_policy::FieldValues,
        _backend: Engine,
    ) -> AuthResult<Vec<(&'static str, SqlValue)>> {
        if fields.is_empty() {
            return Ok(Vec::new());
        }
        Err(alibi_core::AuthError::internal(
            "the user schema has no additional field bindings",
        ))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the field value is unsupported by the model column.
    fn set_additional_field(
        _active: &mut ActiveRow,
        _column: &'static str,
        _value: SqlValue,
        _backend: Engine,
    ) -> AuthResult<()> {
        Err(alibi_core::AuthError::internal(
            "the user schema cannot stage additional fields",
        ))
    }

    fn id_column() -> &'static str;

    fn email_column() -> &'static str;

    /// Returns the username column, or `None` if the username plugin is not enabled.
    #[must_use]
    fn username_column() -> Option<&'static str> {
        None
    }

    #[must_use]
    fn phone_number_column() -> Option<&'static str> {
        None
    }

    fn name_column() -> &'static str;

    fn created_at_column() -> &'static str;

    /// Bind an admin user-list field to its actual model column. Derived models
    /// provide all declared fields, including renamed physical columns. Manual
    /// models may add their plugin/application field bindings explicitly.
    #[must_use]
    fn list_users_column(field: &str) -> Option<&'static str> {
        match field {
            "id" => Some(Self::id_column()),
            "email" => Some(Self::email_column()),
            "name" => Some(Self::name_column()),
            "username" => Self::username_column(),
            "createdAt" => Some(Self::created_at_column()),
            _ => None,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is invalid for this model's ID type.
    fn parse_id(id: &str) -> AuthResult<SqlValue>;

    fn new_active(id: Option<SqlValue>, create_user: CreateUser, now: DateTime<Utc>) -> ActiveRow;

    fn apply_update(active: &mut ActiveRow, update: UpdateUser, now: DateTime<Utc>);

    /// Prepare JSON bindings after application hooks and before the atomic write.
    /// Manual model implementations may retain their existing binding behavior.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata preparation fails.
    fn prepare_json_metadata(_active: &mut ActiveRow, _backend: Engine) -> AuthResult<()> {
        Ok(())
    }
}

pub trait SqlxSessionModel: AuthSession + SqlxModel {
    /// Materialize the application model without a database insert.
    /// Custom schemas opt in to secondary-only sessions by implementing this binding.
    ///
    /// # Errors
    ///
    /// Returns `NotImplemented` unless the schema supports secondary sessions.
    fn materialize_secondary(_active: ActiveRow) -> AuthResult<Self> {
        Err(alibi_core::AuthError::NotImplemented(
            "Secondary session materialization is unsupported".into(),
        ))
    }

    /// Bind configured fields to actual model columns while retaining raw numbers.
    ///
    /// # Errors
    ///
    /// Returns an error if configured additional fields cannot be bound to model columns.
    fn additional_field_bindings(
        fields: &alibi_core::field_policy::FieldValues,
        _backend: Engine,
    ) -> AuthResult<Vec<(&'static str, SqlValue)>> {
        if fields.is_empty() {
            return Ok(Vec::new());
        }
        Err(alibi_core::AuthError::internal(
            "the session schema has no additional field bindings",
        ))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the field value is unsupported by the model column.
    fn set_additional_field(
        _active: &mut ActiveRow,
        _column: &'static str,
        _value: SqlValue,
        _backend: Engine,
    ) -> AuthResult<()> {
        Err(alibi_core::AuthError::internal(
            "the session schema cannot stage additional fields",
        ))
    }

    fn id_column() -> &'static str;

    fn token_column() -> &'static str;

    fn user_id_column() -> &'static str;

    fn active_column() -> &'static str;

    fn expires_at_column() -> &'static str;

    fn created_at_column() -> &'static str;

    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is invalid for this model's ID type.
    fn parse_id(id: &str) -> AuthResult<SqlValue>;

    ///
    /// # Errors
    ///
    /// Returns an error if the user identifier is invalid for this model's ID type.
    fn parse_user_id(user_id: &str) -> AuthResult<SqlValue>;

    fn new_active(
        id: Option<SqlValue>,
        token: String,
        create_session: CreateSession,
        now: DateTime<Utc>,
    ) -> ActiveRow;

    fn set_expires_at(active: &mut ActiveRow, expires_at: DateTime<Utc>);

    fn set_updated_at(active: &mut ActiveRow, updated_at: DateTime<Utc>);

    fn set_active_organization_id(active: &mut ActiveRow, organization_id: Option<String>);

    ///
    /// # Errors
    ///
    /// Returns an error if the configured model does not support an active-team field.
    fn set_active_team_id(active: &mut ActiveRow, team_id: Option<String>) -> AuthResult<()> {
        drop((active, team_id));
        Err(alibi_core::AuthError::internal(
            "the session schema has no active-team field",
        ))
    }
}

pub trait SqlxAccountModel: AuthAccount + SqlxModel {
    /// Bind configured fields to actual model columns while retaining raw numbers.
    ///
    /// # Errors
    ///
    /// Returns an error if configured additional fields cannot be bound to model columns.
    fn additional_field_bindings(
        fields: &alibi_core::field_policy::FieldValues,
        _backend: Engine,
    ) -> AuthResult<Vec<(&'static str, SqlValue)>> {
        if fields.is_empty() {
            return Ok(Vec::new());
        }
        Err(alibi_core::AuthError::internal(
            "the account schema has no additional field bindings",
        ))
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the field value is unsupported by the model column.
    fn set_additional_field(
        _active: &mut ActiveRow,
        _column: &'static str,
        _value: SqlValue,
        _backend: Engine,
    ) -> AuthResult<()> {
        Err(alibi_core::AuthError::internal(
            "the account schema cannot stage additional fields",
        ))
    }

    /// Physical access, refresh and ID token columns for operator conversion.
    /// Handwritten models opt in explicitly; absence fails closed.
    fn oauth_token_columns() -> Option<[&'static str; 3]> {
        None
    }

    fn id_column() -> &'static str;
    fn provider_id_column() -> &'static str;
    fn account_id_column() -> &'static str;
    fn user_id_column() -> &'static str;
    fn created_at_column() -> &'static str;
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is invalid for this model's ID type.
    fn parse_id(id: &str) -> AuthResult<SqlValue>;

    ///
    /// # Errors
    ///
    /// Returns an error if the user identifier is invalid for this model's ID type.
    fn parse_user_id(user_id: &str) -> AuthResult<SqlValue>;

    fn new_active(
        id: Option<SqlValue>,
        create_account: CreateAccount,
        now: DateTime<Utc>,
    ) -> ActiveRow;
    fn apply_update(active: &mut ActiveRow, update: UpdateAccount, now: DateTime<Utc>);
}

pub trait SqlxVerificationModel: AuthVerification + SqlxModel {
    fn id_column() -> &'static str;
    fn identifier_column() -> &'static str;
    fn value_column() -> &'static str;
    fn expires_at_column() -> &'static str;
    fn created_at_column() -> &'static str;
    #[must_use]
    fn updated_at_column() -> Option<&'static str> {
        None
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is invalid for this model's ID type.
    fn parse_id(id: &str) -> AuthResult<SqlValue>;

    /// Convert a deterministic reservation key to this schema's ID type.
    /// String schemas use the upstream key. UUID schemas can accept the UUID
    /// derived from the same digest; numeric schemas must explicitly provide
    /// a collision-resistant reservation strategy instead of truncating it.
    ///
    /// # Errors
    ///
    /// Returns an error if the reservation identifier is invalid for this model's ID type.
    fn parse_reservation_id(encoded: &str, digest: [u8; 32]) -> AuthResult<SqlValue> {
        if let Ok(id) = Self::parse_id(encoded) {
            return Ok(id);
        }
        let mut bytes = [0; 16];
        for (byte, source) in bytes.iter_mut().zip(digest) {
            *byte = source;
        }
        Self::parse_id(&uuid::Uuid::from_bytes(bytes).to_string()).map_err(|_error| {
            alibi_core::AuthError::internal(
                "the verification schema cannot represent deterministic reservation IDs",
            )
        })
    }

    fn new_active(
        id: Option<SqlValue>,
        verification: CreateVerification,
        now: DateTime<Utc>,
    ) -> ActiveRow;
}
