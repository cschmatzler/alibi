//! SeaORM model bindings for Better Auth schemas.

use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult,
    IntoActiveModel, Value,
};

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};
use better_auth_core::error::AuthResult;
pub use better_auth_core::schema::AuthSchema;
use better_auth_core::types::{
    CreateAccount, CreateSession, CreateUser, CreateVerification, UpdateAccount, UpdateUser,
};

pub trait SeaOrmUserModel:
    AuthUser + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn email_column() -> Self::Column;
    /// Returns the username column, or `None` if the username plugin is not enabled.
    fn username_column() -> Option<Self::Column> {
        None
    }
    fn phone_number_column() -> Option<Self::Column> {
        None
    }
    fn name_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    /// Bind an admin user-list field to its actual model column. Derived models
    /// provide all declared fields, including renamed physical columns. Manual
    /// models may add their plugin/application field bindings explicitly.
    fn list_users_column(field: &str) -> Option<Self::Column> {
        match field {
            "id" => Some(Self::id_column()),
            "email" => Some(Self::email_column()),
            "name" => Some(Self::name_column()),
            "username" => Self::username_column(),
            "createdAt" => Some(Self::created_at_column()),
            _ => None,
        }
    }
    fn parse_id(id: &str) -> AuthResult<Self::Id>;

    fn new_active(
        id: Option<Self::Id>,
        create_user: CreateUser,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateUser, now: DateTime<Utc>);
    /// Prepare JSON bindings after application hooks and before the atomic write.
    /// Manual model implementations may retain their existing binding behavior.
    fn prepare_json_metadata(
        _active: &mut Self::ActiveModel,
        _backend: sea_orm::DbBackend,
    ) -> AuthResult<()> {
        Ok(())
    }
}

pub trait SeaOrmSessionModel:
    AuthSession + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    /// Bind configured fields to actual model columns while retaining raw numbers.
    fn additional_field_bindings(
        fields: &better_auth_core::field_policy::FieldValues,
        _backend: sea_orm::DbBackend,
    ) -> AuthResult<Vec<(Self::Column, Value)>> {
        if fields.is_empty() {
            return Ok(Vec::new());
        }
        Err(better_auth_core::AuthError::internal(
            "the session schema has no additional field bindings",
        ))
    }
    fn set_additional_field(
        _active: &mut Self::ActiveModel,
        _column: Self::Column,
        _value: Value,
        _backend: sea_orm::DbBackend,
    ) -> AuthResult<()> {
        Err(better_auth_core::AuthError::internal(
            "the session schema cannot stage additional fields",
        ))
    }
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type UserId: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn token_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn active_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;
    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;

    fn new_active(
        id: Option<Self::Id>,
        token: String,
        create_session: CreateSession,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>);
    fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>);
    fn set_active_organization_id(active: &mut Self::ActiveModel, organization_id: Option<String>);
    fn set_active_team_id(
        active: &mut Self::ActiveModel,
        team_id: Option<String>,
    ) -> AuthResult<()> {
        let _ = (active, team_id);
        Err(better_auth_core::AuthError::internal(
            "the session schema has no active-team field",
        ))
    }
}

pub trait SeaOrmAccountModel:
    AuthAccount + IntoActiveModel<Self::ActiveModel> + Clone + Send + Sync + 'static + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type UserId: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn provider_id_column() -> Self::Column;
    fn account_id_column() -> Self::Column;
    fn user_id_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn parse_id(id: &str) -> AuthResult<Self::Id>;

    fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId>;

    fn new_active(
        id: Option<Self::Id>,
        create_account: CreateAccount,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
    fn apply_update(active: &mut Self::ActiveModel, update: UpdateAccount, now: DateTime<Utc>);
}

pub trait SeaOrmVerificationModel:
    AuthVerification
    + IntoActiveModel<Self::ActiveModel>
    + Clone
    + Send
    + Sync
    + 'static
    + FromQueryResult
{
    type Id: Clone + Into<Value> + Send + Sync + 'static;
    type Entity: EntityTrait<Model = Self>;
    type ActiveModel: ActiveModelTrait<Entity = Self::Entity> + ActiveModelBehavior + Send;
    type Column: ColumnTrait;

    fn id_column() -> Self::Column;
    fn identifier_column() -> Self::Column;
    fn value_column() -> Self::Column;
    fn expires_at_column() -> Self::Column;
    fn created_at_column() -> Self::Column;
    fn updated_at_column() -> Option<Self::Column> {
        None
    }
    fn parse_id(id: &str) -> AuthResult<Self::Id>;

    /// Convert a deterministic reservation key to this schema's ID type.
    /// String schemas use the upstream key. UUID schemas can accept the UUID
    /// derived from the same digest; numeric schemas must explicitly provide
    /// a collision-resistant reservation strategy instead of truncating it.
    fn parse_reservation_id(encoded: &str, digest: [u8; 32]) -> AuthResult<Self::Id> {
        if let Ok(id) = Self::parse_id(encoded) {
            return Ok(id);
        }
        let mut bytes = [0; 16];
        for (byte, source) in bytes.iter_mut().zip(digest) {
            *byte = source;
        }
        Self::parse_id(&uuid::Uuid::from_bytes(bytes).to_string()).map_err(|_| {
            better_auth_core::AuthError::internal(
                "the verification schema cannot represent deterministic reservation IDs",
            )
        })
    }

    fn new_active(
        id: Option<Self::Id>,
        verification: CreateVerification,
        now: DateTime<Utc>,
    ) -> Self::ActiveModel;
}
