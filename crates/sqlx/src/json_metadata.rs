//! JSON metadata storage for bundled and application-owned `SQLx` models.
//!
//! Use `JsonMetadata` for metadata fields which must retain arbitrary object
//! keys on reads. Existing `serde_json::Value` fields remain supported but use
//! `serde_json`'s ordinary decoder. `AuthEntity` prepares set metadata after
//! application hooks and before the store write; manual models can override
//! `SqlxUserModel::prepare_json_metadata` to choose their binding policy.

use crate::pool::SqlxBackend;
use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres};
use sqlx::sqlite::{Sqlite, SqliteArgumentsBuffer, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Decode, Encode, Type};

/// JSON storage preserving every application object key.
///
/// Convert through `From`; the SQL column remains JSON. SQLite writes bind JavaScript JSON text
/// directly so every numeric spelling is preserved. Convert to `Value` to edit and construct a
/// new wrapper before preparation. The prepared value has no mutable access, so its SQLite
/// binding cannot become stale relative to its public JSON serialization.
///
/// ```compile_fail
/// use better_auth_sqlx::JsonMetadata;
/// let mut metadata = JsonMetadata::from(serde_json::json!({"version": "old"}));
/// metadata.0["version"] = serde_json::json!("edited");
/// ```
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct JsonMetadata(serde_json::Value, #[serde(skip)] Option<String>);

impl JsonMetadata {
    pub(crate) fn for_backend(
        value: serde_json::Value,
        backend: SqlxBackend,
    ) -> Result<Self, serde_json::Error> {
        let text = if backend == SqlxBackend::Sqlite {
            Some(better_auth_core::utils::json::to_string(&value)?)
        } else {
            None
        };
        Ok(Self(value, text))
    }

    fn sqlite_text(&self) -> Result<String, serde_json::Error> {
        match &self.1 {
            Some(text) => Ok(text.clone()),
            None => serde_json::to_string(&self.0),
        }
    }
}

impl PartialEq for JsonMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'de> serde::Deserialize<'de> for JsonMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        better_auth_core::utils::json::deserialize_value(deserializer).map(Self::from)
    }
}

impl From<serde_json::Value> for JsonMetadata {
    fn from(value: serde_json::Value) -> Self {
        Self(value, None)
    }
}

impl From<JsonMetadata> for serde_json::Value {
    fn from(value: JsonMetadata) -> Self {
        value.0
    }
}

impl std::ops::Deref for JsonMetadata {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SqlxValue for JsonMetadata {
    const KIND: ColumnKind = ColumnKind::Json;
    fn null() -> SqlValue {
        SqlValue::Json(None)
    }
    fn into_sql_value(self) -> SqlValue {
        match self.1 {
            Some(text) => SqlValue::Text(Some(text)),
            None => SqlValue::Json(Some(Box::new(self.0))),
        }
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Json(Some(value)) => Ok(Self::from(*value)),
            SqlValue::Text(Some(text)) => {
                better_auth_core::utils::json::from_slice::<serde_json::Value>(text.as_bytes())
                    .map(Self::from)
                    .map_err(|_error| ValueTypeError)
            }
            SqlValue::Bool(_)
            | SqlValue::Int(_)
            | SqlValue::BigInt(_)
            | SqlValue::Float(_)
            | SqlValue::Double(_)
            | SqlValue::Text(None)
            | SqlValue::Bytes(_)
            | SqlValue::Json(None)
            | SqlValue::Timestamp(_)
            | SqlValue::NaiveTimestamp(_)
            | SqlValue::Uuid(_) => Err(ValueTypeError),
        }
    }
}

impl Type<Sqlite> for JsonMetadata {
    fn type_info() -> SqliteTypeInfo {
        <sqlx::types::Json<Self> as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <sqlx::types::Json<Self> as Type<Sqlite>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Sqlite> for JsonMetadata {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        <sqlx::types::Json<Self> as Decode<'r, Sqlite>>::decode(value).map(|json| json.0)
    }
}

impl Encode<'_, Sqlite> for JsonMetadata {
    fn encode_by_ref(&self, buf: &mut SqliteArgumentsBuffer) -> Result<IsNull, BoxDynError> {
        <String as Encode<'_, Sqlite>>::encode(self.sqlite_text()?, buf)
    }
}

impl Type<Postgres> for JsonMetadata {
    fn type_info() -> PgTypeInfo {
        <sqlx::types::Json<Self> as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Json<Self> as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for JsonMetadata {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        <sqlx::types::Json<Self> as Decode<'r, Postgres>>::decode(value).map(|json| json.0)
    }
}

impl Encode<'_, Postgres> for JsonMetadata {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <serde_json::Value as Encode<'_, Postgres>>::encode_by_ref(&self.0, buf)
    }
}

/// Prepare a native metadata field for its configured database binding.
///
/// Existing Value fields remain supported; `JsonMetadata` additionally preserves arbitrary keys on
/// reads and exact JavaScript JSON text on SQLite writes.
///
/// # Errors
///
/// Returns an error if metadata cannot be serialized for the selected backend.
pub fn prepare_metadata_value<T>(value: T, backend: SqlxBackend) -> better_auth_core::AuthResult<T>
where
    T: Into<serde_json::Value> + From<serde_json::Value> + 'static,
{
    let value = better_auth_core::utils::json::to_value(&value.into())?;
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<JsonMetadata>() {
        let prepared: Box<dyn std::any::Any> = Box::new(JsonMetadata::for_backend(value, backend)?);
        prepared
            .downcast::<T>()
            .map(|value_2| *value_2)
            .map_err(|_error| better_auth_core::AuthError::internal("Invalid JSON metadata type"))
    } else {
        Ok(T::from(value))
    }
}
