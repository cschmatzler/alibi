//! JSON metadata storage for bundled and application-owned `SeaORM` entities.
//!
//! Use `JsonMetadata` for metadata fields which must retain arbitrary object
//! keys on `SQLx` reads. Existing Value fields remain source-compatible but use
//! `serde_json`'s ordinary `SQLx` decoder. `AuthEntity` calls
//! [`MetadataBinding::prepare`] on Set metadata after application hooks and
//! before the store write; manual models can override
//! `SeaOrmUserModel::prepare_json_metadata` to choose their binding policy.

/// JSON storage preserving every application object key.
///
/// Convert through `From`; the SQL column remains JSON. SQLite writes bind JavaScript JSON text
/// directly because `SeaORM`'s intermediate Value cannot preserve every numeric spelling. Convert
/// to `Value` to edit and construct a new wrapper before preparation. The prepared value has no
/// mutable access, so its SQLite binding cannot become stale relative to its public JSON
/// serialization.
///
/// ```compile_fail
/// use alibi_seaorm::JsonMetadata;
/// let mut metadata = JsonMetadata::from(serde_json::json!({"version": "old"}));
/// metadata.0["version"] = serde_json::json!("edited");
/// ```
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct JsonMetadata(serde_json::Value, #[serde(skip)] Option<String>);

impl JsonMetadata {
    pub(crate) fn for_backend(
        value: serde_json::Value,
        backend: sea_orm::DbBackend,
    ) -> Result<Self, serde_json::Error> {
        let text = if backend == sea_orm::DbBackend::Sqlite {
            Some(alibi_core::utils::json::to_string(&value)?)
        } else {
            None
        };
        Ok(Self(value, text))
    }
}
impl PartialEq for JsonMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<'de> serde::Deserialize<'de> for JsonMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        alibi_core::utils::json::deserialize_value(deserializer).map(Self::from)
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
impl sea_orm::TryGetableFromJson for JsonMetadata {}
impl From<JsonMetadata> for sea_orm::Value {
    fn from(value: JsonMetadata) -> Self {
        match value.1 {
            Some(text) => Self::String(Some(text)),
            None => Self::Json(Some(Box::new(value.0))),
        }
    }
}
impl sea_orm::sea_query::ValueType for JsonMetadata {
    fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            sea_orm::Value::Json(Some(v)) => Ok(Self::from(*v)),
            sea_orm::Value::String(Some(text)) => {
                alibi_core::utils::json::from_slice::<serde_json::Value>(text.as_bytes())
                    .map(Self::from)
                    .map_err(|_error| sea_orm::sea_query::ValueTypeErr)
            }
            sea_orm::Value::Bool(_)
            | sea_orm::Value::TinyInt(_)
            | sea_orm::Value::SmallInt(_)
            | sea_orm::Value::Int(_)
            | sea_orm::Value::BigInt(_)
            | sea_orm::Value::TinyUnsigned(_)
            | sea_orm::Value::SmallUnsigned(_)
            | sea_orm::Value::Unsigned(_)
            | sea_orm::Value::BigUnsigned(_)
            | sea_orm::Value::Float(_)
            | sea_orm::Value::Double(_)
            | sea_orm::Value::String(_)
            | sea_orm::Value::Char(_)
            | sea_orm::Value::Bytes(_)
            | sea_orm::Value::Json(_)
            | sea_orm::Value::ChronoDate(_)
            | sea_orm::Value::ChronoTime(_)
            | sea_orm::Value::ChronoDateTime(_)
            | sea_orm::Value::ChronoDateTimeUtc(_)
            | sea_orm::Value::ChronoDateTimeLocal(_)
            | sea_orm::Value::ChronoDateTimeWithTimeZone(_)
            | sea_orm::Value::TimeDate(_)
            | sea_orm::Value::TimeTime(_)
            | sea_orm::Value::TimeDateTime(_)
            | sea_orm::Value::TimeDateTimeWithTimeZone(_)
            | sea_orm::Value::Uuid(_)
            | sea_orm::Value::Decimal(_)
            | sea_orm::Value::Enum(_)
            | sea_orm::Value::Array(..) => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "JsonMetadata".to_owned()
    }
    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::Json
    }
    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::Json
    }
}
impl sea_orm::sea_query::Nullable for JsonMetadata {
    fn null() -> sea_orm::Value {
        sea_orm::Value::Json(None)
    }
}
impl sea_orm::IntoActiveValue<Self> for JsonMetadata {
    fn into_active_value(self) -> sea_orm::ActiveValue<Self> {
        sea_orm::ActiveValue::set(self)
    }
}

impl std::ops::Deref for JsonMetadata {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A metadata field prepared for its configured database binding, after
/// application hooks and before the store write.
///
/// `serde_json::Value` fields are normalized; [`JsonMetadata`] additionally
/// preserves exact JavaScript JSON text on SQLite writes.
pub trait MetadataBinding: Sized {
    /// # Errors
    ///
    /// Returns an error if the value cannot be serialized for `backend`.
    fn prepare(self, backend: sea_orm::DbBackend) -> alibi_core::AuthResult<Self>;
}

impl MetadataBinding for serde_json::Value {
    fn prepare(self, _backend: sea_orm::DbBackend) -> alibi_core::AuthResult<Self> {
        Ok(alibi_core::utils::json::to_value(&self)?)
    }
}

impl MetadataBinding for JsonMetadata {
    fn prepare(self, backend: sea_orm::DbBackend) -> alibi_core::AuthResult<Self> {
        let value = alibi_core::utils::json::to_value(&self.0)?;
        Ok(Self::for_backend(value, backend)?)
    }
}

impl<T: MetadataBinding> MetadataBinding for Option<T> {
    fn prepare(self, backend: sea_orm::DbBackend) -> alibi_core::AuthResult<Self> {
        self.map(|value| value.prepare(backend)).transpose()
    }
}
