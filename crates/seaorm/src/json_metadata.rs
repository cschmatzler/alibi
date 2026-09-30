//! JSON metadata storage for bundled and application-owned SeaORM entities.
//!
//! Use `JsonMetadata` for metadata fields which must retain arbitrary object
//! keys on SQLx reads. Existing Value fields remain source-compatible but use
//! serde_json's ordinary SQLx decoder. `AuthEntity` prepares Set metadata after
//! application hooks and before the store write; manual models can override
//! `SeaOrmUserModel::prepare_json_metadata` to choose their binding policy.

/// JSON storage preserving every application object key. Convert through `From`;
/// the SQL column remains JSON. SQLite writes bind JavaScript JSON text directly
/// because SeaORM's intermediate Value cannot preserve every numeric spelling.
/// Convert to `Value` to edit and construct a new wrapper before preparation.
/// The prepared value has no mutable access, so its SQLite binding cannot become
/// stale relative to its public JSON serialization.
///
/// ```compile_fail
/// use better_auth_seaorm::JsonMetadata;
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
            Some(better_auth_core::utils::json::to_string(&value)?)
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
    fn try_from(value: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match value {
            sea_orm::Value::Json(Some(value)) => Ok(Self::from(*value)),
            sea_orm::Value::String(Some(text)) => {
                better_auth_core::utils::json::from_slice::<serde_json::Value>(text.as_bytes())
                    .map(Self::from)
                    .map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            _ => Err(sea_orm::sea_query::ValueTypeErr),
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
impl sea_orm::IntoActiveValue<JsonMetadata> for JsonMetadata {
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

/// Prepare a native metadata field for its configured database binding. Existing
/// Value fields remain supported; JsonMetadata additionally preserves arbitrary
/// keys on SQLx reads and exact JavaScript JSON text on SQLite writes.
pub fn prepare_metadata_value<T>(
    value: T,
    backend: sea_orm::DbBackend,
) -> better_auth_core::AuthResult<T>
where
    T: Into<serde_json::Value> + From<serde_json::Value> + 'static,
{
    let value = better_auth_core::utils::json::to_value(&value.into())?;
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<JsonMetadata>() {
        let prepared: Box<dyn std::any::Any> = Box::new(JsonMetadata::for_backend(value, backend)?);
        prepared
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| better_auth_core::AuthError::internal("Invalid JSON metadata type"))
    } else {
        Ok(T::from(value))
    }
}
