use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "organization")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: JsonMetadata,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// JSON storage preserving every application object key. Convert through `From`;
/// the SQL column remains JSON. SQLite writes bind JavaScript JSON text directly
/// because SeaORM's intermediate Value cannot preserve every numeric spelling.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub struct JsonMetadata(pub serde_json::Value, #[serde(skip)] Option<String>);

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
