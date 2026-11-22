//! Canonical JSON metadata and explicit database binding preparation.
use alibi_core::store::adapter::json_metadata::{MetadataCell, MetadataFormat, MetadataParameter};
use alibi_core::{
    AuthResult,
    utils::json::{self, JsValue},
};

/// JSON metadata stored with the backend's physical representation.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct JsonMetadata(MetadataCell);

fn format(backend: sea_orm::DbBackend) -> MetadataFormat {
    if backend == sea_orm::DbBackend::Sqlite {
        MetadataFormat::Sqlite
    } else {
        MetadataFormat::NativeJson
    }
}

impl JsonMetadata {
    pub(crate) fn for_backend(
        value: JsValue,
        backend: sea_orm::DbBackend,
    ) -> Result<Self, serde_json::Error> {
        MetadataCell::for_format(value, format(backend)).map(Self)
    }

    /// Logical metadata after the adapter's read codec has run.
    pub fn to_js_value(&self) -> JsValue {
        self.0.logical_value()
    }

    fn prepared(self, backend: sea_orm::DbBackend) -> Result<Self, serde_json::Error> {
        self.0.prepare(format(backend)).map(Self)
    }
}

impl TryFrom<JsValue> for JsonMetadata {
    type Error = serde_json::Error;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        MetadataCell::try_from(value).map(Self)
    }
}

impl From<serde_json::Value> for JsonMetadata {
    fn from(value: serde_json::Value) -> Self {
        Self(MetadataCell::from(value))
    }
}
impl TryFrom<JsonMetadata> for serde_json::Value {
    type Error = serde_json::Error;
    fn try_from(value: JsonMetadata) -> Result<Self, Self::Error> {
        value.to_js_value().to_json_value()
    }
}
impl From<&JsonMetadata> for JsValue {
    fn from(value: &JsonMetadata) -> Self {
        value.to_js_value()
    }
}
impl From<JsonMetadata> for JsValue {
    fn from(value: JsonMetadata) -> Self {
        value.to_js_value()
    }
}
impl sea_orm::TryGetable for JsonMetadata {
    fn try_get_by<I: sea_orm::ColIdx>(
        result: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        if let Some(row) = result.try_as_pg_row() {
            use sea_orm::sqlx::{Row, Type, ValueRef};
            let raw = row
                .try_get_raw(index.as_sqlx_postgres_index())
                .map_err(|error| {
                    sea_orm::TryGetError::DbErr(sea_orm::DbErr::Custom(error.to_string()))
                })?;
            if <String as Type<sea_orm::sqlx::Postgres>>::compatible(&raw.type_info()) {
                let text = String::try_get_by(result, index)?;
                return Ok(Self(MetadataCell::stored_text(text)));
            }
        }
        if let Some(row) = result.try_as_sqlite_row() {
            use sea_orm::sqlx::{Row, TypeInfo, ValueRef};
            let raw = row
                .try_get_raw(index.as_sqlx_sqlite_index())
                .map_err(|error| {
                    sea_orm::TryGetError::DbErr(sea_orm::DbErr::Custom(error.to_string()))
                })?;
            let value = match raw.type_info().name() {
                "INTEGER" => JsValue::from(i64::try_get_by(result, index)?),
                "REAL" => JsValue::Number(f64::try_get_by(result, index)?),
                "TEXT" => {
                    let text = String::try_get_by(result, index)?;
                    return Ok(Self(MetadataCell::stored_text(text)));
                }
                "NULL" => return Err(sea_orm::TryGetError::Null(format!("{index:?}"))),
                kind => {
                    return Err(sea_orm::TryGetError::DbErr(sea_orm::DbErr::Custom(
                        format!("Unsupported SQLite JSON storage type {kind}"),
                    )));
                }
            };
            Self::try_from(value).map_err(|error| {
                sea_orm::TryGetError::DbErr(sea_orm::DbErr::Custom(error.to_string()))
            })
        } else {
            Ok(Self::from(serde_json::Value::try_get_by(result, index)?))
        }
    }
}
impl From<JsonMetadata> for sea_orm::Value {
    fn from(value: JsonMetadata) -> Self {
        match value.0.into_parameter() {
            MetadataParameter::Text(text) => Self::String(Some(text)),
            MetadataParameter::Scalar(value) => crate::additional_fields::bind_scalar(
                alibi_core::store::adapter::RawFieldValue::from_js(&value)
                    .expect("scalar metadata has no undefined"),
            )
            .expect("scalar metadata has no object"),
            MetadataParameter::Json(value) => Self::Json(value),
        }
    }
}
impl sea_orm::sea_query::ValueType for JsonMetadata {
    fn try_from(value: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match value {
            sea_orm::Value::Json(Some(value)) => Ok(Self(MetadataCell::stored_json(*value))),
            sea_orm::Value::String(Some(text)) => Ok(Self(MetadataCell::stored_text(text))),
            sea_orm::Value::BigInt(Some(value)) => {
                <Self as TryFrom<JsValue>>::try_from(JsValue::from(value))
                    .map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            sea_orm::Value::Double(Some(value)) => {
                <Self as TryFrom<JsValue>>::try_from(JsValue::Number(value))
                    .map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            sea_orm::Value::Bool(Some(value)) => {
                <Self as TryFrom<JsValue>>::try_from(JsValue::Bool(value))
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
impl sea_orm::IntoActiveValue<Self> for JsonMetadata {
    fn into_active_value(self) -> sea_orm::ActiveValue<Self> {
        sea_orm::ActiveValue::set(self)
    }
}

/// Prepare a model field for its configured backend after application hooks.
pub trait MetadataBinding: Sized {
    fn prepare(self, backend: sea_orm::DbBackend) -> AuthResult<Self>;
}
impl MetadataBinding for serde_json::Value {
    fn prepare(self, _: sea_orm::DbBackend) -> AuthResult<Self> {
        Ok(json::to_value(&self)?)
    }
}
impl MetadataBinding for JsonMetadata {
    fn prepare(self, backend: sea_orm::DbBackend) -> AuthResult<Self> {
        Ok(self.prepared(backend)?)
    }
}
impl<T: MetadataBinding> MetadataBinding for Option<T> {
    fn prepare(self, backend: sea_orm::DbBackend) -> AuthResult<Self> {
        self.map(|value| value.prepare(backend)).transpose()
    }
}
