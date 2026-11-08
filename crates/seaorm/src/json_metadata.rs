//! Canonical JSON metadata and explicit database binding preparation.
use alibi_core::{
    AuthResult,
    utils::json::{self, JsValue},
};

/// Canonical JSON metadata with a deferred SQLite storage cell.
/// Initialized output policies use the physical cell before their callback; ordinary
/// model getters and serialization use the decoded logical value. Native JSON
/// backends validate their strict ordinary projection only when binding.
#[derive(Clone, Debug)]
pub struct JsonMetadata(JsValue, JsonBinding);

impl serde::Serialize for JsonMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_js_value().serialize(serializer)
    }
}

#[derive(Clone, Debug)]
enum JsonBinding {
    Text(String),
    Read,
    Prepared,
    Scalar,
    Native,
}

impl JsonMetadata {
    pub(crate) fn for_backend(
        value: JsValue,
        backend: sea_orm::DbBackend,
    ) -> Result<Self, serde_json::Error> {
        if backend == sea_orm::DbBackend::Sqlite {
            Self::try_from(value)
        } else {
            let _ = value.to_json_value()?;
            Ok(Self(value, JsonBinding::Native))
        }
    }
    /// Logical metadata for non-policy consumers (organization/OAuth resources,
    /// model getters and DTO serialization), never an encoded SQLite JSON cell.
    pub fn to_js_value(&self) -> JsValue {
        match (&self.0, &self.1) {
            (JsValue::String(text), JsonBinding::Read | JsonBinding::Prepared) => {
                json::parse_adapter_string(text)
            }
            _ => self.0.clone(),
        }
    }

    fn prepared(self, backend: sea_orm::DbBackend) -> Result<Self, serde_json::Error> {
        if backend == sea_orm::DbBackend::Sqlite && !matches!(self.1, JsonBinding::Native) {
            return Ok(self);
        }
        let value = match self.1 {
            JsonBinding::Text(text) => json::parse_value(&text)?,
            JsonBinding::Read | JsonBinding::Prepared => self.to_js_value(),
            _ => self.0,
        };
        Self::for_backend(value, backend)
    }
}
impl PartialEq for JsonMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.to_js_value() == other.to_js_value()
    }
}
impl<'de> serde::Deserialize<'de> for JsonMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(JsValue::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl TryFrom<JsValue> for JsonMetadata {
    type Error = serde_json::Error;
    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        let binding = match &value {
            JsValue::Undefined => {
                return Err(serde::ser::Error::custom(
                    "cannot bind undefined JSON metadata",
                ));
            }
            JsValue::Null | JsValue::Array(_) | JsValue::Object(_) | JsValue::Date(_) => {
                JsonBinding::Text(json::to_string(&value)?)
            }
            _ => JsonBinding::Scalar,
        };
        Ok(Self(value, binding))
    }
}
impl From<serde_json::Value> for JsonMetadata {
    fn from(value: serde_json::Value) -> Self {
        Self::try_from(JsValue::from(value)).expect("ordinary JSON contains no undefined root")
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
                return Ok(Self(JsValue::String(text.into()), JsonBinding::Read));
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
                    return Ok(Self(JsValue::String(text.into()), JsonBinding::Read));
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
        match value.1 {
            JsonBinding::Text(text) => Self::String(Some(text)),
            JsonBinding::Scalar | JsonBinding::Read | JsonBinding::Prepared => {
                crate::additional_fields::bind_scalar(
                    alibi_core::store::adapter::RawFieldValue::from_js(&value.0)
                        .expect("scalar metadata has no undefined"),
                )
                .expect("scalar metadata has no object")
            }
            JsonBinding::Native if value.0.is_null() => Self::Json(None),
            JsonBinding::Native => Self::Json(Some(Box::new(
                value
                    .0
                    .to_json_value()
                    .expect("native JSON binding was validated"),
            ))),
        }
    }
}
impl sea_orm::sea_query::ValueType for JsonMetadata {
    fn try_from(value: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match value {
            sea_orm::Value::Json(Some(value)) => {
                Ok(Self(JsValue::from(*value), JsonBinding::Native))
            }
            sea_orm::Value::String(Some(text)) => {
                Ok(Self(JsValue::String(text.into()), JsonBinding::Prepared))
            }
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
