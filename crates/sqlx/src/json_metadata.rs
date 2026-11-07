//! Canonical JSON metadata and explicit database binding preparation.
use crate::pool::Engine;
use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use alibi_core::{
    error::AuthResult,
    utils::json::{self, JsValue},
};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
#[cfg(feature = "postgres")]
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres};
#[cfg(feature = "sqlite")]
use sqlx::sqlite::{Sqlite, SqliteArgumentsBuffer, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Decode, Encode, Type, TypeInfo, ValueRef};

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
    pub(crate) fn for_backend(value: JsValue, backend: Engine) -> Result<Self, serde_json::Error> {
        if backend == Engine::Sqlite {
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

    pub(crate) fn to_plain_value(&self) -> Result<JsValue, serde_json::Error> {
        match (&self.0, &self.1) {
            (JsValue::String(text), JsonBinding::Read | JsonBinding::Prepared) => {
                json::parse_js_value(text)
            }
            _ => Ok(self.0.clone()),
        }
    }

    fn prepared(self, backend: Engine) -> Result<Self, serde_json::Error> {
        if backend == Engine::Sqlite && !matches!(self.1, JsonBinding::Native) {
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

impl SqlxValue for JsonMetadata {
    const KIND: ColumnKind = ColumnKind::Json;
    fn null() -> SqlValue {
        SqlValue::Json(None)
    }
    fn into_sql_value(self) -> SqlValue {
        match self.1 {
            JsonBinding::Text(text) => SqlValue::Text(Some(text)),
            JsonBinding::Scalar | JsonBinding::Read | JsonBinding::Prepared => {
                crate::additional_fields::bind_scalar(
                    alibi_core::store::adapter::RawFieldValue::from_js(&self.0)
                        .expect("scalar metadata has no undefined"),
                )
                .expect("scalar metadata has no object")
            }
            JsonBinding::Native if self.0.is_null() => SqlValue::Json(None),
            JsonBinding::Native => SqlValue::Json(Some(Box::new(
                self.0
                    .to_json_value()
                    .expect("native JSON binding was validated"),
            ))),
        }
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Json(Some(value)) => Ok(Self::from(*value)),
            SqlValue::Text(Some(text)) => {
                Ok(Self(JsValue::String(text.into()), JsonBinding::Prepared))
            }
            SqlValue::BigInt(Some(value)) => {
                Self::try_from(JsValue::from(value)).map_err(|_| ValueTypeError)
            }
            SqlValue::Double(Some(value)) => {
                Self::try_from(JsValue::Number(value)).map_err(|_| ValueTypeError)
            }
            SqlValue::Bool(Some(value)) => {
                Self::try_from(JsValue::Bool(value)).map_err(|_| ValueTypeError)
            }
            _ => Err(ValueTypeError),
        }
    }
    fn prepare(self, engine: Engine) -> AuthResult<Self> {
        Ok(self.prepared(engine)?)
    }
}
#[cfg(feature = "sqlite")]
impl Type<Sqlite> for JsonMetadata {
    fn type_info() -> SqliteTypeInfo {
        <sqlx::types::Json<Self> as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <sqlx::types::Json<Self> as Type<Sqlite>>::compatible(ty)
            || <i64 as Type<Sqlite>>::compatible(ty)
            || <f64 as Type<Sqlite>>::compatible(ty)
    }
}
#[cfg(feature = "sqlite")]
impl<'r> Decode<'r, Sqlite> for JsonMetadata {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        let native = match value.type_info().name() {
            "INTEGER" => JsValue::from(<i64 as Decode<'r, Sqlite>>::decode(value)?),
            "REAL" => JsValue::Number(<f64 as Decode<'r, Sqlite>>::decode(value)?),
            "TEXT" => {
                let text = <String as Decode<'r, Sqlite>>::decode(value)?;
                return Ok(Self(JsValue::String(text.into()), JsonBinding::Read));
            }
            kind => return Err(format!("Unsupported SQLite JSON storage type {kind}").into()),
        };
        Ok(Self::try_from(native)?)
    }
}
#[cfg(feature = "sqlite")]
impl Encode<'_, Sqlite> for JsonMetadata {
    fn encode_by_ref(&self, buf: &mut SqliteArgumentsBuffer) -> Result<IsNull, BoxDynError> {
        let value = self.clone().prepared(Engine::Sqlite)?;
        match value.1 {
            JsonBinding::Text(text) => <String as Encode<'_, Sqlite>>::encode(text, buf),
            JsonBinding::Scalar | JsonBinding::Read | JsonBinding::Prepared => match value.0 {
                JsValue::String(text) => {
                    <String as Encode<'_, Sqlite>>::encode(text.to_utf8_binding(), buf)
                }
                JsValue::Number(number) => <f64 as Encode<'_, Sqlite>>::encode(number, buf),
                JsValue::Bool(boolean) => <bool as Encode<'_, Sqlite>>::encode(boolean, buf),
                _ => unreachable!("metadata scalar bindings contain only primitives"),
            },
            JsonBinding::Native => unreachable!("SQLite preparation resolves native JSON bindings"),
        }
    }
}
#[cfg(feature = "postgres")]
impl Type<Postgres> for JsonMetadata {
    fn type_info() -> PgTypeInfo {
        <sqlx::types::Json<Self> as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Json<Self> as Type<Postgres>>::compatible(ty)
            || <String as Type<Postgres>>::compatible(ty)
    }
}
#[cfg(feature = "postgres")]
impl<'r> Decode<'r, Postgres> for JsonMetadata {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        if <String as Type<Postgres>>::compatible(&value.type_info()) {
            Ok(json::from_str(<&str as Decode<'r, Postgres>>::decode(
                value,
            )?)?)
        } else {
            <sqlx::types::Json<serde_json::Value> as Decode<'r, Postgres>>::decode(value)
                .map(|json| Self::from(json.0))
        }
    }
}
#[cfg(feature = "postgres")]
impl Encode<'_, Postgres> for JsonMetadata {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <serde_json::Value as Encode<'_, Postgres>>::encode(self.0.to_json_value()?, buf)
    }
}
