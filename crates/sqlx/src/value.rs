//! Typed SQL values bound to `SQLx` arguments.
//!
//! Every variant carries its own nullable type, so PostgreSQL receives a typed
//! `NULL` for each column rather than an untyped text parameter.

use crate::pool::Engine;
use better_auth_core::error::AuthResult;
use chrono::{DateTime, NaiveDateTime, Utc};

/// A typed value bound to one SQL parameter.
#[derive(Clone, Debug, PartialEq)]
pub enum SqlValue {
    Bool(Option<bool>),
    Int(Option<i32>),
    BigInt(Option<i64>),
    Float(Option<f32>),
    Double(Option<f64>),
    Text(Option<String>),
    /// PostgreSQL fixed-width character value (`bpchar`), including typed NULL.
    /// Other engines bind the exact string as ordinary text.
    BpChar(Option<String>),
    Bytes(Option<Vec<u8>>),
    Json(Option<Box<serde_json::Value>>),
    /// Timezone-aware timestamp (PostgreSQL `TIMESTAMPTZ`).
    Timestamp(Option<DateTime<Utc>>),
    /// UTC wall-clock timestamp (PostgreSQL `TIMESTAMP WITHOUT TIME ZONE`).
    NaiveTimestamp(Option<NaiveDateTime>),
    Uuid(Option<uuid::Uuid>),
}

impl SqlValue {
    /// Whether this value binds SQL `NULL`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(
            self,
            Self::Bool(None)
                | Self::Int(None)
                | Self::BigInt(None)
                | Self::Float(None)
                | Self::Double(None)
                | Self::Text(None)
                | Self::BpChar(None)
                | Self::Bytes(None)
                | Self::Json(None)
                | Self::Timestamp(None)
                | Self::NaiveTimestamp(None)
                | Self::Uuid(None)
        )
    }
}

macro_rules! sql_value_from {
    ($($type:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$type> for SqlValue {
                fn from(value: $type) -> Self {
                    Self::$variant(Some(value))
                }
            }
            impl From<Option<$type>> for SqlValue {
                fn from(value: Option<$type>) -> Self {
                    Self::$variant(value)
                }
            }
        )*
    };
}

sql_value_from!(
    bool => Bool,
    i32 => Int,
    i64 => BigInt,
    f32 => Float,
    f64 => Double,
    String => Text,
    Vec<u8> => Bytes,
    DateTime<Utc> => Timestamp,
    NaiveDateTime => NaiveTimestamp,
    uuid::Uuid => Uuid,
);

impl From<&str> for SqlValue {
    fn from(value: &str) -> Self {
        Self::Text(Some(value.to_owned()))
    }
}

impl From<Option<&str>> for SqlValue {
    fn from(value: Option<&str>) -> Self {
        Self::Text(value.map(str::to_owned))
    }
}

impl From<&String> for SqlValue {
    fn from(value: &String) -> Self {
        Self::Text(Some(value.clone()))
    }
}

impl From<serde_json::Value> for SqlValue {
    fn from(value: serde_json::Value) -> Self {
        Self::Json(Some(Box::new(value)))
    }
}

impl From<Option<serde_json::Value>> for SqlValue {
    fn from(value: Option<serde_json::Value>) -> Self {
        Self::Json(value.map(Box::new))
    }
}

/// Storage category of a model column, derived from its Rust field type.
///
/// Configured additional fields use it to coerce raw JavaScript values before
/// binding, exactly as the `SeaORM` adapter coerces by its column type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnKind {
    /// `String`, `char` and text columns: values use the backend's TEXT cast.
    Text,
    /// JSON documents.
    Json,
    /// String-backed PostgreSQL `CHAR(n)`; opt in per model column.
    BpChar,
    /// `f64` columns.
    Double,
    /// `f32` columns.
    Float,
    /// `bool` columns.
    Boolean,
    /// Integers, timestamps, bytes, UUIDs and custom values: bound unchanged.
    Other,
    /// UTC wall-clock timestamps, bound as PostgreSQL `TIMESTAMP`.
    NaiveTimestamp,
}

/// Failure to represent a bound value as a model field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueTypeError;

impl std::fmt::Display for ValueTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("value cannot be represented by its model field")
    }
}

impl std::error::Error for ValueTypeError {}

/// A model field type which converts to and from a bound [`SqlValue`].
///
/// Conversions preserve the field representation: strings accept TEXT and
/// explicitly selected bpchar values; optional fields accept their typed `NULL`. `AuthEntity` uses this to stage
/// additional fields and to materialize models without a database round trip.
pub trait SqlxValue: Sized {
    /// The column category used to coerce configured raw values.
    const KIND: ColumnKind;

    /// The typed `NULL` of this field type.
    fn null() -> SqlValue;

    fn into_sql_value(self) -> SqlValue;

    /// # Errors
    ///
    /// Returns an error if the value has a different type.
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError>;

    /// Prepare a staged value for `engine`, after application hooks and
    /// before the write. JSON metadata binds exact JavaScript text on SQLite;
    /// every other value is bound unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be serialized for `engine`.
    fn prepare(self, engine: Engine) -> AuthResult<Self> {
        let _ = engine;
        Ok(self)
    }
}

macro_rules! sqlx_value {
    ($($type:ty => $variant:ident, $kind:ident),* $(,)?) => {
        $(
            impl SqlxValue for $type {
                const KIND: ColumnKind = ColumnKind::$kind;
                fn null() -> SqlValue {
                    SqlValue::$variant(None)
                }
                fn into_sql_value(self) -> SqlValue {
                    SqlValue::$variant(Some(self))
                }
                fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
                    match value {
                        SqlValue::$variant(Some(value)) => Ok(value),
                        _ => Err(ValueTypeError),
                    }
                }
            }
        )*
    };
}

sqlx_value!(
    bool => Bool, Boolean,
    i32 => Int, Other,
    i64 => BigInt, Other,
    f32 => Float, Float,
    f64 => Double, Double,
    Vec<u8> => Bytes, Other,
    DateTime<Utc> => Timestamp, Other,
    NaiveDateTime => NaiveTimestamp, NaiveTimestamp,
    uuid::Uuid => Uuid, Other,
);

impl SqlxValue for serde_json::Value {
    const KIND: ColumnKind = ColumnKind::Json;
    fn null() -> SqlValue {
        SqlValue::Json(None)
    }
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Json(Some(Box::new(self)))
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Json(Some(value)) => Ok(*value),
            _ => Err(ValueTypeError),
        }
    }
}

impl<T: SqlxValue> SqlxValue for Option<T> {
    const KIND: ColumnKind = T::KIND;
    fn null() -> SqlValue {
        T::null()
    }
    fn into_sql_value(self) -> SqlValue {
        self.map_or_else(T::null, T::into_sql_value)
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        if value == T::null()
            || matches!(
                (&value, T::null()),
                (SqlValue::BpChar(None), SqlValue::Text(None))
            )
        {
            Ok(None)
        } else {
            T::from_sql_value(value).map(Some)
        }
    }
    fn prepare(self, engine: Engine) -> AuthResult<Self> {
        self.map(|value| value.prepare(engine)).transpose()
    }
}

impl SqlxValue for String {
    const KIND: ColumnKind = ColumnKind::Text;
    fn null() -> SqlValue {
        SqlValue::Text(None)
    }
    fn into_sql_value(self) -> SqlValue {
        SqlValue::Text(Some(self))
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Text(Some(value)) | SqlValue::BpChar(Some(value)) => Ok(value),
            _ => Err(ValueTypeError),
        }
    }
}
