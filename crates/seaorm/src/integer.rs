//! INTEGER decoding across PostgreSQL's int4 and SQLite's 64-bit storage.
use sea_orm::sea_query::{ArrayType, ColumnType, Nullable, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, QueryResult, TryGetError, TryGetable, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Integer(pub i64);

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self(value)
    }
}
impl From<Integer> for Value {
    fn from(value: Integer) -> Self {
        Self::BigInt(Some(value.0))
    }
}
impl Nullable for Integer {
    fn null() -> Value {
        Value::BigInt(None)
    }
}
impl ValueType for Integer {
    fn try_from(value: Value) -> Result<Self, ValueTypeErr> {
        match value {
            Value::BigInt(Some(value)) => Ok(Self(value)),
            Value::Int(Some(value)) => Ok(Self(i64::from(value))),
            _ => Err(ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "Integer".into()
    }
    fn array_type() -> ArrayType {
        ArrayType::BigInt
    }
    fn column_type() -> ColumnType {
        ColumnType::Integer
    }
}
impl TryGetable for Integer {
    fn try_get_by<I: ColIdx>(result: &QueryResult, index: I) -> Result<Self, TryGetError> {
        i64::try_get_by(result, index)
            .map(Self)
            .or_else(|_| i32::try_get_by(result, index).map(|value| Self(i64::from(value))))
    }
}
