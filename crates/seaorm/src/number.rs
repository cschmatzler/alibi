use sea_orm::entity::prelude::*;

/// Better Auth's number columns use SQLite INTEGER affinity.
///
/// SQLite may return either an integer or a real for the same column, including large JS chain
/// IDs. PostgreSQL returns its INTEGER as i32. Retain the value as a JS Number without requiring a
/// different persisted column type.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
#[serde(transparent)]
pub struct Number(pub f64);

impl From<f64> for Number {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl From<Number> for Value {
    fn from(value: Number) -> Self {
        // Keep the same bind type as NULL. PostgreSQL caches parameter types for a
        // prepared statement, so switching between DOUBLE and BIGINT corrupts values.
        Self::Double(Some(value.0))
    }
}

impl sea_orm::sea_query::Nullable for Number {
    fn null() -> Value {
        Value::Double(None)
    }
}

impl sea_orm::sea_query::ValueType for Number {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::Double(Some(v)) => Ok(Self(v)),
            Value::BigInt(Some(v)) => Ok(Self(v as f64)),
            Value::Int(Some(v)) => Ok(Self(f64::from(v))),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "Number".to_owned()
    }
    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::Double
    }
    fn column_type() -> ColumnType {
        ColumnType::Integer
    }
}

impl sea_orm::TryGetable for Number {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        f64::try_get_by(res, index)
            .map(Self)
            .or_else(|_| i64::try_get_by(res, index).map(|value| Self(value as f64)))
            .or_else(|_| i32::try_get_by(res, index).map(|value| Self(f64::from(value))))
    }
}
