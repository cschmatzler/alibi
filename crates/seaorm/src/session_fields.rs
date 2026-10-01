//! Raw configured values staged on actual session entity columns.
use better_auth_core::{AuthError, AuthResult, utils::json::JsValue};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, Statement, Value, sea_query::ColumnType};

/// Called by generated model bindings before any backend affinity conversion.
///
/// # Errors
///
/// Returns an error if an object or array cannot be serialized as JSON.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub fn raw_value(value: &JsValue) -> AuthResult<Value> {
    Ok(match value {
        JsValue::Null => Value::String(None),
        JsValue::Bool(value) => Value::Bool(Some(*value)),
        JsValue::Number(value)
            if value.is_finite()
                && value.fract() == 0.0
                && !(*value == 0.0 && value.is_sign_negative())
                && (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0).contains(value) =>
        {
            Value::BigInt(Some(*value as i64))
        }
        JsValue::Number(value) => Value::Double(Some(*value)),
        JsValue::String(value) => Value::String(Some(value.clone())),
        JsValue::Array(_) | JsValue::Object(_) => {
            Value::Json(Some(Box::new(value.to_json_value()?)))
        }
    })
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep backend-specific JSON and numeric binding decisions together at the adapter boundary"
)]
pub(crate) async fn prepare_value<C: ConnectionTrait>(
    db: &C,
    column: &impl ColumnTrait,
    value: Value,
) -> AuthResult<Value> {
    let backend = db.get_database_backend();
    match column.def().get_column_type() {
        ColumnType::Char(_) | ColumnType::String(_) | ColumnType::Text => {
            if let Value::String(_) = &value {
                return Ok(value);
            }
            let number = if let Value::Double(Some(number)) = &value {
                Some(*number)
            } else {
                None
            };
            if matches!(&value, Value::Json(_)) {
                return Err(AuthError::internal(
                    "object cannot bind to a scalar session field",
                ));
            }
            let sql = match backend {
                DbBackend::Sqlite => "SELECT CAST(? AS TEXT) AS value",
                DbBackend::Postgres => "SELECT CAST($1 AS TEXT) AS value",
                DbBackend::MySql => "SELECT CAST(? AS CHAR) AS value",
                _ => {
                    return Err(AuthError::internal(
                        "session TEXT affinity is unsupported by this backend",
                    ));
                }
            };
            let row = db
                .query_one_raw(Statement::from_sql_and_values(backend, sql, [value]))
                .await
                .map_err(crate::store::map_db_err)?
                .ok_or_else(|| AuthError::internal("session TEXT affinity returned no row"))?;
            let actual: Option<String> =
                row.try_get("", "value").map_err(crate::store::map_db_err)?;
            let text = match (backend, number) {
                (DbBackend::Sqlite, Some(number)) if number.is_finite() => {
                    Some(crate::store::sqlite_real_text(number))
                }
                _ => actual,
            };
            Ok(Value::String(text))
        }
        ColumnType::Json | ColumnType::JsonBinary => {
            let json = match value {
                Value::Bool(Some(value)) => serde_json::json!(value),
                Value::BigInt(Some(value)) => serde_json::json!(value),
                Value::Double(Some(value)) => serde_json::json!(value),
                Value::String(Some(value)) => serde_json::json!(value),
                Value::Json(Some(value)) => *value,
                Value::Bool(_)
                | Value::TinyInt(_)
                | Value::SmallInt(_)
                | Value::Int(_)
                | Value::BigInt(_)
                | Value::TinyUnsigned(_)
                | Value::SmallUnsigned(_)
                | Value::Unsigned(_)
                | Value::BigUnsigned(_)
                | Value::Float(_)
                | Value::Double(_)
                | Value::String(_)
                | Value::Char(_)
                | Value::Bytes(_)
                | Value::Json(_)
                | Value::ChronoDate(_)
                | Value::ChronoTime(_)
                | Value::ChronoDateTime(_)
                | Value::ChronoDateTimeUtc(_)
                | Value::ChronoDateTimeLocal(_)
                | Value::ChronoDateTimeWithTimeZone(_)
                | Value::TimeDate(_)
                | Value::TimeTime(_)
                | Value::TimeDateTime(_)
                | Value::TimeDateTimeWithTimeZone(_)
                | Value::Uuid(_)
                | Value::Decimal(_)
                | Value::Array(..) => serde_json::Value::Null,
            };
            Ok(crate::JsonMetadata::for_backend(json, backend)?.into())
        }
        ColumnType::Double => Ok(match value {
            Value::BigInt(Some(value)) => Value::Double(Some(value as f64)),
            Value::String(None) => Value::Double(None),
            other @ (Value::Bool(_)
            | Value::TinyInt(_)
            | Value::SmallInt(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::TinyUnsigned(_)
            | Value::SmallUnsigned(_)
            | Value::Unsigned(_)
            | Value::BigUnsigned(_)
            | Value::Float(_)
            | Value::Double(_)
            | Value::String(_)
            | Value::Char(_)
            | Value::Bytes(_)
            | Value::Json(_)
            | Value::ChronoDate(_)
            | Value::ChronoTime(_)
            | Value::ChronoDateTime(_)
            | Value::ChronoDateTimeUtc(_)
            | Value::ChronoDateTimeLocal(_)
            | Value::ChronoDateTimeWithTimeZone(_)
            | Value::TimeDate(_)
            | Value::TimeTime(_)
            | Value::TimeDateTime(_)
            | Value::TimeDateTimeWithTimeZone(_)
            | Value::Uuid(_)
            | Value::Decimal(_)
            | Value::Array(..)) => other,
        }),
        ColumnType::Float => Ok(match value {
            Value::BigInt(Some(value)) => Value::Float(Some(value as f32)),
            Value::Double(Some(value)) => Value::Float(Some(value as f32)),
            Value::String(None) => Value::Float(None),
            other @ (Value::Bool(_)
            | Value::TinyInt(_)
            | Value::SmallInt(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::TinyUnsigned(_)
            | Value::SmallUnsigned(_)
            | Value::Unsigned(_)
            | Value::BigUnsigned(_)
            | Value::Float(_)
            | Value::Double(_)
            | Value::String(_)
            | Value::Char(_)
            | Value::Bytes(_)
            | Value::Json(_)
            | Value::ChronoDate(_)
            | Value::ChronoTime(_)
            | Value::ChronoDateTime(_)
            | Value::ChronoDateTimeUtc(_)
            | Value::ChronoDateTimeLocal(_)
            | Value::ChronoDateTimeWithTimeZone(_)
            | Value::TimeDate(_)
            | Value::TimeTime(_)
            | Value::TimeDateTime(_)
            | Value::TimeDateTimeWithTimeZone(_)
            | Value::Uuid(_)
            | Value::Decimal(_)
            | Value::Array(..)) => other,
        }),
        ColumnType::Boolean => Ok(match value {
            Value::String(None) => Value::Bool(None),
            other @ (Value::Bool(_)
            | Value::TinyInt(_)
            | Value::SmallInt(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::TinyUnsigned(_)
            | Value::SmallUnsigned(_)
            | Value::Unsigned(_)
            | Value::BigUnsigned(_)
            | Value::Float(_)
            | Value::Double(_)
            | Value::String(_)
            | Value::Char(_)
            | Value::Bytes(_)
            | Value::Json(_)
            | Value::ChronoDate(_)
            | Value::ChronoTime(_)
            | Value::ChronoDateTime(_)
            | Value::ChronoDateTimeUtc(_)
            | Value::ChronoDateTimeLocal(_)
            | Value::ChronoDateTimeWithTimeZone(_)
            | Value::TimeDate(_)
            | Value::TimeTime(_)
            | Value::TimeDateTime(_)
            | Value::TimeDateTimeWithTimeZone(_)
            | Value::Uuid(_)
            | Value::Decimal(_)
            | Value::Array(..)) => other,
        }),
        ColumnType::Blob
        | ColumnType::TinyInteger
        | ColumnType::SmallInteger
        | ColumnType::Integer
        | ColumnType::BigInteger
        | ColumnType::TinyUnsigned
        | ColumnType::SmallUnsigned
        | ColumnType::Unsigned
        | ColumnType::BigUnsigned
        | ColumnType::Decimal(_)
        | ColumnType::DateTime
        | ColumnType::Timestamp
        | ColumnType::TimestampWithTimeZone
        | ColumnType::Time
        | ColumnType::Date
        | ColumnType::Year
        | ColumnType::Interval(..)
        | ColumnType::Binary(_)
        | ColumnType::VarBinary(_)
        | ColumnType::Bit(_)
        | ColumnType::VarBit(_)
        | ColumnType::Money(_)
        | ColumnType::Uuid
        | ColumnType::Custom(_)
        | ColumnType::Enum { .. }
        | ColumnType::Array(_)
        | ColumnType::Vector(_)
        | ColumnType::Cidr
        | ColumnType::Inet
        | ColumnType::MacAddr
        | ColumnType::LTree
        | _ => Ok(value),
    }
}
