//! Raw configured values staged on actual session entity columns.
use alibi_core::store::adapter::RawFieldValue;
use alibi_core::{AuthError, AuthResult, utils::json::JsValue};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, Statement, Value, sea_query::ColumnType};

/// Called by generated model bindings before any backend affinity conversion.
///
/// # Errors
///
/// Returns an error if an object or array cannot be serialized as JSON.
pub fn raw_value(value: &JsValue) -> AuthResult<Value> {
    Ok(match RawFieldValue::from_js(value)? {
        RawFieldValue::Null => Value::String(None),
        RawFieldValue::Bool(value) => Value::Bool(Some(value)),
        RawFieldValue::Integer(value) => Value::BigInt(Some(value)),
        RawFieldValue::Number(value) => Value::Double(Some(value)),
        RawFieldValue::Text(value) => Value::String(Some(value)),
        RawFieldValue::Json(value) => Value::Json(Some(Box::new(value))),
    })
}

pub(crate) async fn prepare_string_value<C: ConnectionTrait>(
    db: &C,
    value: Value,
) -> AuthResult<Option<String>> {
    if let Value::String(value) = value {
        return Ok(value);
    }
    if matches!(&value, Value::Json(_)) {
        return Err(AuthError::internal(
            "object cannot bind to a scalar session field",
        ));
    }
    let backend = db.get_database_backend();
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
    row.try_get("", "value").map_err(crate::store::map_db_err)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(crate) async fn prepare_value<C: ConnectionTrait>(
    db: &C,
    column: &impl ColumnTrait,
    value: Value,
) -> AuthResult<Value> {
    match column.def().get_column_type() {
        ColumnType::Char(_) | ColumnType::String(_) | ColumnType::Text => {
            Ok(Value::String(prepare_string_value(db, value).await?))
        }
        ColumnType::Json | ColumnType::JsonBinary => {
            let json = match value {
                Value::Bool(Some(value)) => serde_json::json!(value),
                Value::BigInt(Some(value)) => serde_json::json!(value),
                Value::Double(Some(value)) => serde_json::json!(value),
                Value::String(Some(value)) => serde_json::json!(value),
                Value::Json(Some(value)) => *value,
                _ => serde_json::Value::Null,
            };
            let backend = db.get_database_backend();
            Ok(crate::JsonMetadata::for_backend(json, backend)?.into())
        }
        ColumnType::Double => Ok(match value {
            Value::BigInt(Some(value)) => Value::Double(Some(value as f64)),
            Value::String(None) => Value::Double(None),
            other => other,
        }),
        ColumnType::Float => Ok(match value {
            Value::BigInt(Some(value)) => Value::Float(Some(value as f32)),
            Value::Double(Some(value)) => Value::Float(Some(value as f32)),
            Value::String(None) => Value::Float(None),
            other => other,
        }),
        ColumnType::Boolean => Ok(match value {
            Value::String(None) => Value::Bool(None),
            other => other,
        }),
        _ => Ok(value),
    }
}
