//! Raw configured values staged on actual model columns.

use crate::json_metadata::JsonMetadata;
use crate::pool::Exec;
use crate::sql::Sql;
use crate::value::{ColumnKind, SqlValue, SqlxValue};
use alibi_core::store::adapter::RawFieldValue;
use alibi_core::{AuthError, AuthResult, utils::json::JsValue};

/// Called by generated model bindings before any backend affinity conversion.
///
/// # Errors
///
/// Returns an error if an object or array cannot be serialized as JSON.
pub fn raw_value(value: &JsValue) -> AuthResult<SqlValue> {
    Ok(match RawFieldValue::from_js(value)? {
        RawFieldValue::Null => SqlValue::Text(None),
        RawFieldValue::Bool(value) => SqlValue::Bool(Some(value)),
        RawFieldValue::Integer(value) => SqlValue::BigInt(Some(value)),
        RawFieldValue::Number(value) => SqlValue::Double(Some(value)),
        RawFieldValue::Text(value) => SqlValue::Text(Some(value)),
        RawFieldValue::Json(value) => SqlValue::Json(Some(Box::new(value))),
    })
}

pub(crate) async fn prepare_string_value(
    exec: Exec<'_>,
    value: SqlValue,
) -> AuthResult<Option<String>> {
    if let SqlValue::Text(value) | SqlValue::BpChar(value) = value {
        return Ok(value);
    }
    if matches!(&value, SqlValue::Json(_)) {
        return Err(AuthError::internal(
            "object cannot bind to a scalar session field",
        ));
    }
    let mut sql = Sql::with(exec.engine(), "SELECT CAST(");
    sql.bind(value);
    sql.push(" AS TEXT) AS value");
    exec.fetch_scalar::<Option<String>>(sql)
        .await?
        .ok_or_else(|| AuthError::internal("session TEXT affinity returned no row"))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(crate) async fn prepare_value(
    exec: Exec<'_>,
    kind: ColumnKind,
    value: SqlValue,
) -> AuthResult<SqlValue> {
    let backend = exec.engine();
    match kind {
        ColumnKind::Text | ColumnKind::BpChar => {
            Ok(SqlValue::Text(prepare_string_value(exec, value).await?))
        }
        ColumnKind::Json => {
            let json = match value {
                SqlValue::Bool(Some(value)) => serde_json::json!(value),
                SqlValue::BigInt(Some(value)) => serde_json::json!(value),
                SqlValue::Double(Some(value)) => serde_json::json!(value),
                SqlValue::Text(Some(value)) => serde_json::json!(value),
                SqlValue::Json(Some(value)) => *value,
                _ => serde_json::Value::Null,
            };
            Ok(JsonMetadata::for_backend(json, backend)?.into_sql_value())
        }
        ColumnKind::Double => Ok(match value {
            SqlValue::BigInt(Some(value)) => SqlValue::Double(Some(value as f64)),
            SqlValue::Text(None) => SqlValue::Double(None),
            other => other,
        }),
        ColumnKind::Float => Ok(match value {
            SqlValue::BigInt(Some(value)) => SqlValue::Float(Some(value as f32)),
            SqlValue::Double(Some(value)) => SqlValue::Float(Some(value as f32)),
            SqlValue::Text(None) => SqlValue::Float(None),
            other => other,
        }),
        ColumnKind::Boolean => Ok(match value {
            SqlValue::Text(None) => SqlValue::Bool(None),
            other => other,
        }),
        ColumnKind::Int | ColumnKind::BigInt | ColumnKind::Other | ColumnKind::NaiveTimestamp => {
            Ok(value)
        }
    }
}
