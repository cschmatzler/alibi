//! Raw configured values staged on actual model columns.

use crate::pool::Exec;
use crate::sql::Sql;
use crate::value::{ColumnKind, SqlValue};
use better_auth_core::{AuthError, AuthResult, utils::json::JsValue};

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
pub fn raw_value(value: &JsValue) -> AuthResult<SqlValue> {
    Ok(match value {
        JsValue::Null => SqlValue::Text(None),
        JsValue::Bool(value) => SqlValue::Bool(Some(*value)),
        JsValue::Number(value)
            if value.is_finite()
                && value.fract() == 0.0
                && !(*value == 0.0 && value.is_sign_negative())
                && (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0).contains(value) =>
        {
            SqlValue::BigInt(Some(*value as i64))
        }
        JsValue::Number(value) => SqlValue::Double(Some(*value)),
        JsValue::String(value) => SqlValue::Text(Some(value.clone())),
        JsValue::Array(_) | JsValue::Object(_) => {
            SqlValue::Json(Some(Box::new(value.to_json_value()?)))
        }
    })
}

pub(crate) async fn prepare_string_value(
    exec: Exec<'_>,
    value: SqlValue,
) -> AuthResult<Option<String>> {
    if let SqlValue::Text(value) = value {
        return Ok(value);
    }
    if matches!(&value, SqlValue::Json(_)) {
        return Err(AuthError::internal(
            "object cannot bind to a scalar session field",
        ));
    }
    let mut sql = Sql::with(exec.backend(), "SELECT CAST(");
    sql.bind(value).push(" AS TEXT) AS value");
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
    let backend = exec.backend();
    match kind {
        ColumnKind::Text => Ok(SqlValue::Text(prepare_string_value(exec, value).await?)),
        ColumnKind::Json => {
            let json = match value {
                SqlValue::Bool(Some(value)) => serde_json::json!(value),
                SqlValue::BigInt(Some(value)) => serde_json::json!(value),
                SqlValue::Double(Some(value)) => serde_json::json!(value),
                SqlValue::Text(Some(value)) => serde_json::json!(value),
                SqlValue::Json(Some(value)) => *value,
                SqlValue::Bool(None)
                | SqlValue::Int(_)
                | SqlValue::BigInt(None)
                | SqlValue::Float(_)
                | SqlValue::Double(None)
                | SqlValue::Text(None)
                | SqlValue::Bytes(_)
                | SqlValue::Json(None)
                | SqlValue::Timestamp(_)
                | SqlValue::Uuid(_) => serde_json::Value::Null,
            };
            Ok(crate::value::SqlxValue::into_sql_value(
                crate::JsonMetadata::for_backend(json, backend)?,
            ))
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
        ColumnKind::Other => Ok(value),
    }
}
