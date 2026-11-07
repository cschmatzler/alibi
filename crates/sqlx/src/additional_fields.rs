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
pub fn raw_value(value: &JsValue) -> AuthResult<RawFieldValue> {
    Ok(RawFieldValue::from_js(value)?)
}

pub(crate) fn bind_scalar(value: RawFieldValue) -> AuthResult<SqlValue> {
    Ok(match value {
        RawFieldValue::Null => SqlValue::Text(None),
        RawFieldValue::Bool(value) => SqlValue::Bool(Some(value)),
        RawFieldValue::Integer(value) => SqlValue::BigInt(Some(value)),
        RawFieldValue::Number(value) => SqlValue::Double(Some(value)),
        RawFieldValue::Text(value) => SqlValue::Text(Some(value.to_utf8_binding())),
        RawFieldValue::Date(value) => SqlValue::Text(Some(
            alibi_core::utils::datetime::json_date_millis(value.timestamp_millis()),
        )),
        RawFieldValue::Json(_) => {
            return Err(AuthError::internal("object cannot bind to a scalar field"));
        }
    })
}

pub(crate) async fn prepare_string_value(
    exec: Exec<'_>,
    value: RawFieldValue,
) -> AuthResult<Option<String>> {
    let value = bind_scalar(value)?;
    prepare_bound_string(exec, value).await
}

async fn prepare_bound_string(exec: Exec<'_>, value: SqlValue) -> AuthResult<Option<String>> {
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
    value: RawFieldValue,
) -> AuthResult<SqlValue> {
    let backend = exec.engine();
    if kind == ColumnKind::Json {
        return Ok(JsonMetadata::for_backend(JsValue::from(value), backend)?.into_sql_value());
    }
    if backend == crate::pool::Engine::Postgres {
        match (kind, &value) {
            (ColumnKind::Timestamp, RawFieldValue::Date(value)) => {
                return Ok(SqlValue::Timestamp(Some(*value)));
            }
            (ColumnKind::Timestamp, RawFieldValue::Null) => return Ok(SqlValue::Timestamp(None)),
            (ColumnKind::NaiveTimestamp, RawFieldValue::Date(value)) => {
                return Ok(SqlValue::NaiveTimestamp(Some(value.naive_utc())));
            }
            (ColumnKind::NaiveTimestamp, RawFieldValue::Null) => {
                return Ok(SqlValue::NaiveTimestamp(None));
            }
            _ => {}
        }
    }
    let value = bind_scalar(value)?;
    match kind {
        ColumnKind::Text | ColumnKind::BpChar => {
            Ok(SqlValue::Text(prepare_bound_string(exec, value).await?))
        }
        ColumnKind::Double | ColumnKind::Number => Ok(match value {
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
        ColumnKind::Int
        | ColumnKind::BigInt
        | ColumnKind::Other
        | ColumnKind::Timestamp
        | ColumnKind::NaiveTimestamp
        | ColumnKind::Json => Ok(value),
    }
}

pub fn physical_json_value(value: SqlValue, exact: bool) -> AuthResult<JsValue> {
    Ok(match value {
        SqlValue::Text(Some(text)) => JsValue::String(text.into()),
        SqlValue::Json(Some(value)) => {
            if exact {
                return Err(AuthError::not_implemented(
                    "Exact SQLite JSON output transforms require a JsonMetadata model field",
                ));
            }
            JsValue::String(alibi_core::utils::json::to_string(&JsValue::from(*value))?.into())
        }
        SqlValue::Bool(Some(value)) => JsValue::Bool(value),
        SqlValue::BigInt(Some(value)) => JsValue::from(value),
        SqlValue::Double(Some(value)) => JsValue::Number(value),
        SqlValue::Json(None) | SqlValue::Text(None) => JsValue::Null,
        _ => return Err(AuthError::internal("Unsupported physical JSON parameter")),
    })
}
