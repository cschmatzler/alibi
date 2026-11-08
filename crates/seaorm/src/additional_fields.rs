//! Raw configured values staged on actual session entity columns.
use alibi_core::store::adapter::RawFieldValue;
use alibi_core::{AuthError, AuthResult, utils::json::JsValue};
use sea_orm::{ColumnTrait, ConnectionTrait, DbBackend, Statement, Value, sea_query::ColumnType};

/// Called by generated model bindings before any backend affinity conversion.
///
/// # Errors
///
/// Returns an error if an object or array cannot be serialized as JSON.
pub fn raw_value(value: &JsValue) -> AuthResult<RawFieldValue> {
    Ok(RawFieldValue::from_js(value)?)
}

pub(crate) fn bind_scalar(value: RawFieldValue) -> AuthResult<Value> {
    Ok(match value {
        RawFieldValue::Null => Value::String(None),
        RawFieldValue::Bool(value) => Value::Bool(Some(value)),
        RawFieldValue::Integer(value) => Value::BigInt(Some(value)),
        RawFieldValue::Number(value) => Value::Double(Some(value)),
        RawFieldValue::Text(value) => Value::String(Some(value.to_utf8_binding())),
        RawFieldValue::Date(value) => Value::String(Some(
            alibi_core::utils::datetime::json_date_millis(value.timestamp_millis()),
        )),
        RawFieldValue::Json(_) => {
            return Err(AuthError::internal("object cannot bind to a scalar field"));
        }
    })
}

pub(crate) async fn prepare_string_value<C: ConnectionTrait>(
    db: &C,
    value: RawFieldValue,
) -> AuthResult<Option<String>> {
    let value = bind_scalar(value)?;
    prepare_bound_string(db, value).await
}

async fn prepare_bound_string<C: ConnectionTrait>(
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
    value: RawFieldValue,
) -> AuthResult<Value> {
    let backend = db.get_database_backend();
    if matches!(
        column.def().get_column_type(),
        ColumnType::Json | ColumnType::JsonBinary
    ) {
        return Ok(crate::JsonMetadata::for_backend(JsValue::from(value), backend)?.into());
    }
    if backend == DbBackend::Postgres && matches!(column.def().get_column_type(), ColumnType::Text)
    {
        return Ok(Value::String(
            alibi_core::store::postgres_parameter::text_parameter(&JsValue::from(value))?
                .map(|text| text.to_utf8_binding()),
        ));
    }
    let value = bind_scalar(value)?;
    match column.def().get_column_type() {
        ColumnType::Char(_) | ColumnType::String(_) | ColumnType::Text => {
            Ok(Value::String(prepare_bound_string(db, value).await?))
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

pub fn physical_json_value(value: Value, exact: bool) -> AuthResult<JsValue> {
    Ok(match value {
        Value::String(Some(text)) => JsValue::String(text.into()),
        Value::Json(Some(value)) => {
            if exact {
                return Err(AuthError::not_implemented(
                    "Exact JSON text output requires a JsonMetadata model field",
                ));
            }
            JsValue::String(alibi_core::utils::json::to_string(&JsValue::from(*value))?.into())
        }
        Value::Bool(Some(value)) => JsValue::Bool(value),
        Value::BigInt(Some(value)) => JsValue::from(value),
        Value::Double(Some(value)) => JsValue::Number(value),
        Value::Json(None) | Value::String(None) => JsValue::Null,
        _ => return Err(AuthError::internal("Unsupported physical JSON parameter")),
    })
}
