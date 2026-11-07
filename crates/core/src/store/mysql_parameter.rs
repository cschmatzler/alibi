//! Scalar text produced by mysql2's query formatter before MySQL column conversion.
use crate::utils::json::{JsString, JsValue};
use crate::{AuthError, AuthResult};
use chrono::Datelike;

pub fn text_parameter(value: &JsValue) -> AuthResult<Option<JsString>> {
    Ok(Some(match value {
        JsValue::Undefined | JsValue::Null => return Ok(None),
        JsValue::Array(values) => {
            let [value] = values.as_slice() else {
                return Err(AuthError::internal(
                    "MySQL value list does not fit a scalar column",
                ));
            };
            return text_parameter(value);
        }
        JsValue::Date(date) => {
            let date = date.with_timezone(&chrono::Local);
            format!(
                "{:0>4}-{}",
                date.year().to_string(),
                date.format("%m-%d %H:%M:%S%.3f")
            )
            .into()
        }
        JsValue::Bool(value) => if *value { "1" } else { "0" }.into(),
        JsValue::Number(value) if !value.is_finite() => {
            return Err(AuthError::internal(
                "MySQL does not accept a non-finite numeric literal",
            ));
        }
        _ => value.coerce_js_string().map_err(AuthError::internal)?,
    }))
}
