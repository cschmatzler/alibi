//! Better Auth's relational adapter filter operand and parameter rules.

use crate::utils::javascript::{string_to_number, trim};
use crate::utils::json::JsValue;
use crate::{AuthError, AuthResult, UserFilterValue};

#[derive(Clone, Copy)]
pub enum Column {
    Boolean,
    Number,
    Int,
    BigInt,
    Float,
    Double,
    Text,
    Other,
}

pub enum Parameter {
    Text(String),
    Number(f64),
    Boolean(bool),
}

pub struct Filter {
    pub pattern: String,
    pub parameters: Vec<Parameter>,
    pub cast: Option<&'static str>,
}

pub fn field(name: Option<&str>) -> &str {
    name.filter(|name| !name.is_empty()).unwrap_or("email")
}

pub fn prepare(
    value: &UserFilterValue,
    operator: &str,
    column: Column,
    postgres: bool,
) -> AuthResult<Filter> {
    let native = value.native();
    if operator == "in" && !matches!(native, JsValue::Array(_)) {
        return Err(AuthError::bad_request("Value must be an array"));
    }
    let value = transform(native, column, postgres);
    let pattern = binding_text(&value)?;
    let operands = match value {
        JsValue::Array(values) => values,
        scalar => vec![scalar],
    };
    let cast = if postgres {
        match column {
            Column::Boolean => Some("boolean"),
            Column::Int => Some("int4"),
            Column::BigInt => Some("int8"),
            Column::Float => Some("float4"),
            Column::Double => Some("float8"),
            _ => None,
        }
    } else {
        None
    };
    // node-postgres sends primitives as text for these inferred column types.
    let bind_as_text = postgres && (cast.is_some() || matches!(column, Column::Text));
    let parameters = operands
        .into_iter()
        .map(|value| {
            if bind_as_text {
                return binding_text(&value).map(Parameter::Text);
            }
            match value {
                JsValue::String(value) => Ok(Parameter::Text(value.to_utf8_binding())),
                JsValue::Number(value) => Ok(Parameter::Number(value)),
                JsValue::Bool(value) => Ok(Parameter::Boolean(value)),
                _ => Err(AuthError::bad_request("Unsupported user filter operand")),
            }
        })
        .collect::<AuthResult<_>>()?;
    Ok(Filter {
        pattern,
        parameters,
        cast,
    })
}

fn binding_text(value: &JsValue) -> AuthResult<String> {
    Ok(value
        .coerce_js_string()
        .map_err(AuthError::internal)?
        .to_utf8_binding())
}

// The factory converts scalar booleans and all-or-none numeric string arrays.
fn transform(value: JsValue, column: Column, supports_booleans: bool) -> JsValue {
    if matches!(column, Column::Boolean) {
        let value = match value {
            JsValue::String(value) => JsValue::Bool(value == "true"),
            value => value,
        };
        return match value {
            JsValue::Bool(value) if !supports_booleans => {
                JsValue::Number(f64::from(u8::from(value)))
            }
            value => value,
        };
    }
    if matches!(
        column,
        Column::Number | Column::Int | Column::BigInt | Column::Float | Column::Double
    ) {
        let parse = |value: &JsValue| {
            value
                .as_str()
                .filter(|value| !trim(value).is_empty())
                .and_then(string_to_number)
                .filter(|value| !value.is_nan())
                .map(JsValue::Number)
        };
        match &value {
            JsValue::String(_) => parse(&value).unwrap_or(value),
            JsValue::Array(values) => values
                .iter()
                .map(parse)
                .collect::<Option<Vec<_>>>()
                .map_or(value, JsValue::Array),
            _ => value,
        }
    } else {
        value
    }
}
