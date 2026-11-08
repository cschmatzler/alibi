//! Text parameters produced by node-postgres before PostgreSQL column conversion.
use crate::AuthResult;
use crate::utils::json::{self, JsString, JsValue};
use chrono::Datelike;

/// Quote an unknown PostgreSQL literal for parse-time column conversion.
/// Binary drivers cannot send raw text in a timestamp-typed bind parameter;
/// casting a TEXT parameter instead can skip conversion on zero-row writes.
#[must_use]
pub fn quoted_literal(value: &str) -> String {
    let mut literal = String::from("E'");
    for character in value.chars() {
        match character {
            '\\' => literal.push_str("\\\\"),
            '\'' => literal.push_str("\\'"),
            '\0' => literal.push_str("\\000"),
            character => literal.push(character),
        }
    }
    literal.push('\'');
    literal
}

pub fn text_parameter(value: &JsValue) -> AuthResult<Option<JsString>> {
    Ok(Some(match value {
        JsValue::Undefined | JsValue::Null => return Ok(None),
        JsValue::Date(date) => {
            let date = date.with_timezone(&chrono::Local);
            let year = date.year();
            let bc = year < 1;
            let year = if bc {
                year.unsigned_abs() + 1
            } else {
                year.unsigned_abs()
            };
            format!(
                "{year:04}-{}{}",
                date.format("%m-%dT%H:%M:%S%.3f%:z"),
                if bc { " BC" } else { "" }
            )
            .into()
        }
        JsValue::Array(values) => {
            let mut units = Vec::new();
            array_parameter(&mut units, values)?;
            JsString::from_code_units(units)
        }
        JsValue::Object(_) => json::to_string(value)?.into(),
        _ => value
            .coerce_js_string()
            .map_err(crate::AuthError::internal)?,
    }))
}

fn array_parameter(units: &mut Vec<u16>, values: &[JsValue]) -> AuthResult<()> {
    units.push(u16::from(b'{'));
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            units.push(u16::from(b','));
        }
        match value {
            JsValue::Array(values) => array_parameter(units, values)?,
            _ => {
                if let Some(value) = text_parameter(value)? {
                    units.push(u16::from(b'"'));
                    for unit in value.code_units() {
                        if *unit == u16::from(b'"') || *unit == u16::from(b'\\') {
                            units.push(u16::from(b'\\'));
                        }
                        units.push(*unit);
                    }
                    units.push(u16::from(b'"'));
                } else {
                    units.extend("NULL".encode_utf16());
                }
            }
        }
    }
    units.push(u16::from(b'}'));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::quoted_literal;

    #[test]
    fn literals_escape_sql_delimiters_and_backslashes() {
        assert_eq!(quoted_literal(""), "E''");
        assert_eq!(quoted_literal("O'Reilly"), r"E'O\'Reilly'");
        assert_eq!(quoted_literal(r"\path"), r"E'\\path'");
        assert_eq!(
            quoted_literal("'; DROP TABLE users; --"),
            r"E'\'; DROP TABLE users; --'"
        );
    }

    #[test]
    fn literals_preserve_unicode_without_protocol_nul_bytes() {
        assert_eq!(quoted_literal("雪\0date\n"), "E'雪\\000date\n'");
    }
}
