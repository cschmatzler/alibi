use super::*;
pub(in crate::jwt) fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => alibi_core::utils::json::number_as_f64(value)
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

pub(in crate::jwt) fn js_raw_primitive_string(value: &alibi_core::utils::json::JsValue) -> String {
    use alibi_core::utils::json::JsValue;
    match value {
        JsValue::Null => "null".to_owned(),
        JsValue::String(value) => value.clone(),
        JsValue::Bool(value) => value.to_string(),
        JsValue::Number(value) if value.is_nan() => "NaN".to_owned(),
        JsValue::Number(value) if *value == f64::INFINITY => "Infinity".to_owned(),
        JsValue::Number(value) if *value == f64::NEG_INFINITY => "-Infinity".to_owned(),
        JsValue::Number(value) => serde_json::Number::from_f64(*value)
            .and_then(|number| alibi_core::utils::json::number_to_string(&number).ok())
            .unwrap_or_default(),
        JsValue::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    String::new()
                } else {
                    js_raw_primitive_string(value)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        JsValue::Object(_) => "[object Object]".to_owned(),
    }
}

pub(in crate::jwt) fn js_primitive_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.as_f64().unwrap_or_default().to_string(),
        Value::Array(values) => values
            .iter()
            .map(|value_2| {
                if value_2.is_null() {
                    String::new()
                } else {
                    js_primitive_string(value_2)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

pub(in crate::jwt) fn decode_compact_part(
    value: &str,
    allow_whitespace: bool,
) -> AuthResult<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    // Bun's JOSE decoder accepts these five ASCII whitespace characters and
    // unused trailing bits, while requiring the exact optional padding count.
    let bytes = value
        .bytes()
        .filter(|byte| !allow_whitespace || !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
        .collect::<Vec<_>>();
    let end = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    let (encoded, padded) = bytes
        .split_at_checked(end)
        .ok_or_else(|| AuthError::bad_request("Invalid JWT base64url encoding"))?;
    let padding = padded.len();
    if padding > 0
        && (padding > 2
            || !padded.iter().all(|byte| *byte == b'=')
            || end % 4 == 0
            || bytes.len() % 4 != 0)
    {
        return Err(AuthError::bad_request("Invalid JWT base64url encoding"));
    }
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(encoded)
    .map_err(|_error| AuthError::bad_request("Invalid JWT base64url encoding"))
}

pub(in crate::jwt) fn decode_compact_json(
    value: &str,
    allow_whitespace: bool,
) -> AuthResult<Value> {
    let bytes = decode_compact_part(value, allow_whitespace)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_error| AuthError::bad_request("Invalid JWT JSON UTF8"))?;
    Ok(alibi_core::utils::json::parse_value(text)?.to_json_value()?)
}

pub(in crate::jwt) fn validate_numeric_date(field: &str, number: Option<f64>) -> AuthResult<()> {
    if number.is_some_and(|number| !number.is_finite()) {
        return Err(AuthError::internal(format!("Invalid {field} input")));
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
pub(in crate::jwt) fn normalize_signing_claims(payload: &mut Map<String, Value>) -> AuthResult<()> {
    let now = Utc::now().timestamp();
    for field in ["exp", "iat", "nbf"] {
        if let Some(value) = payload.get(field)
            && (field == "exp" || js_truthy(value))
        {
            let value = match value {
                Value::Number(number) => {
                    validate_numeric_date(field, alibi_core::utils::json::number_as_f64(number))?;
                    value.clone()
                }
                Value::String(value) => json!(now as f64 + relative_numeric_date(value)?),
                Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
                    return Err(AuthError::internal("Invalid time period format"));
                }
            };
            drop(payload.insert(field.to_owned(), value));
        }
    }
    for field in ["iss", "sub", "jti"] {
        if let Some(value) = payload.get(field)
            && (field == "iss" || js_truthy(value))
            && !value.is_string()
        {
            return Err(AuthError::internal(format!(
                "\"{field}\" claim must be a string"
            )));
        }
    }
    if let Some(value) = payload.get("aud")
        && !value.is_string()
        && !value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err(AuthError::internal(
            "\"aud\" claim must be a string or an array of strings",
        ));
    }
    Ok(())
}

// JOSE's relative NumericDate grammar, including its rounding and year length.
pub(in crate::jwt) fn relative_numeric_date(value: &str) -> AuthResult<f64> {
    let invalid = || AuthError::internal("Invalid time period format");
    let lower = value.to_ascii_lowercase();
    let ago = value.ends_with(" ago");
    let (value, suffix) = if lower.ends_with(" from now") {
        (
            value
                .get(..value.len().saturating_sub(9))
                .ok_or_else(invalid)?,
            true,
        )
    } else if lower.ends_with(" ago") {
        (
            value
                .get(..value.len().saturating_sub(4))
                .ok_or_else(invalid)?,
            true,
        )
    } else {
        (value, false)
    };
    let (number, negative, signed) = value.strip_prefix('-').map_or_else(
        || {
            value
                .strip_prefix('+')
                .map_or((value, false, false), |value| (value, false, true))
        },
        |value| (value, true, true),
    );
    if suffix && signed {
        return Err(invalid());
    }
    let number = number.strip_prefix(' ').unwrap_or(number);
    let split = number
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .ok_or_else(invalid)?;
    let digits = number.get(..split).ok_or_else(invalid)?;
    let unit = number.get(split..).ok_or_else(invalid)?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit).to_ascii_lowercase();
    let mut parts = digits.split('.');
    if !parts
        .next()
        .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        || parts
            .next()
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || parts.next().is_some()
    {
        return Err(invalid());
    }
    let multiplier = match unit.as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
        "d" | "day" | "days" => 86400.0,
        "w" | "week" | "weeks" => 604_800.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600.0,
        _ => return Err(invalid()),
    };
    let seconds = digits
        .parse::<f64>()
        .map_err(|_error| invalid())?
        .mul_add(multiplier, 0.5)
        .floor();
    if !seconds.is_finite() {
        return Err(invalid());
    }
    // The reference regex is case insensitive; its `ago` sign check is literal.
    let negative = negative || ago;
    Ok(if negative { -seconds } else { seconds })
}

pub(in crate::jwt) fn validate_critical_header(
    header: &Map<String, Value>,
    signing: bool,
) -> AuthResult<()> {
    let Some(critical) = header.get("crit") else {
        return Ok(());
    };
    let critical = critical.as_array().filter(|values| {
        !values.is_empty() && values.iter().all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
    }).ok_or_else(|| AuthError::internal("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"))?;
    if signing {
        let mut seen = std::collections::HashSet::new();
        if critical
            .iter()
            .any(|value| !seen.insert(value.as_str().unwrap_or_default()))
        {
            return Err(AuthError::internal(
                "\"crit\" (Critical) Header Parameter MUST NOT contain duplicate values",
            ));
        }
    }
    for value in critical {
        let parameter = value.as_str().unwrap_or_default();
        if parameter != "b64" {
            return Err(AuthError::internal(format!(
                "Extension Header Parameter \"{parameter}\" is not recognized"
            )));
        }
        match header.get("b64") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => {
                return Err(AuthError::internal("JWTs MUST NOT use unencoded payload"));
            }
            None => {
                return Err(AuthError::internal(
                    "Extension Header Parameter \"b64\" is missing",
                ));
            }
            _ => {
                return Err(AuthError::internal(
                    "The \"b64\" (base64url-encode payload) Header Parameter must be a boolean",
                ));
            }
        }
    }
    Ok(())
}
