//! The pinned safeJSONParse date reviver, restricted to its ISO-Z grammar.
use crate::utils::json::JsValue;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};

pub(crate) fn parse(value: &str) -> Option<DateTime<Utc>> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<u32> {
        let digits = bytes.get(start..end)?;
        digits.iter().all(u8::is_ascii_digit).then_some(())?;
        digits
            .iter()
            .try_fold(0, |total, digit| Some(total * 10 + u32::from(digit - b'0')))
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 24
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fraction = if bytes.len() == 20 {
        &[][..]
    } else {
        if bytes.get(19) != Some(&b'.') {
            return None;
        }
        let digits = bytes.get(20..bytes.len() - 1)?;
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        digits
    };
    if hour == 24 && (minute != 0 || second != 0 || fraction.iter().any(|digit| *digit != b'0')) {
        return None;
    }
    let millis = fraction
        .iter()
        .take(3)
        .zip([100, 10, 1])
        .fold(0, |total, (digit, factor)| {
            total + u32::from(digit - b'0') * factor
        });
    let first = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, 1)?;
    let date =
        first.checked_add_signed(Duration::days(i64::from(day - 1) + i64::from(hour == 24)))?;
    Some(
        date.and_hms_milli_opt(if hour == 24 { 0 } else { hour }, minute, second, millis)?
            .and_utc(),
    )
}

pub(crate) fn revive(value: &mut JsValue) {
    match value {
        JsValue::String(text) => {
            if let Some(normalized) = crate::utils::datetime::normalize_json_date(text) {
                *text = normalized;
            }
        }
        JsValue::Array(values) => values.iter_mut().for_each(revive),
        JsValue::Object(values) => values.values_mut().for_each(revive),
        JsValue::Null | JsValue::Bool(_) | JsValue::Number(_) => {}
    }
}

// safeJSONParse's second invocation walks a pre-parsed object into fresh
// ordinary JavaScript objects. The __proto__ setter changes its prototype;
// it does not create an enumerable output property.
pub(crate) fn revive_parsed(value: &mut JsValue) {
    match value {
        JsValue::Object(values) => {
            _ = values.shift_remove("__proto__");
            values.values_mut().for_each(revive_parsed);
        }
        JsValue::Array(values) => values.iter_mut().for_each(revive_parsed),
        _ => revive(value),
    }
}

// The compatibility runtime's UTC Date primitive conversion. Keep Date
// revival distinct from ordinary string coercion; arrays join revived values.
pub(crate) fn coerce_id(value: &JsValue) -> Option<String> {
    match value {
        JsValue::String(text) => parse(text).map_or_else(
            || Some(text.clone()),
            |date| {
                Some(format!(
                    "{}{:04}{}",
                    date.format("%a %b %d "),
                    date.year(),
                    date.format(" %H:%M:%S GMT+0000 (Coordinated Universal Time)")
                ))
            },
        ),
        JsValue::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    Some(String::new())
                } else {
                    coerce_id(value)
                }
            })
            .collect::<Option<Vec<_>>>()
            .map(|values| values.join(",")),
        JsValue::Object(values) => coerce_object_id(values),
        value => value.coerce_string().ok(),
    }
}

fn coerce_object_id(values: &indexmap::IndexMap<String, JsValue>) -> Option<String> {
    // Own/inherited non-callable toString values cannot yield a primitive.
    if values.contains_key("toString") {
        return None;
    }
    match values.get("__proto__") {
        Some(JsValue::Object(prototype)) => coerce_object_id(prototype),
        // These require JavaScript internal slots or inherited Array methods,
        // rather than an idiomatic own-property native JSON object.
        Some(JsValue::Null | JsValue::Array(_)) => None,
        Some(JsValue::String(text)) if parse(text).is_some() => None,
        _ => Some("[object Object]".into()),
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::json::parse_value;

    fn id(json: &str) -> Option<String> {
        coerce_id(&parse_value(json).unwrap())
    }

    #[test]
    fn rejects_malformed_iso_dates() {
        assert!(parse("2024-03-01T10:20:30Z").is_some());
        for text in [
            "2024-03-01",
            "2024-03-01T10:20:30,5Z",
            "2024-03-01T10:20:30.Z",
            "2024-03-01T10:20:30.1xZ",
            "2024-13-01T10:20:30Z",
            "2024-03-01T24:00:01Z",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn revival_normalizes_nested_dates_and_drops_proto() {
        let mut value =
            parse_value(r#"{"a":["2024-02-30T24:00:00.0Z",1],"__proto__":{"x":1}}"#).unwrap();
        revive_parsed(&mut value);
        assert_eq!(
            value.to_json_value().unwrap(),
            serde_json::json!({"a":["2024-03-02T00:00:00.000Z",1]})
        );
        let mut value = parse_value(r#"[["2024-03-01T10:20:30Z"]]"#).unwrap();
        revive(&mut value);
        assert_eq!(
            value.to_json_value().unwrap(),
            serde_json::json!([["2024-03-01T10:20:30.000Z"]])
        );
    }

    #[test]
    fn coerces_ids_like_javascript_primitives() {
        assert_eq!(
            id(r#""2024-03-01T10:20:30.000Z""#).as_deref(),
            Some("Fri Mar 01 2024 10:20:30 GMT+0000 (Coordinated Universal Time)")
        );
        assert_eq!(id(r#""plain""#).as_deref(), Some("plain"));
        assert_eq!(id("[1,null,\"a\"]").as_deref(), Some("1,,a"));
        assert_eq!(id("[{\"toString\":1}]"), None);
        assert_eq!(id("42").as_deref(), Some("42"));
        assert_eq!(id("true").as_deref(), Some("true"));
        assert_eq!(id("{}").as_deref(), Some("[object Object]"));
        assert_eq!(id(r#"{"toString":"x"}"#), None);
        assert_eq!(
            id(r#"{"__proto__":{"a":1}}"#).as_deref(),
            Some("[object Object]")
        );
        assert_eq!(id(r#"{"__proto__":{"toString":1}}"#), None);
        assert_eq!(id(r#"{"__proto__":null}"#), None);
        assert_eq!(id(r#"{"__proto__":[]}"#), None);
        assert_eq!(id(r#"{"__proto__":"2024-03-01T10:20:30Z"}"#), None);
        assert_eq!(
            id(r#"{"__proto__":"x"}"#).as_deref(),
            Some("[object Object]")
        );
    }
}
// LCOV_EXCL_STOP
