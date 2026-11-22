use crate::utils::datetime::parse_json_date;
use crate::utils::json::{JsValue, normalize_json_dates};
use chrono::Datelike;

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
        _ => normalize_json_dates(value),
    }
}

// The compatibility runtime's UTC Date primitive conversion. Keep Date
// revival distinct from ordinary string coercion; arrays join revived values.
pub(crate) fn coerce_id(value: &JsValue) -> Option<String> {
    match value {
        JsValue::String(text) => text.as_str().and_then(parse_json_date).map_or_else(
            || text.to_utf8().ok(),
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

fn coerce_object_id(values: &crate::utils::json::JsObject) -> Option<String> {
    // Own/inherited non-callable toString values cannot yield a primitive.
    if values.contains_key("toString") {
        return None;
    }
    match values.get("__proto__") {
        Some(JsValue::Object(prototype)) => coerce_object_id(prototype),
        // These require JavaScript internal slots or inherited Array methods,
        // rather than an idiomatic own-property native JSON object.
        Some(JsValue::Null | JsValue::Array(_)) => None,
        Some(JsValue::String(text)) if text.as_str().and_then(parse_json_date).is_some() => None,
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
        assert!(parse_json_date("2024-03-01T10:20:30Z").is_some());
        for text in [
            "2024-03-01",
            "2024-03-01T10:20:30,5Z",
            "2024-03-01T10:20:30.Z",
            "2024-03-01T10:20:30.1xZ",
            "2024-13-01T10:20:30Z",
            "2024-03-01T24:00:01Z",
        ] {
            assert_eq!(parse_json_date(text), None, "{text}");
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
        normalize_json_dates(&mut value);
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
