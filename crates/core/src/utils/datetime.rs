//! JSON timestamps matching JavaScript's `Date.toJSON()` precision.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serializer;

/// Serialize a timestamp with exactly three fractional digits and a UTC suffix.
///
/// The official client interprets fractional digits as milliseconds. Chrono's
/// automatic microsecond precision can otherwise shift a parsed client date.
pub fn serialize<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Serialize a nullable timestamp using the same millisecond precision.
pub fn serialize_optional<S: Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => {
            serializer.serialize_some(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
        }
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Timestamps {
        #[serde(serialize_with = "super::serialize")]
        created_at: DateTime<Utc>,
        #[serde(serialize_with = "super::serialize_optional")]
        expires_at: Option<DateTime<Utc>>,
    }

    #[test]
    fn wire_precision_is_milliseconds_for_every_source_precision() {
        for (input, expected) in [
            ("2026-09-30T12:00:00Z", "2026-09-30T12:00:00.000Z"),
            ("2026-09-30T12:00:00.123Z", "2026-09-30T12:00:00.123Z"),
            ("2026-09-30T12:00:00.123456Z", "2026-09-30T12:00:00.123Z"),
            ("2026-09-30T12:00:00.123456789Z", "2026-09-30T12:00:00.123Z"),
        ] {
            let value: DateTime<Utc> = input.parse().expect("valid timestamp");
            let encoded = serde_json::to_value(Timestamps {
                created_at: value,
                expires_at: Some(value),
            })
            .expect("serialize timestamps");
            assert_eq!(encoded["created_at"], expected);
            assert_eq!(encoded["expires_at"], expected);
            let decoded: Timestamps =
                serde_json::from_value(encoded).expect("deserialize timestamps");
            assert_eq!(
                decoded.created_at.timestamp_millis(),
                value.timestamp_millis()
            );
            assert_eq!(
                decoded.expires_at.map(|date| date.timestamp_millis()),
                Some(value.timestamp_millis())
            );
        }
    }

    #[test]
    fn optional_null_remains_null_and_input_keeps_full_precision() {
        let value: Timestamps = serde_json::from_value(
            serde_json::json!({"created_at":"2026-09-30T12:00:00.123456789Z","expires_at":null}),
        )
        .expect("deserialize timestamps");
        assert_eq!(value.created_at.timestamp_subsec_nanos(), 123456789);
        let encoded = serde_json::to_value(value).expect("serialize timestamps");
        assert_eq!(encoded["created_at"], "2026-09-30T12:00:00.123Z");
        assert_eq!(encoded["expires_at"], serde_json::Value::Null);
    }
}
