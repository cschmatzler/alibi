//! JSON timestamps matching JavaScript's `Date.toJSON()` precision.

#[cfg(test)]
mod tests;

use chrono::{DateTime, SecondsFormat, Utc};

use serde::Serializer;

/// Serialize a timestamp with exactly three fractional digits and a UTC suffix.
///
/// The official client interprets fractional digits as milliseconds. Chrono's
/// automatic microsecond precision can otherwise shift a parsed client date.
///
/// # Errors
///
/// Propagates errors from the serializer.
pub fn serialize<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Serialize a nullable timestamp using the same millisecond precision.
///
/// # Errors
///
/// Propagates errors from the serializer.
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
