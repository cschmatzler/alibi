//! JSON timestamps matching JavaScript's `Date.toJSON()` precision.

#[cfg(test)]
mod tests;

mod parse;
use chrono::{DateTime, Datelike, Duration, NaiveDate, SecondsFormat, Utc};
pub use parse::parse_date_millis;
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

/// Normalize the UTC ISO strings revived by Source's `safeJSONParse`.
///
/// Only its exact four-digit-year shape is accepted. JavaScript permits day
/// overflow and midnight at 24:00, truncates fractional seconds, and emits an
/// expanded six-digit year when midnight advances past year 9999. Invalid
/// dates remain ordinary strings for authorization and JSON responses.
#[must_use]
pub fn normalize_json_date(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 if bytes.len() > 20 => *byte == b'.',
            index if index == bytes.len() - 1 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
    {
        return None;
    }
    let year = value.get(..4)?.parse().ok()?;
    let month = value.get(5..7)?.parse().ok()?;
    let day: u32 = value.get(8..10)?.parse().ok()?;
    let hour: u32 = value.get(11..13)?.parse().ok()?;
    let minute: u32 = value.get(14..16)?.parse().ok()?;
    let second: u32 = value.get(17..19)?.parse().ok()?;
    let fraction = if bytes.len() == 20 {
        ""
    } else {
        let fraction = value.get(20..bytes.len() - 1)?;
        if fraction.is_empty() {
            return None;
        }
        fraction
    };
    if !(1..=31).contains(&day)
        || hour > 24
        || minute > 59
        || second > 59
        || (hour == 24
            && (minute != 0 || second != 0 || fraction.bytes().any(|digit| digit != b'0')))
    {
        return None;
    }
    let milliseconds = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0u32, |value, digit| value * 10 + u32::from(digit - b'0'));
    let offset = i64::from(day - 1) * 86_400_000
        + i64::from(hour) * 3_600_000
        + i64::from(minute) * 60_000
        + i64::from(second) * 1_000
        + i64::from(milliseconds);
    let date = NaiveDate::from_ymd_opt(year, month, 1)?
        .and_hms_opt(0, 0, 0)?
        .checked_add_signed(Duration::milliseconds(offset))?;
    let year = if date.year() > 9999 {
        format!("+{:06}", date.year())
    } else {
        format!("{:04}", date.year())
    };
    Some(format!("{year}{}", date.format("-%m-%dT%H:%M:%S%.3fZ")))
}

/// JavaScript Date JSON at every valid TimeClip millisecond, including dates
/// outside Chrono's physical model range. Callers must supply a TimeClip value.
#[must_use]
pub fn json_date_millis(millis: i64) -> String {
    let days = millis.div_euclid(86_400_000);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+07}")
    };
    let time = millis.rem_euclid(86_400_000);
    format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        time / 3_600_000,
        time / 60_000 % 60,
        time / 1000 % 60,
        time % 1000
    )
}
