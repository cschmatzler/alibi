//! The pinned safeJSONParse date reviver, restricted to its ISO-Z grammar.
use crate::utils::json::JsValue;
use chrono::{DateTime, Duration, NaiveDate, Utc};

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
