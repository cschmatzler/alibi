//! SIWE compares JavaScript Date.parse results, including ISO day overflow and
//! fractional-second truncation. Invalid dates deliberately impose no bound.

use super::parse::js_trim;
use chrono::{DateTime, Datelike, Local, NaiveDate, NaiveDateTime, Offset, TimeZone};

pub(super) fn parse_date_millis(value: &str) -> Option<i64> {
    let value = js_trim(value);
    parse_iso(value).or_else(|| parse_legacy(value))
}

fn digits(input: &mut &str, width: usize) -> Option<i64> {
    let prefix = input.get(..width)?;
    if !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = prefix.parse().ok()?;
    *input = input.get(width..)?;
    Some(value)
}

fn separator(input: &mut &str, expected: char) -> Option<()> {
    *input = input.strip_prefix(expected)?;
    Some(())
}

fn parse_iso(mut input: &str) -> Option<i64> {
    let year = match input.as_bytes().first() {
        Some(b'+' | b'-') => {
            let negative = input.starts_with('-');
            input = input.get(1..)?;
            let year = digits(&mut input, 6)?;
            if negative && year == 0 {
                return None;
            }
            if negative { -year } else { year }
        }
        _ => digits(&mut input, 4)?,
    };
    let mut month = 1;
    let mut day = 1;
    if input.starts_with('-') {
        separator(&mut input, '-')?;
        month = digits(&mut input, 2)?;
        if input.starts_with('-') {
            separator(&mut input, '-')?;
            day = digits(&mut input, 2)?;
        }
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = civil_days(year, month, day);
    if input.is_empty() {
        return time_clip(days.checked_mul(86_400_000)?);
    }
    if !input.starts_with(['T', 't', ' ']) {
        return None;
    }
    input = input.get(1..)?;
    let hour = digits(&mut input, 2)?;
    separator(&mut input, ':')?;
    let minute = digits(&mut input, 2)?;
    let mut second = 0;
    let mut milliseconds = 0;
    let mut fractional_nonzero = false;
    if input.starts_with(':') {
        separator(&mut input, ':')?;
        second = digits(&mut input, 2)?;
        if input.starts_with('.') {
            separator(&mut input, '.')?;
            let length = input.bytes().take_while(u8::is_ascii_digit).count();
            if length == 0 {
                return None;
            }
            fractional_nonzero = input.get(..length)?.bytes().any(|digit| digit != b'0');
            let first = input.get(..length.min(3))?;
            milliseconds =
                first.parse::<i64>().ok()? * 10i64.pow(u32::try_from(3 - first.len()).ok()?);
            input = input.get(length..)?;
        }
    }
    if hour > 24
        || minute > 59
        || second > 59
        || (hour == 24 && (minute != 0 || second != 0 || fractional_nonzero))
    {
        return None;
    }
    let nominal = days.checked_mul(86_400_000)?
        + hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + milliseconds;
    if input.is_empty() {
        return time_clip(local_millis(nominal)?);
    }
    if input == "Z" || input == "z" {
        return time_clip(nominal);
    }
    let negative = input.starts_with('-');
    if !negative && !input.starts_with('+') {
        return None;
    }
    input = input.get(1..)?;
    let offset_hour = digits(&mut input, 2)?;
    if input.starts_with(':') {
        separator(&mut input, ':')?;
    }
    let offset_minute = digits(&mut input, 2)?;
    if !input.is_empty() || offset_hour > 23 || offset_minute > 59 {
        return None;
    }
    let offset = (offset_hour * 60 + offset_minute) * 60_000;
    time_clip(nominal + if negative { offset } else { -offset })
}

fn time_clip(milliseconds: i64) -> Option<i64> {
    (milliseconds.abs() <= 8_640_000_000_000_000).then_some(milliseconds)
}

// Gregorian arithmetic lets expanded ISO years reach JavaScript's TimeClip
// boundary without inheriting Chrono's smaller calendar-year range.
fn civil_days(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_in_era = adjusted_year - era * 400;
    let march_month = month + if month > 2 { -3 } else { 9 };
    let day_in_year = (153 * march_month + 2) / 5 + day - 1;
    let day_in_era = year_in_era * 365 + year_in_era / 4 - year_in_era / 100 + day_in_year;
    era * 146_097 + day_in_era - 719_468
}

fn local_millis(nominal: i64) -> Option<i64> {
    let naive = DateTime::from_timestamp_millis(nominal)?.naive_utc();
    if let Some(date) = Local.from_local_datetime(&naive).earliest() {
        return Some(date.timestamp_millis());
    }
    // A local clock skipped by a daylight-saving transition advances by the
    // gap, using the offset before that transition (ECMAScript compatible).
    let prior = Local
        .timestamp_millis_opt(nominal.checked_sub(86_400_000)?)
        .single()?;
    let offset = i64::from(prior.offset().fix().local_minus_utc()) * 1_000;
    nominal.checked_sub(offset)
}

fn parse_legacy(value: &str) -> Option<i64> {
    let value = remove_comments(value)?;
    let value = value.trim();
    let value = strip_weekday(value).trim();
    if let Ok(date) = DateTime::parse_from_rfc2822(value) {
        return time_clip(date.timestamp_millis());
    }
    let value = value.replace(',', " ");
    let value = normalize_legacy(&value);
    let without_gmt = value.replace("GMT+", "+").replace("GMT-", "-");
    // Chrono needs an explicit offset; literal GMT/UTC format tokens do not
    // supply one. JavaScript accepts these names as zero-offset bounds.
    let without_gmt = without_gmt
        .strip_suffix(" GMT")
        .or_else(|| without_gmt.strip_suffix(" UTC"))
        .map_or_else(|| without_gmt.clone(), |prefix| format!("{prefix} +0000"));
    for format in [
        "%b %d %Y %H:%M:%S%.f %z",
        "%d %b %Y %H:%M:%S%.f %z",
        "%b %d %Y %H:%M:%S%.f GMT",
        "%d %b %Y %H:%M:%S%.f GMT",
        "%b %d %Y %H:%M:%S%.f UTC",
        "%d %b %Y %H:%M:%S%.f UTC",
    ] {
        if let Ok(date) = DateTime::parse_from_str(&without_gmt, format) {
            return time_clip(date.timestamp_millis());
        }
    }
    for format in [
        "%b %d %Y %H:%M:%S%.f",
        "%d %b %Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%b %d %Y %I:%M:%S %p",
        "%d %b %Y %I:%M:%S %p",
    ] {
        if let Ok(date) = NaiveDateTime::parse_from_str(&value, format) {
            return time_clip(local_millis(date.and_utc().timestamp_millis())?);
        }
    }
    for format in [
        "%b %d %Y", "%d %b %Y", "%m/%d/%Y", "%Y/%m/%d", "%m-%d-%Y", "%Y-%m-%d",
    ] {
        if let Ok(mut date) = NaiveDate::parse_from_str(&value, format) {
            if (0..=99).contains(&date.year()) {
                date = date.with_year(if date.year() < 50 {
                    2000 + date.year()
                } else {
                    1900 + date.year()
                })?;
            }
            return time_clip(local_millis(
                date.and_hms_opt(0, 0, 0)?.and_utc().timestamp_millis(),
            )?);
        }
    }
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        let number: i64 = value.parse().ok()?;
        if number > 1_000_000 {
            return None;
        }
        let (year, month) = match number {
            0 => (2000, 1),
            1..=12 => (2001, number),
            13..=31 => return None,
            32..=49 => (2000 + number, 1),
            50..=99 => (1900 + number, 1),
            _ => (number, 1),
        };
        return time_clip(civil_days(year, month, 1).checked_mul(86_400_000)?);
    }
    None
}

fn strip_weekday(value: &str) -> &str {
    let Some(prefix) = value.get(..3) else {
        return value;
    };
    if ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        .iter()
        .any(|weekday| prefix.eq_ignore_ascii_case(weekday))
    {
        return value
            .get(3..)
            .unwrap_or(value)
            .trim_start_matches([',', ' ']);
    }
    value
}

fn normalize_legacy(value: &str) -> String {
    let months = [
        ("January", "Jan"),
        ("February", "Feb"),
        ("March", "Mar"),
        ("April", "Apr"),
        ("May", "May"),
        ("June", "Jun"),
        ("July", "Jul"),
        ("August", "Aug"),
        ("September", "Sep"),
        ("October", "Oct"),
        ("November", "Nov"),
        ("December", "Dec"),
    ];
    let mut parts = value
        .split_whitespace()
        .map(|part| {
            months
                .iter()
                .find(|(name, _)| part.eq_ignore_ascii_case(name))
                .map_or(part, |(_, abbreviation)| *abbreviation)
        })
        .collect::<Vec<_>>();
    // These named North American offsets are accepted by Date.parse. Match a
    // whole final token so an arbitrary suffix cannot become a valid timezone.
    let zones = [
        ("UT", "+0000"),
        ("UTC", "+0000"),
        ("GMT", "+0000"),
        ("EST", "-0500"),
        ("EDT", "-0400"),
        ("CST", "-0600"),
        ("CDT", "-0500"),
        ("MST", "-0700"),
        ("MDT", "-0600"),
        ("PST", "-0800"),
        ("PDT", "-0700"),
    ];
    if let Some(last) = parts.last_mut()
        && let Some((_, offset)) = zones
            .iter()
            .find(|(name, _)| last.eq_ignore_ascii_case(name))
    {
        *last = offset;
    }
    parts.join(" ")
}

fn remove_comments(value: &str) -> Option<String> {
    let mut result = String::new();
    let mut depth = 0usize;
    for character in value.chars() {
        match character {
            '(' => depth = depth.checked_add(1)?,
            ')' if depth > 0 => depth -= 1,
            ')' => return None,
            _ if depth == 0 => result.push(character),
            _ => {}
        }
    }
    (depth == 0).then_some(result)
}
