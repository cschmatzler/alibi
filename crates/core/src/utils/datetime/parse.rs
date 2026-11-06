//! JavaScript Date.parse results, including ISO day overflow and
//! fractional-second truncation. Invalid dates deliberately impose no bound.

use crate::utils::javascript::trim as js_trim;
use chrono::{
    DateTime, Local, Offset, TimeZone, Timelike,
    format::{Parsed, StrftimeItems, parse},
};

#[must_use]
pub fn parse_date_millis(value: &str) -> Option<i64> {
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
    let year = if input.starts_with(' ') {
        legacy_year(year)
    } else {
        year
    };
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

fn legacy_year(year: i64) -> i64 {
    match year {
        0..=49 => year + 2000,
        50..=99 => year + 1900,
        _ => year,
    }
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
        "%b %d %Y %H:%M %z",
        "%d %b %Y %H:%M %z",
        "%m/%d/%Y %H:%M:%S%.f %z",
        "%Y/%m/%d %H:%M:%S%.f %z",
        "%m/%d/%Y %H:%M %z",
        "%Y/%m/%d %H:%M %z",
        "%b %d %Y %H:%M:%S%.f GMT",
        "%d %b %Y %H:%M:%S%.f GMT",
        "%b %d %Y %H:%M:%S%.f UTC",
        "%d %b %Y %H:%M:%S%.f UTC",
    ] {
        if let Some(millis) = parse_legacy_format(&without_gmt, format) {
            return Some(millis);
        }
    }
    let midnight = format!("{without_gmt} 00:00:00");
    for format in [
        "%b %d %Y %z %H:%M:%S",
        "%d %b %Y %z %H:%M:%S",
        "%m/%d/%Y %z %H:%M:%S",
        "%Y/%m/%d %z %H:%M:%S",
        "%Y-%m-%d %z %H:%M:%S",
    ] {
        if let Some(millis) = parse_legacy_format(&midnight, format) {
            return Some(millis);
        }
    }
    for format in [
        "%b %d %Y %H:%M:%S%.f",
        "%d %b %Y %H:%M:%S%.f",
        "%m/%d/%Y %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
        "%b %d %Y %H:%M",
        "%d %b %Y %H:%M",
        "%m/%d/%Y %H:%M",
        "%Y/%m/%d %H:%M",
        "%b %d %Y %I:%M %p",
        "%d %b %Y %I:%M %p",
        "%b %d %Y %I:%M:%S %p",
        "%d %b %Y %I:%M:%S %p",
    ] {
        if let Some(millis) = parse_legacy_format(&value, format) {
            return Some(millis);
        }
    }
    for format in [
        "%b %d %Y", "%d %b %Y", "%m/%d/%Y", "%Y/%m/%d", "%m-%d-%Y", "%Y-%m-%d",
    ] {
        if let Some(millis) = parse_legacy_format(&value, format) {
            return Some(millis);
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
        return time_clip(local_millis(civil_days(year, month, 1).checked_mul(86_400_000)?)?);
    }
    None
}

fn parse_legacy_format(value: &str, format: &str) -> Option<i64> {
    let mut parsed = Parsed::new();
    parse(&mut parsed, value, StrftimeItems::new(format)).ok()?;
    let year = legacy_year(i64::from(parsed.year()?));
    let days = civil_days(year, i64::from(parsed.month()?), i64::from(parsed.day()?));
    let time = if parsed.hour_div_12().is_some() {
        let time = parsed.to_naive_time().ok()?;
        i64::from(time.num_seconds_from_midnight()) * 1000
            + i64::from(time.nanosecond() / 1_000_000)
    } else {
        0
    };
    let nominal = days.checked_mul(86_400_000)?.checked_add(time)?;
    let millis = if let Some(offset) = parsed.offset() {
        nominal.checked_sub(i64::from(offset) * 1000)?
    } else {
        local_millis(nominal)?
    };
    time_clip(millis)
}

fn strip_weekday(value: &str) -> &str {
    let Some(prefix) = value.get(..3) else {
        return value;
    };
    if ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        .iter()
        .any(|weekday| prefix.eq_ignore_ascii_case(weekday))
    {
        let end = value
            .bytes()
            .position(|byte| !byte.is_ascii_alphabetic())
            .unwrap_or(value.len());
        let rest = &value[end..];
        if rest.is_empty() || rest.starts_with([',', ' ']) {
            return rest.trim_start_matches([',', ' ']);
        }
    }
    value
}

fn normalize_legacy(value: &str) -> String {
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut parts = value
        .split_whitespace()
        .map(|part| {
            months
                .iter()
                .find(|month| {
                    part.bytes().all(|byte| byte.is_ascii_alphabetic())
                        && part.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case(month))
                })
                .copied()
                .unwrap_or(part)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_month_tokens_use_their_three_letter_prefix() {
        for (month, token) in [
            "Januaryish", "Febuary", "Marble", "Aprilfoo", "Maybe", "Juniper",
            "Julyish", "Augustus", "Sept", "Octoberish", "Novemberish", "Decemberish",
        ].into_iter().enumerate() {
            let input = format!("{token} 1 2024 GMT");
            let expected = format!("2024-{:02}-01T00:00:00Z", month + 1);
            assert_eq!(parse_date_millis(&input), parse_date_millis(&expected), "{input}");
        }
        for token in ["Ju", "Jax", "Month"] {
            assert_eq!(parse_date_millis(&format!("{token} 1 2024 GMT")), None);
        }
    }

    #[test]
    fn slash_separated_expiry_timestamps_honor_offsets() {
        for (input, expected) in [
            ("2024/01/02 12:34 GMT+0530", "2024-01-02T07:04:00Z"),
            ("01/02/2024 12:34:56 EST", "2024-01-02T17:34:56Z"),
            ("2024/1/2 12:34:56.789 UTC", "2024-01-02T12:34:56.789Z"),
            ("1/2/2024 12:34 -0800", "2024-01-02T20:34:00Z"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
        assert_eq!(parse_date_millis("1/2/2024 12:34 BOGUS"), None);
    }

    #[test]
    fn numeric_legacy_dates_use_local_midnight() {
        const CHILD: &str = "ALIBI_NUMERIC_DATE_TZ_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "utils::datetime::parse::tests::numeric_legacy_dates_use_local_midnight",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .env("TZ", "America/New_York")
                .output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        for (input, expected) in [
            ("0", "2000-01-01T05:00:00Z"),
            ("1", "2001-01-01T05:00:00Z"),
            ("12", "2001-12-01T05:00:00Z"),
            ("32", "2032-01-01T05:00:00Z"),
            ("99", "1999-01-01T05:00:00Z"),
            ("10000", "+010000-01-01T05:00:00Z"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
        assert_eq!(parse_date_millis("1000"), parse_date_millis("1000-01-01T00:00:00Z"));
    }

    #[test]
    fn legacy_dates_roll_over_days_within_the_javascript_range() {
        for (input, expected) in [
            ("2024/02/30", "2024-03-01T00:00:00"),
            ("02/30/2024", "2024-03-01T00:00:00"),
            ("2/31/2024", "2024-03-02T00:00:00"),
            ("Feb 30 2024 GMT", "2024-03-01T00:00:00Z"),
            ("30 Feb 2024 12:34 GMT", "2024-03-01T12:34:00Z"),
            ("2024/02/30 12:00:00", "2024-03-01T12:00:00"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
        for input in ["2024/02/32", "2024/00/01", "2024/02/00"] {
            assert_eq!(parse_date_millis(input), None, "{input}");
        }
    }

    #[test]
    fn legacy_datetime_seconds_are_optional() {
        for (input, expected) in [
            ("Jan 1 2024 12:34 GMT", "2024-01-01T12:34:00Z"),
            ("1 Jan 2024 12:34 EST", "2024-01-01T17:34:00Z"),
            ("Jan 1 2024 12:34", "2024-01-01T12:34:00"),
            ("2024/1/1 12:34", "2024-01-01T12:34:00"),
            ("1/1/2024 12:34", "2024-01-01T12:34:00"),
            ("Jan 1 2024 1:34 PM", "2024-01-01T13:34:00"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
    }

    #[test]
    fn legacy_datetime_years_use_javascript_century_pivot() {
        for (input, expected) in [
            ("Jan 1 49 12:00:00 GMT", "2049-01-01T12:00:00Z"),
            ("Jan 1 99 12:00:00 GMT", "1999-01-01T12:00:00Z"),
            ("Jan 1 00 GMT", "2000-01-01T00:00:00Z"),
            ("0049-01-01 12:00:00Z", "2049-01-01T12:00:00Z"),
            ("0049-01-01T12:00:00Z", "0049-01-01T12:00:00Z"),
            ("Jan 1 49 12:00:00", "2049-01-01T12:00:00"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
    }

    #[test]
    fn date_only_bounds_honor_explicit_timezone_tokens() {
        for (input, expected) in [
            ("01 Jan 2024 GMT", "2024-01-01T00:00:00Z"),
            ("Jan 1 2024 UTC", "2024-01-01T00:00:00Z"),
            ("January 1 2024 EST", "2024-01-01T05:00:00Z"),
            ("2024/1/1 GMT+0530", "2023-12-31T18:30:00Z"),
        ] {
            assert_eq!(parse_date_millis(input), parse_date_millis(expected), "{input}");
        }
        assert_eq!(parse_date_millis("Jan 1 2024 BOGUS"), None);
    }

    #[test]
    fn legacy_dates_accept_full_weekday_tokens() {
        let expected = parse_date_millis("2024-01-01T12:00:00Z");
        for weekday in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "mOnDaY"] {
            assert_eq!(
                parse_date_millis(&format!("{weekday}, 01 Jan 2024 12:00:00 GMT")),
                expected,
                "{weekday}"
            );
        }
        assert_eq!(parse_date_millis("Monday01 Jan 2024 12:00:00 GMT"), None);
        assert_eq!(parse_date_millis("Mon01 Jan 2024 12:00:00 GMT"), None);
    }
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
