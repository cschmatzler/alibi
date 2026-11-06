//! Better Auth's `wildcardMatch` and the simple path globs used by rate limits.

use crate::utils::LockUnpoisoned;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{LazyLock, Mutex};

const SEPARATOR: &str = r"[/\\]";
const SEGMENT_CHARACTER: &str = r"[^/\\]";
const SEGMENT_RUN: &str = r"[^/\\]*?";

/// A compiled JavaScript glob, matching UTF-16 code units rather than scalars.
#[derive(Clone, Debug)]
pub struct Wildcard {
    regex: Regex,
}

impl Wildcard {
    #[must_use]
    pub fn is_match(&self, value: &str) -> bool {
        self.regex.is_match(&utf16_sample(value))
    }
}

// Shift the surrogate range and everything above it to valid, disjoint Rust
// scalars. ASCII separators, regex syntax and line terminators stay unchanged.
fn utf16_sample(value: &str) -> Cow<'_, str> {
    if value.chars().all(|character| u32::from(character) < 0xd800) {
        return Cow::Borrowed(value);
    }
    Cow::Owned(
        value
            .encode_utf16()
            .map(|unit| {
                let scalar = u32::from(unit) + if unit >= 0xd800 { 0x800 } else { 0 };
                char::from_u32(scalar).expect("shifted UTF-16 units are Unicode scalars")
            })
            .collect(),
    )
}

/// Compile a separator-aware pattern: `*` and `?` stay within a `/`- or
/// `\`-delimited segment, and a whole `**` segment spans any number of segments.
///
/// # Errors
/// Returns the regex compilation error for patterns exceeding the size limit.
pub fn compile(pattern: &str) -> Result<Wildcard, regex::Error> {
    let segments: Vec<_> = pattern.split('/').collect();
    let mut expression = String::from("^");
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() && index > 0 {
            continue;
        }
        let separator = if index + 1 == segments.len() {
            format!("{SEPARATOR}*?")
        } else if segments.get(index + 1) == Some(&"**") {
            String::new()
        } else {
            format!("{SEPARATOR}+?")
        };
        if *segment == "**" {
            if !separator.is_empty() {
                if index > 0 {
                    expression.push_str(&separator);
                }
                _ = write!(expression, "(?:{SEGMENT_RUN}{separator})*?");
            }
            continue;
        }
        translate(&mut expression, segment, |character| match character {
            '*' => Some(SEGMENT_RUN),
            '?' => Some(SEGMENT_CHARACTER),
            _ => None,
        });
        expression.push_str(&separator);
    }
    expression.push('$');
    Regex::new(&expression).map(|regex| Wildcard { regex })
}

/// Match `value` against a [`compile`]d pattern. Compiled patterns are cached,
/// since trusted-origin matching evaluates the same few patterns on every request.
#[must_use]
pub fn matches(pattern: &str, value: &str) -> bool {
    const CACHE_LIMIT: usize = 256;
    static CACHE: LazyLock<Mutex<HashMap<String, Option<Wildcard>>>> =
        LazyLock::new(Mutex::default);
    let compiled = {
        let mut cache = CACHE.lock_unpoisoned();
        if cache.len() >= CACHE_LIMIT && !cache.contains_key(pattern) {
            cache.clear();
        }
        cache
            .entry(pattern.to_owned())
            .or_insert_with(|| compile(pattern).ok())
            .clone()
    };
    compiled.is_some_and(|compiled| compiled.is_match(value))
}

/// Compile a path glob in which `*` matches any characters, including separators.
///
/// # Errors
/// Returns the regex compilation error for patterns exceeding the size limit.
pub fn compile_path_glob(pattern: &str) -> Result<Wildcard, regex::Error> {
    let mut expression = String::from("^");
    translate(&mut expression, pattern, |character| match character {
        '*' => Some(r"[^\n\r\u{2028}\u{2029}]*?"),
        '?' => Some(r"[^\n\r\u{2028}\u{2029}]"),
        _ => None,
    });
    expression.push('$');
    Regex::new(&expression).map(|regex| Wildcard { regex })
}

/// Append `pattern` to `expression`, escaping every character that `special`
/// does not translate. A backslash escapes the following character.
fn translate(
    expression: &mut String,
    pattern: &str,
    special: impl Fn(char) -> Option<&'static str>,
) {
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        let literal = match (character, special(character)) {
            ('\\', _) => {
                let Some(escaped) = characters.next() else {
                    continue;
                };
                escaped
            }
            (_, Some(translated)) => {
                expression.push_str(translated);
                continue;
            }
            (literal, None) => literal,
        };
        expression.push_str(&regex::escape(&utf16_sample(
            literal.encode_utf8(&mut [0; 4]),
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_questions_consume_utf16_code_units() {
        for compile in [compile, compile_path_glob] {
            assert!(!compile("/?").unwrap().is_match("/😀"));
            assert!(compile("/??").unwrap().is_match("/😀"));
            assert!(compile("/?*?").unwrap().is_match("/😀"));
            assert!(compile("/😀?").unwrap().is_match("/😀x"));
            assert!(compile(r"/\😀?").unwrap().is_match("/😀x"));
            assert!(!compile("/??").unwrap().is_match("/\u{e000}"));
            assert!(compile("/\u{e000}").unwrap().is_match("/\u{e000}"));
            assert!(!compile("/😀").unwrap().is_match("/\u{e03d}\u{e600}"));
        }
    }

    #[test]
    fn path_globs_exclude_all_javascript_line_terminators() {
        for separator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
            let path = format!("/a{separator}b");
            assert!(!compile_path_glob("/a*b").unwrap().is_match(&path));
            assert!(!compile_path_glob("/a?b").unwrap().is_match(&path));
            assert!(compile_path_glob(&path).unwrap().is_match(&path));
        }
        assert!(compile_path_glob("/a*b").unwrap().is_match("/a/b"));
        assert!(compile_path_glob("/a?b").unwrap().is_match("/a\tb"));
    }
}
