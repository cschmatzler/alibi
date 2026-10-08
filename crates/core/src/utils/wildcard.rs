//! Better Auth's `wildcardMatch` and the simple path globs used by rate limits.

use regex::Regex;

const SEPARATOR: &str = r"[/\\]";
const SEGMENT_CHARACTER: &str = r"[^/\\]";
const SEGMENT_RUN: &str = r"[^/\\]*?";

/// Compile a separator-aware pattern: `*` and `?` stay within a `/`- or
/// `\`-delimited segment, and a whole `**` segment spans any number of segments.
///
/// # Errors
/// Returns the regex compilation error for patterns exceeding the size limit.
pub fn compile(pattern: &str) -> Result<Regex, regex::Error> {
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
                expression.push_str(&format!("(?:{SEGMENT_RUN}{separator})*?"));
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
    Regex::new(&expression)
}

/// Match `value` against a [`compile`]d pattern.
#[must_use]
pub fn matches(pattern: &str, value: &str) -> bool {
    compile(pattern).is_ok_and(|compiled| compiled.is_match(value))
}

/// Compile a path glob in which `*` matches any characters, including separators.
///
/// # Errors
/// Returns the regex compilation error for patterns exceeding the size limit.
pub fn compile_path_glob(pattern: &str) -> Result<Regex, regex::Error> {
    let mut expression = String::from("^");
    translate(&mut expression, pattern, |character| match character {
        '*' => Some(".*?"),
        '?' => Some("."),
        _ => None,
    });
    expression.push('$');
    Regex::new(&expression)
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
            ('\\', _) => match characters.next() {
                Some(escaped) => escaped,
                None => continue,
            },
            (_, Some(translated)) => {
                expression.push_str(translated);
                continue;
            }
            (literal, None) => literal,
        };
        expression.push_str(&regex::escape(literal.encode_utf8(&mut [0; 4])));
    }
}
