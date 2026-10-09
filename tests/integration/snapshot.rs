//! Normalized request traces compared against committed baselines.
//!
//! Ported compatibility scenarios record what each request returned. Values
//! that differ between runs (generated IDs, tokens, codes, timestamps) are
//! replaced with stable placeholders; a value that recurs keeps its
//! placeholder, so the baseline still proves which responses share an
//! identity. Run with `UPDATE_SNAPSHOTS=1` to rewrite baselines, then review
//! the diff.

use alibi::prelude::AuthResponse;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

/// Body fields whose string values are generated, however short.
const GENERATED_KEYS: &[&str] = &[
    "backupCodes",
    "key",
    "start",
    "token",
    "user_code",
    "userCode",
];
/// Body fields whose numbers depend on elapsed time.
const TIMING_KEYS: &[&str] = &["tryAgainIn", "expires_in", "expiresIn"];

#[derive(Default)]
pub(crate) struct Trace {
    entries: Vec<Value>,
    placeholders: HashMap<String, String>,
}

impl Trace {
    /// Record a response's status, notable headers and body under `label`.
    pub(crate) fn response(&mut self, label: &str, response: &AuthResponse) {
        let mut headers = Map::new();
        for (name, value) in response.headers.iter() {
            let name = name.to_ascii_lowercase();
            let value = match name.as_str() {
                "set-cookie" => Self::cookie(value),
                "location" | "content-type" => value.clone(),
                _ if name.starts_with("x-") => value.clone(),
                _ => continue,
            };
            let entry = headers
                .entry(name)
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(values) = entry {
                values.push(Value::String(value));
            }
        }
        let body = serde_json::from_slice(&response.body).unwrap_or_else(|_| {
            Value::String(String::from_utf8_lossy(&response.body).into_owned())
        });
        self.value(
            label,
            json!({"status": response.status, "headers": headers, "body": body}),
        );
    }

    /// Record an arbitrary observation, such as persisted rows.
    pub(crate) fn value(&mut self, label: &str, value: Value) {
        let value = self.normalize(value);
        self.entries.push(json!({ label: value }));
    }

    /// Treat a short generated value, such as a user code or OTP, as volatile.
    pub(crate) fn mask(&mut self, value: &str) {
        _ = self.placeholder("m", value);
    }

    /// Keep a cookie's name and attributes; mask its value and expiry date.
    /// Values are not correlated: signed timestamps can coincide within a second.
    fn cookie(header: &str) -> String {
        header
            .split(';')
            .enumerate()
            .map(|(index, part)| {
                let part = part.trim();
                match part.split_once('=') {
                    Some((name, value)) if index == 0 && !value.is_empty() => {
                        format!("{name}=<cookie>")
                    }
                    Some((name, _)) if name.eq_ignore_ascii_case("expires") => {
                        format!("{name}=<date>")
                    }
                    _ => part.to_owned(),
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Compare against `tests/fixtures/snapshots/<name>.json`.
    #[track_caller]
    pub(crate) fn assert(&self, name: &str) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/snapshots")
            .join(format!("{name}.json"));
        let actual = Value::Array(self.entries.clone());
        if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut text = serde_json::to_string_pretty(&actual).unwrap();
            text.push('\n');
            std::fs::write(&path, text).unwrap();
            return;
        }
        let expected: Value = std::fs::read_to_string(&path)
            .map(|text| serde_json::from_str(&text).unwrap())
            .unwrap_or_else(|_| {
                panic!(
                    "missing snapshot {}; run with UPDATE_SNAPSHOTS=1",
                    path.display()
                )
            });
        if actual != expected {
            let actual = serde_json::to_string_pretty(&actual).unwrap();
            let expected = serde_json::to_string_pretty(&expected).unwrap();
            let line = actual
                .lines()
                .zip(expected.lines())
                .position(|(left, right)| left != right)
                .unwrap_or_else(|| actual.lines().count().min(expected.lines().count()));
            let context = |text: &str| {
                text.lines()
                    .skip(line.saturating_sub(5))
                    .take(12)
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            panic!(
                "snapshot {name} differs at line {}\n--- expected\n{}\n--- actual\n{}",
                line + 1,
                context(&expected),
                context(&actual)
            );
        }
    }

    fn placeholder(&mut self, kind: &str, value: &str) -> String {
        let next = self.placeholders.len() + 1;
        self.placeholders
            .entry(value.to_owned())
            .or_insert_with(|| format!("<{kind}{next}>"))
            .clone()
    }

    fn normalize(&mut self, value: Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.normalize_text(&text)),
            Value::Number(number)
                if number
                    .as_f64()
                    .is_some_and(|value| value.abs() >= 1_000_000_000.0) =>
            {
                Value::String("<time>".into())
            }
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|value| self.normalize(value))
                    .collect(),
            ),
            Value::Object(object) => Value::Object(
                object
                    .into_iter()
                    .map(|(key, value)| {
                        let value = match value {
                            Value::String(text) if GENERATED_KEYS.contains(&key.as_str()) => {
                                Value::String(self.placeholder("g", &text))
                            }
                            Value::Array(values) if GENERATED_KEYS.contains(&key.as_str()) => {
                                Value::Array(
                                    values
                                        .into_iter()
                                        .map(|value| match value {
                                            Value::String(text) => {
                                                Value::String(self.placeholder("g", &text))
                                            }
                                            value => self.normalize(value),
                                        })
                                        .collect(),
                                )
                            }
                            Value::Number(_) if TIMING_KEYS.contains(&key.as_str()) => {
                                Value::String("<elapsed>".into())
                            }
                            value => self.normalize(value),
                        };
                        (key, value)
                    })
                    .collect(),
            ),
            other => other,
        }
    }

    /// Replace timestamps and generated runs of token characters: 16 or more
    /// with a digit or mixed case, or 24 or more plain alphanumerics.
    fn normalize_text(&mut self, text: &str) -> String {
        if chrono::DateTime::parse_from_rfc3339(text).is_ok()
            || chrono::DateTime::parse_from_rfc2822(text).is_ok()
        {
            return "<date>".into();
        }
        if let Some(placeholder) = self.placeholders.get(text) {
            return placeholder.clone();
        }
        let mut normalized = String::with_capacity(text.len());
        let mut run = String::new();
        let flush = |run: &mut String, normalized: &mut String, trace: &mut Self| {
            if let Some(placeholder) = trace.placeholders.get(run.as_str()) {
                normalized.push_str(placeholder);
            } else if run.len() >= 16
                && (run.bytes().any(|byte| byte.is_ascii_digit())
                    || (run.bytes().any(|byte| byte.is_ascii_uppercase())
                        && run.bytes().any(|byte| byte.is_ascii_lowercase()))
                    || (run.len() >= 24 && run.bytes().all(|byte| byte.is_ascii_alphanumeric())))
            {
                normalized.push_str(&trace.placeholder("v", run));
            } else {
                normalized.push_str(run);
            }
            run.clear();
        };
        for character in text.chars() {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                run.push(character);
            } else {
                flush(&mut run, &mut normalized, self);
                normalized.push(character);
            }
        }
        flush(&mut run, &mut normalized, self);
        normalized
    }
}
