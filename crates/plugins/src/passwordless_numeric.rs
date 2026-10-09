//! Numeric passwordless settings retain their IEEE754 configuration semantics.
use alibi_core::{AuthError, AuthResult};
use chrono::{DateTime, Utc};
use num_traits::ToPrimitive;
use rand::RngExt;

pub(super) fn generate_code(length: f64) -> AuthResult<String> {
    if length.is_nan() {
        return Ok(String::new());
    }
    if length <= 0.0 {
        return Err(AuthError::internal("Length must be a positive integer."));
    }
    // Source allocates floor(length * 2) random bytes. Below 0.5 it cannot
    // advance; at or above 32768.5 Web Crypto rejects the >65536-byte buffer.
    // Reject those unsafe/nonterminating inputs without allocation or looping.
    if !(0.5..32768.5).contains(&length) {
        return Err(AuthError::internal("Unsupported random code length"));
    }
    let count = length
        .ceil()
        .to_u32()
        .ok_or_else(|| AuthError::internal("Unsupported random code length"))?;
    let mut rng = rand::rng();
    Ok((0..count)
        .map(|_| char::from(b'0' + rng.random_range(0..10)))
        .collect())
}

pub(super) fn expires_at(seconds: f64, zero_nan_default: bool) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let seconds = if zero_nan_default && (seconds == 0.0 || seconds.is_nan()) {
        300.0
    } else {
        seconds
    };
    let milliseconds = now.timestamp_millis().to_f64()? + seconds * 1000.0;
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return None;
    }
    let milliseconds = milliseconds.trunc().to_i64()?;
    DateTime::from_timestamp_millis(milliseconds)
}

pub(super) fn attempts_number(attempts: usize) -> f64 {
    // Counters are parsed as integers; convert at the numeric comparison only.
    attempts.to_f64().unwrap_or(f64::INFINITY)
}
