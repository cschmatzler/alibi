//! Rolling-window quota arithmetic shared by the database-backed rate limiters.
//!
//! A bucket stores a request `count`, the `last_request` time and an
//! `expires_at` hint, all in Unix milliseconds. Storage adapters read a
//! bucket, call [`step`], and write the result back under a compare-and-swap
//! predicate on the observed `count` and `last_request`.

use super::{EndpointRateLimit, RateLimitDecision};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The outcome of one request against an observed bucket.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    /// Over quota inside the window.
    Blocked { retry_after: f64 },
    /// Admitted; store `count`. `reset` means the window had elapsed.
    Allowed { count: f64, reset: bool },
}

impl From<Step> for Option<RateLimitDecision> {
    fn from(step: Step) -> Self {
        match step {
            Step::Blocked { retry_after } => Some(RateLimitDecision::Blocked { retry_after }),
            Step::Allowed { .. } => None,
        }
    }
}

/// Decide one request given the stored `count` and `last_request`.
#[must_use]
pub fn step(count: f64, last_request: i64, now: i64, rule: &EndpointRateLimit) -> Step {
    let elapsed = chrono::Duration::milliseconds(now.saturating_sub(last_request))
        .to_std()
        .map_or(0.0, |duration| duration.as_secs_f64());
    let expired = elapsed >= rule.window_seconds;
    if !expired
        && (rule.window_seconds.is_nan()
            || rule.max_requests.is_nan()
            || count >= rule.max_requests)
    {
        return Step::Blocked {
            retry_after: (rule.window_seconds - elapsed).ceil(),
        };
    }
    Step::Allowed {
        count: if expired { 1.0 } else { count + 1.0 },
        reset: expired,
    }
}

/// When a bucket admitted at `now` stops mattering. Degenerate windows expire
/// immediately; an overflowing window never expires.
#[must_use]
pub fn expires_at(now: i64, window: f64) -> Option<i64> {
    if window <= 0.0 || window.is_nan() {
        return Some(now);
    }
    millis(window).and_then(|milliseconds| now.checked_add(milliseconds))
}

fn millis(seconds: f64) -> Option<i64> {
    Duration::try_from_secs_f64(seconds)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
}

/// The longest window any rule has used, so pruning never discards a bucket
/// a live rule could still consult.
#[derive(Debug)]
pub struct LongestWindow(AtomicU64);

impl Default for LongestWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl LongestWindow {
    /// Starts at sixty seconds, the default endpoint window.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU64::new(60.0_f64.to_bits()))
    }

    pub fn observe(&self, window: f64) {
        if window > 0.0 {
            // Positive IEEE-754 bit patterns order like their values, so this
            // is an atomic maximum.
            _ = self.0.fetch_max(window.to_bits(), Ordering::Relaxed);
        }
    }

    /// Buckets last touched before this instant are safe to delete.
    #[must_use]
    pub fn prune_cutoff(&self, now: i64) -> Option<i64> {
        millis(f64::from_bits(self.0.load(Ordering::Relaxed)))
            .and_then(|milliseconds| now.checked_sub(milliseconds))
    }
}
