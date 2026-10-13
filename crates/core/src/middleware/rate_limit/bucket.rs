//! Rolling-window quota arithmetic shared by the database-backed rate limiters.
//!
//! A bucket stores a request `count` and the `last_request` time in Unix
//! milliseconds. Storage adapters read a
//! bucket, call [`step`], and write the result back under a compare-and-swap
//! predicate on the observed `count` and `last_request`.

use super::{EndpointRateLimit, RateLimitDecision};

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
