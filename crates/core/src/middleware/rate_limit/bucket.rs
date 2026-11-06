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
    let elapsed = (crate::utils::javascript::number_from_i64(now)
        - crate::utils::javascript::number_from_i64(last_request))
        / 1000.0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_last_request_extends_retry_after() {
        let rule = EndpointRateLimit {
            window_seconds: 10.0,
            max_requests: 3.0,
        };
        assert_eq!(
            step(3.0, 3000, 1000, &rule),
            Step::Blocked { retry_after: 12.0 }
        );
        assert_eq!(
            step(2.0, 3000, 1000, &rule),
            Step::Allowed { count: 3.0, reset: false }
        );
        assert_eq!(
            step(3.0, 3000, 13000, &rule),
            Step::Allowed { count: 1.0, reset: true }
        );
    }
}
