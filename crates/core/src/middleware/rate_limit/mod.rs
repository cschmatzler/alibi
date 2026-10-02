#[cfg(test)]
mod tests;

use super::Middleware;
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse};
use async_trait::async_trait;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for the rate limiting middleware.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default limit for endpoints without a built-in special rule or custom override.
    pub default: EndpointRateLimit,

    /// Exact or glob path overrides. Exact matches win, then the most specific glob.
    pub per_endpoint: HashMap<String, EndpointRateLimit>,

    /// Maximum live client/path buckets. New buckets fail closed at capacity.
    pub max_buckets: usize,

    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

/// Rate limit parameters for a single endpoint.
#[derive(Debug, Clone)]
pub struct EndpointRateLimit {
    /// Rolling inactivity window, extended by each allowed request.
    pub window: Duration,

    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default: EndpointRateLimit {
                window: Duration::from_secs(10),
                max_requests: 100,
            },
            per_endpoint: HashMap::new(),
            max_buckets: 100_000,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn default_limit(mut self, window: Duration, max_requests: u32) -> Self {
        self.default = EndpointRateLimit {
            window,
            max_requests,
        };
        self
    }

    #[must_use]
    pub fn endpoint(
        mut self,
        path: impl Into<String>,
        window: Duration,
        max_requests: u32,
    ) -> Self {
        _ = self.per_endpoint.insert(
            path.into(),
            EndpointRateLimit {
                window,
                max_requests,
            },
        );
        self
    }

    /// Bound memory without evicting active clients and resetting their quotas.
    #[must_use]
    pub const fn max_buckets(mut self, maximum: usize) -> Self {
        self.max_buckets = maximum;
        self
    }

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// An atomic in-memory rolling-window limiter for one process.
///
/// Each allowed request extends the current window until its quota is exhausted.
/// Expired buckets are removed through an ordered expiry index. Both indexes
/// are bounded by `max_buckets`; no per-request timestamp list is retained.
/// Multiple application instances require a shared rate limiter upstream.
#[derive(Debug)]
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    base_path: String,
    state: Mutex<RateLimitState>,
}

#[derive(Debug, Default)]
struct RateLimitState {
    buckets: HashMap<(String, String), Bucket>,
    expirations: BTreeSet<(Instant, (String, String))>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    deadline: Instant,
    count: u32,
}

const AUTH_LIMIT: EndpointRateLimit = EndpointRateLimit {
    window: Duration::from_secs(10),
    max_requests: 3,
};
const EMAIL_LIMIT: EndpointRateLimit = EndpointRateLimit {
    window: Duration::from_secs(60),
    max_requests: 3,
};

impl RateLimitMiddleware {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            base_path: String::new(),
            state: Mutex::new(RateLimitState::default()),
        }
    }

    /// Match and key routes relative to the application's auth mount path.
    #[must_use]
    pub fn with_base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into().trim_end_matches('/').to_owned();
        self
    }

    /// Use the same trusted, normalized IP policy as persisted session metadata.
    /// Requests without a resolved IP share one per-path bucket.
    fn client_key(req: &AuthRequest) -> String {
        let policy = req.extensions().get::<crate::config::IpAddressConfig>();
        policy
            .as_ref()
            .map_or_else(
                || crate::config::IpAddressConfig::default().resolve_ip(&req.headers),
                |policy| policy.resolve_ip(&req.headers),
            )
            .unwrap_or_else(|| "no-trusted-ip".to_owned())
    }

    fn limit_for_path(&self, path: &str) -> &EndpointRateLimit {
        if let Some(limit) = self.config.per_endpoint.get(path) {
            return limit;
        }
        if let Some((_, limit)) = self
            .config
            .per_endpoint
            .iter()
            .filter(|(pattern, _)| {
                pattern.contains(['*', '?']) && glob_match::glob_match(pattern, path)
            })
            .max_by(|(left, _), (right, _)| {
                let specificity =
                    |pattern: &str| pattern.chars().filter(|c| !matches!(c, '*' | '?')).count();
                specificity(left)
                    .cmp(&specificity(right))
                    .then_with(|| right.cmp(left))
            })
        {
            return limit;
        }
        if ["/sign-in", "/sign-up", "/change-password", "/change-email"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            return &AUTH_LIMIT;
        }
        if matches!(
            path,
            "/request-password-reset"
                | "/send-verification-email"
                | "/email-otp/send-verification-otp"
                | "/email-otp/request-password-reset"
        ) || path.starts_with("/forget-password")
        {
            return &EMAIL_LIMIT;
        }
        &self.config.default
    }

    fn blocked(remaining: Duration) -> AuthResponse {
        let retry_after = remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() != 0));
        AuthResponse::text(
            429,
            r#"{"message":"Too many requests. Please try again later."}"#,
        )
        .with_header("content-type", "text/plain;charset=utf-8")
        .with_header("X-Retry-After", retry_after.to_string())
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled
            || req
                .extensions()
                .get::<crate::config::IpAddressConfig>()
                .is_some_and(|policy| policy.disable_ip_tracking)
        {
            return Ok(None);
        }

        let path = req
            .path
            .strip_prefix(&self.base_path)
            .filter(|suffix| suffix.starts_with('/'))
            .unwrap_or(&req.path);
        let limit = self.limit_for_path(path);
        let key = (Self::client_key(req), path.to_owned());
        let now = Instant::now();
        let deadline = now
            .checked_add(limit.window)
            .ok_or_else(|| crate::error::AuthError::internal("Rate-limit window is too large"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| crate::error::AuthError::internal("Rate-limit lock poisoned"))?;

        while state
            .expirations
            .first()
            .is_some_and(|(expiry, _)| *expiry <= now)
        {
            if let Some((_, expired_key)) = state.expirations.pop_first() {
                _ = state.buckets.remove(&expired_key);
            }
        }
        let count = if let Some(previous) = state.buckets.get(&key).copied() {
            if previous.count >= limit.max_requests {
                return Ok(Some(Self::blocked(
                    previous.deadline.saturating_duration_since(now),
                )));
            }
            _ = state.expirations.remove(&(previous.deadline, key.clone()));
            previous.count + 1
        } else {
            if limit.max_requests == 0 || state.buckets.len() >= self.config.max_buckets {
                let remaining = state
                    .expirations
                    .first()
                    .map_or(limit.window, |(expiry, _)| {
                        expiry.saturating_duration_since(now)
                    });
                return Ok(Some(Self::blocked(remaining)));
            }
            1
        };
        _ = state
            .buckets
            .insert(key.clone(), Bucket { deadline, count });
        _ = state.expirations.insert((deadline, key));
        drop(state);
        Ok(None)
    }
}
