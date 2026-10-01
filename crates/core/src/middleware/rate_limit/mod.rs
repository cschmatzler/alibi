#[cfg(test)]
mod tests;

use async_trait::async_trait;

use std::collections::HashMap;

use std::sync::Mutex;

use std::time::{Duration, Instant};

use super::Middleware;

use crate::error::AuthResult;

use crate::types::{AuthRequest, AuthResponse};

/// Configuration for the rate limiting middleware.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default rate limit applied to all endpoints.
    pub default: EndpointRateLimit,

    /// Per-endpoint overrides. Key is the path (e.g. "/sign-in/email").
    pub per_endpoint: HashMap<String, EndpointRateLimit>,

    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

/// Rate limit parameters for a single endpoint.
#[derive(Debug, Clone)]
pub struct EndpointRateLimit {
    /// Sliding window duration.
    pub window: Duration,

    /// Maximum number of requests allowed within the window.
    pub max_requests: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default: EndpointRateLimit {
                window: Duration::from_secs(60),
                max_requests: 100,
            },
            per_endpoint: HashMap::new(),
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

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// In-memory sliding-window rate limiter.
///
/// For production use with multiple instances, a `CacheAdapter`-backed
/// implementation should be used instead. This implementation is suitable
/// for single-process deployments and testing.
#[derive(Debug)]
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    /// Keyed by (`client_identifier`, path) → list of request timestamps.
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimitMiddleware {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Derive a client key from the request. Uses X-Forwarded-For, then
    /// falls back to a fixed key (single-bucket) when no IP is available.
    fn client_key(req: &AuthRequest) -> String {
        req.headers
            .get("x-forwarded-for")
            .or_else(|| req.headers.get("x-real-ip"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned())
    }

    fn limit_for_path(&self, path: &str) -> &EndpointRateLimit {
        self.config
            .per_endpoint
            .get(path)
            .unwrap_or(&self.config.default)
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    fn name(&self) -> &'static str {
        "rate-limit"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let limit = self.limit_for_path(&req.path);
        let key = format!("{}:{}", Self::client_key(req), req.path);
        let now = Instant::now();
        let window = limit.window;

        let mut buckets = self
            .buckets
            .lock()
            .map_err(|_error| crate::error::AuthError::internal("Rate-limit lock poisoned"))?;
        let timestamps = buckets.entry(key).or_default();

        // Remove timestamps outside the window
        timestamps.retain(|&t| now.duration_since(t) < window);

        if !u32::try_from(timestamps.len()).is_ok_and(|count| count < limit.max_requests) {
            let retry_after = timestamps.first().map_or(window.as_secs(), |&t| {
                window
                    .as_secs()
                    .saturating_sub(now.duration_since(t).as_secs())
            });

            drop(buckets);
            return Ok(Some(
                AuthResponse::json(
                    429,
                    &crate::types::RateLimitErrorResponse {
                        code: "RATE_LIMIT_EXCEEDED",
                        message: "Too many requests",
                        retry_after,
                    },
                )?
                .with_header("Retry-After", retry_after.to_string()),
            ));
        }

        timestamps.push(now);
        drop(buckets);
        Ok(None)
    }
}
