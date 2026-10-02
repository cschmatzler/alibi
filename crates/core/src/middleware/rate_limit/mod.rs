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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HttpMethod;
    use std::collections::HashMap as StdHashMap;

    fn make_request(path: &str, ip: &str) -> AuthRequest {
        let mut headers = StdHashMap::new();
        headers.insert("x-forwarded-for".to_owned(), ip.to_owned());
        AuthRequest::from_parts(
            HttpMethod::Post,
            path.to_owned(),
            headers,
            None,
            StdHashMap::new(),
        )
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_allows_within_limit() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 5);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/get-session", "1.2.3.4");

        for _ in 0..5 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_blocks_over_limit() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 3);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/get-session", "1.2.3.4");

        for _ in 0..3 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }

        let resp = mw.before_request(&req).await.unwrap();
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status, 429);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_per_client() {
        let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 2);
        let mw = RateLimitMiddleware::new(config);

        let req_a = make_request("/get-session", "1.1.1.1");
        let req_b = make_request("/get-session", "2.2.2.2");

        // Client A uses up its limit
        for _ in 0..2 {
            assert!(mw.before_request(&req_a).await.unwrap().is_none());
        }
        assert!(mw.before_request(&req_a).await.unwrap().is_some());

        // Client B should still be allowed
        assert!(mw.before_request(&req_b).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_per_endpoint_override() {
        for (pattern, path) in [
            ("/sign-in/email", "/sign-in/email"),
            ("/sign-in/*", "/sign-in/email"),
            ("/email-otp/*", "/email-otp/send-verification-otp"),
        ] {
            let config = RateLimitConfig::new()
                .default_limit(Duration::from_secs(60), 100)
                .endpoint(pattern, Duration::from_secs(60), 2);
            let mw = RateLimitMiddleware::new(config);
            let req = make_request(path, "1.2.3.4");
            for _ in 0..2 {
                assert!(mw.before_request(&req).await.unwrap().is_none());
            }
            assert_eq!(mw.before_request(&req).await.unwrap().unwrap().status, 429);
        }
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let config = RateLimitConfig::new()
            .default_limit(Duration::from_secs(60), 1)
            .enabled(false);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request("/sign-in/email", "1.2.3.4");

        for _ in 0..10 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
    }

    // The real middleware must protect sensitive routes without application overrides.
    #[tokio::test]
    async fn default_sensitive_routes_are_limited_before_generic_routes() {
        for path in [
            "/sign-in/email",
            "/sign-up/email",
            "/change-password",
            "/change-email",
            "/request-password-reset",
            "/send-verification-email",
            "/forget-password/email",
            "/email-otp/send-verification-otp",
            "/email-otp/request-password-reset",
        ] {
            let mw = RateLimitMiddleware::new(RateLimitConfig::new());
            let req = make_request(path, "192.0.2.1");
            for _ in 0..3 {
                assert!(mw.before_request(&req).await.unwrap().is_none());
            }
            assert_eq!(
                mw.before_request(&req).await.unwrap().unwrap().status,
                429,
                "{path}"
            );
        }
        let mw = RateLimitMiddleware::new(RateLimitConfig::new());
        let req = make_request("/get-session", "192.0.2.1");
        for _ in 0..100 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        let response = mw.before_request(&req).await.unwrap().unwrap();
        assert_eq!(response.status, 429);
        assert!(
            response
                .headers
                .get("x-retry-after")
                .unwrap()
                .parse::<u64>()
                .unwrap()
                <= 10
        );
    }

    // Capacity and expiry are observable admission behavior, not private map layout.
    #[tokio::test]
    async fn bounded_buckets_preserve_active_quotas_and_recover_after_expiry() {
        let mw = RateLimitMiddleware::new(
            RateLimitConfig::new()
                .default_limit(Duration::from_millis(250), 2)
                .max_buckets(2),
        );
        let first = make_request("/get-session", "192.0.2.1");
        let second = make_request("/get-session", "192.0.2.2");
        let third = make_request("/get-session", "192.0.2.3");
        assert!(mw.before_request(&first).await.unwrap().is_none());
        assert!(mw.before_request(&second).await.unwrap().is_none());
        for _ in 0..8 {
            assert_eq!(
                mw.before_request(&third).await.unwrap().unwrap().status,
                429
            );
        }
        assert!(mw.before_request(&first).await.unwrap().is_none());
        assert_eq!(
            mw.before_request(&first).await.unwrap().unwrap().status,
            429
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(mw.before_request(&third).await.unwrap().is_none());
        assert!(mw.before_request(&first).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mounted_and_internal_paths_share_sensitive_route_quotas() {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new()).with_base_path("/api/auth/");
        let mounted = make_request("/api/auth/sign-in/email", "192.0.2.1");
        let internal = make_request("/sign-in/email", "192.0.2.1");
        assert!(mw.before_request(&mounted).await.unwrap().is_none());
        assert!(mw.before_request(&internal).await.unwrap().is_none());
        assert!(mw.before_request(&mounted).await.unwrap().is_none());
        assert_eq!(
            mw.before_request(&internal).await.unwrap().unwrap().status,
            429
        );
        let other_mount = make_request("/unrelated/sign-in/email", "192.0.2.1");
        for _ in 0..4 {
            assert!(mw.before_request(&other_mount).await.unwrap().is_none());
        }
    }
}
// LCOV_EXCL_STOP
