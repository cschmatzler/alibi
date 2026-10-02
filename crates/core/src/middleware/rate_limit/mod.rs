#[cfg(test)]
mod tests;

use super::Middleware;
use crate::error::AuthResult;
use crate::types::{AuthRequest, AuthResponse};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn path_matches(pattern: &str, path: &str) -> AuthResult<bool> {
    if !pattern.contains('*') {
        return Ok(pattern == path);
    }
    let mut expression = String::from("^");
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        match character {
            '*' => expression.push_str(".*?"),
            '?' => expression.push('.'),
            '\\' => {
                if let Some(escaped) = characters.next() {
                    expression.push_str(&regex::escape(&escaped.to_string()));
                }
            }
            literal => expression.push_str(&regex::escape(&literal.to_string())),
        }
    }
    expression.push('$');
    regex::Regex::new(&expression)
        .map(|compiled| compiled.is_match(path))
        .map_err(|_| crate::error::AuthError::internal("Invalid rate-limit path pattern"))
}

/// A rate-limit backend must atomically decide and consume before returning.
#[async_trait]
pub trait RateLimitStorage: Send + Sync + std::fmt::Debug {
    /// Publish configured windows before serving requests, so persistent
    /// storage can prune without retiring a longer-lived configured quota.
    fn observe_window(&self, _window_seconds: f64) {}

    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision>;
}

#[derive(Debug, Clone, Copy)]
pub enum RateLimitDecision {
    Allowed,
    Blocked { retry_after: f64 },
}

/// Bounded rolling in-memory storage. Share an `Arc` between auth instances
/// when they must consume the same client/path quotas.
#[derive(Debug)]
pub struct MemoryRateLimitStorage {
    state: Mutex<RateLimitState>,
    max_buckets: usize,
}

impl MemoryRateLimitStorage {
    #[must_use]
    pub fn new(max_buckets: usize) -> Self {
        Self {
            state: Mutex::new(RateLimitState::default()),
            max_buckets,
        }
    }
    fn consume_memory(
        &self,
        key: String,
        limit: &EndpointRateLimit,
    ) -> AuthResult<RateLimitDecision> {
        let now = Instant::now();
        let deadline = Duration::try_from_secs_f64(limit.window_seconds)
            .ok()
            .and_then(|window| now.checked_add(window));
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
        // Non-positive and NaN windows have no live memory entry in Source.
        if limit.window_seconds <= 0.0 || limit.window_seconds.is_nan() {
            if let Some(previous) = state.buckets.remove(&key)
                && let Some(deadline) = previous.deadline
            {
                _ = state.expirations.remove(&(deadline, key));
            }
            return Ok(RateLimitDecision::Allowed);
        }
        let count = if let Some(previous) = state.buckets.get(&key).copied() {
            let elapsed = now.duration_since(previous.last_request).as_secs_f64();
            let expired = elapsed >= limit.window_seconds;
            if !expired && previous.count >= limit.max_requests {
                return Ok(RateLimitDecision::Blocked {
                    retry_after: (limit.window_seconds
                        - now.duration_since(previous.last_request).as_secs_f64())
                    .ceil(),
                });
            }
            if let Some(deadline) = previous.deadline {
                _ = state.expirations.remove(&(deadline, key.clone()));
            }
            if expired { 1.0 } else { previous.count + 1.0 }
        } else {
            if state.buckets.len() >= self.max_buckets {
                let remaining = state
                    .expirations
                    .first()
                    .map_or(limit.window_seconds, |(expiry, _)| {
                        expiry.saturating_duration_since(now).as_secs_f64()
                    });
                return Ok(RateLimitDecision::Blocked {
                    retry_after: remaining.ceil(),
                });
            }
            1.0
        };
        _ = state.buckets.insert(
            key.clone(),
            Bucket {
                deadline,
                last_request: now,
                count,
            },
        );
        if let Some(deadline) = deadline {
            _ = state.expirations.insert((deadline, key));
        }
        Ok(RateLimitDecision::Allowed)
    }
}

#[async_trait]
impl RateLimitStorage for MemoryRateLimitStorage {
    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        self.consume_memory(key.to_owned(), rule)
    }
}

/// Shared fixed-window counter backed by the application's existing cache.
/// Every attempt increments, including blocked attempts; retries report the full window.
pub struct CacheRateLimitStorage {
    cache: Arc<dyn crate::store::cache::CacheAdapter>,
}

impl std::fmt::Debug for CacheRateLimitStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheRateLimitStorage")
            .finish_non_exhaustive()
    }
}

impl CacheRateLimitStorage {
    #[must_use]
    pub fn new(cache: Arc<dyn crate::store::cache::CacheAdapter>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl RateLimitStorage for CacheRateLimitStorage {
    async fn consume(&self, key: &str, rule: &EndpointRateLimit) -> AuthResult<RateLimitDecision> {
        let ttl = Duration::try_from_secs_f64(rule.window_seconds)
            .map_err(|_| crate::error::AuthError::internal("Invalid shared rate-limit window"))?;
        let count = self.cache.increment(key, ttl).await?;
        Ok(if count <= rule.max_requests {
            RateLimitDecision::Allowed
        } else {
            RateLimitDecision::Blocked {
                retry_after: rule.window_seconds,
            }
        })
    }
}

/// Application-owned request policy; returning `None` disables this request's limit.
#[async_trait]
pub trait RateLimitResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(
        &self,
        request: &AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> AuthResult<Option<EndpointRateLimit>>;
}

#[derive(Debug, Clone)]
pub enum RateLimitRule {
    Limit(EndpointRateLimit),
    Disabled,
    Dynamic(Arc<dyn RateLimitResolver>),
}

/// Plugin rules are evaluated in installation order, before application overrides.
#[derive(Debug, Clone)]
pub struct PluginRateLimit {
    pub matches: fn(&str) -> bool,
    pub limit: EndpointRateLimit,
}

/// Configuration for the rate limiting middleware.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default limit for endpoints without a built-in special rule or custom override.
    pub default: EndpointRateLimit,

    /// Ordered path overrides. The first matching rule wins.
    pub per_endpoint: IndexMap<String, RateLimitRule>,

    /// Shared atomic storage; absent selects bounded process-local memory.
    pub storage: Option<Arc<dyn RateLimitStorage>>,

    /// Maximum live client/path buckets. New buckets fail closed at capacity.
    pub max_buckets: usize,

    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

/// Rate limit parameters for a single endpoint.
#[derive(Debug, Clone)]
pub struct EndpointRateLimit {
    /// Rolling inactivity window, extended by each allowed request.
    pub window_seconds: f64,

    /// Maximum number of requests allowed within the window.
    pub max_requests: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default: EndpointRateLimit {
                window_seconds: 10.0,
                max_requests: 100.0,
            },
            per_endpoint: IndexMap::new(),
            storage: None,
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
    pub fn default_limit(mut self, window: Duration, max_requests: u32) -> Self {
        self.default = EndpointRateLimit {
            window_seconds: window.as_secs_f64(),
            max_requests: f64::from(max_requests),
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
            RateLimitRule::Limit(EndpointRateLimit {
                window_seconds: window.as_secs_f64(),
                max_requests: f64::from(max_requests),
            }),
        );
        self
    }

    #[must_use]
    pub fn rule(mut self, path: impl Into<String>, rule: RateLimitRule) -> Self {
        drop(self.per_endpoint.insert(path.into(), rule));
        self
    }

    #[must_use]
    pub fn storage(mut self, storage: Arc<dyn RateLimitStorage>) -> Self {
        self.storage = Some(storage);
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

/// Request policies with atomic rolling or fixed-window storage.
///
/// Each allowed request extends the current window until its quota is exhausted.
/// Expired buckets are removed through an ordered expiry index. Both indexes
/// are bounded by `max_buckets`; no per-request timestamp list is retained.
/// Independent processes can install shared database/cache storage.
#[derive(Debug)]
pub struct RateLimitMiddleware {
    config: RateLimitConfig,
    base_path: String,
    memory: MemoryRateLimitStorage,
    plugin_rules: Vec<PluginRateLimit>,
}

#[derive(Debug, Default)]
struct RateLimitState {
    buckets: HashMap<String, Bucket>,
    expirations: BTreeSet<(Instant, String)>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    deadline: Option<Instant>,
    last_request: Instant,
    count: f64,
}

const AUTH_LIMIT: EndpointRateLimit = EndpointRateLimit {
    window_seconds: 10.0,
    max_requests: 3.0,
};
const EMAIL_LIMIT: EndpointRateLimit = EndpointRateLimit {
    window_seconds: 60.0,
    max_requests: 3.0,
};

impl RateLimitMiddleware {
    #[must_use]
    pub fn new(mut config: RateLimitConfig) -> Self {
        if config.default.window_seconds == 0.0 || config.default.window_seconds.is_nan() {
            config.default.window_seconds = 10.0;
        }
        if config.default.max_requests == 0.0 || config.default.max_requests.is_nan() {
            config.default.max_requests = 100.0;
        }
        let memory = MemoryRateLimitStorage::new(config.max_buckets);
        if let Some(storage) = &config.storage {
            storage.observe_window(config.default.window_seconds);
            storage.observe_window(AUTH_LIMIT.window_seconds);
            storage.observe_window(EMAIL_LIMIT.window_seconds);
            for rule in config.per_endpoint.values() {
                if let RateLimitRule::Limit(limit) = rule {
                    storage.observe_window(limit.window_seconds);
                }
            }
        }
        Self {
            config,
            base_path: String::new(),
            memory,
            plugin_rules: Vec::new(),
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

    #[must_use]
    pub fn with_plugin_rules(mut self, rules: Vec<PluginRateLimit>) -> Self {
        if let Some(storage) = &self.config.storage {
            for rule in &rules {
                storage.observe_window(rule.limit.window_seconds);
            }
        }
        self.plugin_rules = rules;
        self
    }

    async fn limit_for_request(
        &self,
        req: &AuthRequest,
        path: &str,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        let mut limit = self.default_limit_for_path(path).clone();
        if let Some(rule) = self.plugin_rules.iter().find(|rule| (rule.matches)(path)) {
            limit = rule.limit.clone();
        }
        for (pattern, rule) in &self.config.per_endpoint {
            if path_matches(pattern, path)? {
                return match rule {
                    RateLimitRule::Limit(limit) => Ok(Some(limit.clone())),
                    RateLimitRule::Disabled => Ok(None),
                    RateLimitRule::Dynamic(resolver) => resolver.resolve(req, &limit).await,
                };
            }
        }
        Ok(Some(limit))
    }

    fn default_limit_for_path(&self, path: &str) -> &EndpointRateLimit {
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

    fn blocked(retry_after: f64) -> AuthResponse {
        AuthResponse::text(
            429,
            r#"{"message":"Too many requests. Please try again later."}"#,
        )
        .with_header("content-type", "text/plain;charset=utf-8")
        .with_header(
            "X-Retry-After",
            ryu_js::Buffer::new().format(retry_after).to_owned(),
        )
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

        let requested = req.path.trim_end_matches('/');
        let path = if requested == self.base_path || requested.is_empty() {
            "/"
        } else {
            requested
                .strip_prefix(&self.base_path)
                .filter(|suffix| suffix.starts_with('/'))
                .unwrap_or(requested)
        };
        let Some(limit) = self.limit_for_request(req, path).await? else {
            return Ok(None);
        };
        let ip = Self::client_key(req);
        let decision = if let Some(storage) = &self.config.storage {
            storage.consume(&format!("{ip}|{path}"), &limit).await?
        } else {
            self.memory.consume(&format!("{ip}|{path}"), &limit).await?
        };
        Ok(match decision {
            RateLimitDecision::Allowed => None,
            RateLimitDecision::Blocked { retry_after } => Some(Self::blocked(retry_after)),
        })
    }
}
