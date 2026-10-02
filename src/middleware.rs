//! Middleware traits and configuration types.

pub use better_auth_core::middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CacheRateLimitStorage, CorsConfig, CorsMiddleware,
    CsrfConfig, CsrfMiddleware, EndpointRateLimit, MemoryRateLimitStorage, Middleware,
    PluginRateLimit, RateLimitConfig, RateLimitDecision, RateLimitMiddleware, RateLimitResolver,
    RateLimitRule, RateLimitStorage,
};
