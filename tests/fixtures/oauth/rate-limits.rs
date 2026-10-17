use alibi::EndpointRateLimit;
use alibi::middleware::{RateLimitConfig, RateLimitRule};
use alibi::plugins::{OAuthEndpointRateLimit, OAuthProviderRateLimits};
use std::time::Duration;

pub(crate) fn policies(mode: &str) -> (OAuthProviderRateLimits, RateLimitConfig) {
    let mut provider = OAuthProviderRateLimits::default();
    let mut global = RateLimitConfig::new().default_limit(Duration::from_secs(120), 2);
    if matches!(mode, "rate-override" | "rate-global-disabled") {
        provider.token = OAuthEndpointRateLimit::Limit(EndpointRateLimit {
            window_seconds: 120.0,
            max_requests: 2.0,
        });
        provider.authorize = OAuthEndpointRateLimit::Limit(EndpointRateLimit {
            window_seconds: 60.0,
            max_requests: 0.0,
        });
        provider.introspect = OAuthEndpointRateLimit::Limit(EndpointRateLimit {
            window_seconds: 0.0,
            max_requests: 1.0,
        });
    }
    if mode == "rate-false" {
        provider = OAuthProviderRateLimits {
            token: OAuthEndpointRateLimit::Disabled,
            authorize: OAuthEndpointRateLimit::Disabled,
            introspect: OAuthEndpointRateLimit::Disabled,
            revoke: OAuthEndpointRateLimit::Disabled,
            register: OAuthEndpointRateLimit::Disabled,
            userinfo: OAuthEndpointRateLimit::Disabled,
        };
    }
    if mode == "rate-global-disabled" {
        global = global.enabled(false);
    }
    if mode == "rate-application" {
        global = global
            .rule("/oauth2/token", RateLimitRule::Disabled)
            .endpoint("/oauth2/*", Duration::from_secs(180), 1);
    }
    (provider, global)
}
