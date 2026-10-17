//! Protocol quotas registered with the application's canonical rate limiter.
use alibi_core::{EndpointRateLimit, PluginRateLimit};

/// A provider rule can inherit its endpoint default, replace it, or be omitted.
/// `Disabled` omits only the plugin rule: global/application policy still applies.
#[derive(Debug, Clone, Default)]
pub enum OAuthEndpointRateLimit {
    #[default]
    Default,
    Disabled,
    /// Both values are supplied, including zero, as in the published provider API.
    Limit(EndpointRateLimit),
}

/// OAuth protocol endpoint policies, in seconds and requests per client/path.
/// Rules are effective only when application rate limiting is enabled; its
/// storage and ordered custom rules remain authoritative.
#[derive(Debug, Clone, Default)]
pub struct OAuthProviderRateLimits {
    /// Defaults to 20 requests per 60 seconds.
    pub token: OAuthEndpointRateLimit,
    /// Defaults to 30 requests per 60 seconds.
    pub authorize: OAuthEndpointRateLimit,
    /// Defaults to 100 requests per 60 seconds.
    pub introspect: OAuthEndpointRateLimit,
    /// Defaults to 30 requests per 60 seconds.
    pub revoke: OAuthEndpointRateLimit,
    /// Defaults to 5 requests per 60 seconds.
    pub register: OAuthEndpointRateLimit,
    /// Defaults to 60 requests per 60 seconds, shared by GET and POST.
    pub userinfo: OAuthEndpointRateLimit,
}

type RoutePolicy<'a> = (fn(&str) -> bool, &'a OAuthEndpointRateLimit, f64);

impl OAuthProviderRateLimits {
    pub(super) fn rules(&self) -> Vec<PluginRateLimit> {
        let routes: [RoutePolicy<'_>; 6] = [
            (|path| path == "/oauth2/token", &self.token, 20.0),
            (|path| path == "/oauth2/authorize", &self.authorize, 30.0),
            (|path| path == "/oauth2/introspect", &self.introspect, 100.0),
            (|path| path == "/oauth2/revoke", &self.revoke, 30.0),
            (|path| path == "/oauth2/register", &self.register, 5.0),
            (|path| path == "/oauth2/userinfo", &self.userinfo, 60.0),
        ];
        routes
            .into_iter()
            .filter_map(|(matches, policy, max)| {
                let limit = match policy {
                    OAuthEndpointRateLimit::Disabled => return None,
                    OAuthEndpointRateLimit::Default => EndpointRateLimit {
                        window_seconds: 60.0,
                        max_requests: max,
                    },
                    OAuthEndpointRateLimit::Limit(limit) => limit.clone(),
                };
                Some(PluginRateLimit { matches, limit })
            })
            .collect()
    }
}
