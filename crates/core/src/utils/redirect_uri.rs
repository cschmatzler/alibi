//! Shared OAuth redirect URI syntax and loopback host checks.

pub const INSECURE_REDIRECT_URI: &str =
    "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)";

pub fn syntax_issue(uri: &str) -> Option<&'static str> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some("Invalid URL");
    };
    if ["javascript", "data", "vbscript"].contains(&url.scheme()) {
        return Some("URL cannot use javascript:, data:, or vbscript: scheme");
    }
    if uri.contains('#') {
        return Some("Redirect URI must not contain a fragment component");
    }
    None
}

pub fn loopback_host(url: &url::Url) -> bool {
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .trim_end_matches('.');
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
            std::net::IpAddr::V4(ip) => ip.is_loopback(),
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
            }
        })
}
