pub(super) const PRIVATE_ENDPOINTS: &[&str] = &[
    "https://10.0.0.1/endpoint",
    "https://169.254.169.254/endpoint",
    "https://100.64.0.1/endpoint",
    "https://192.0.2.1/endpoint",
    "https://metadata.google.internal./endpoint",
    "https://[fc00::1]/endpoint",
    "https://[::ffff:10.0.0.1]/endpoint",
    "https://[2001:db8::1]/endpoint",
];
pub(super) fn private_error(field: &str, value: &str) -> serde_json::Value {
    let url = url::Url::parse(value).unwrap();
    serde_json::json!({"code":"discovery_private_host","message":format!("The {field} URL ({url}) is not publicly routable: {}. If this is an internal IdP, add its origin to trustedOrigins.",url.host_str().unwrap())})
}
