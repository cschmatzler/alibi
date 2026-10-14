//! Application algorithm choices shared by native and fixture configuration.
use alibi::plugins::{SsoDeprecatedAlgorithmBehavior, SsoSamlSigningPolicy};
pub(crate) fn policy(mode: &str) -> SsoSamlSigningPolicy {
    let mut policy = SsoSamlSigningPolicy::default();
    if mode == "algorithm-strict" {
        policy.allowed_signature_algorithms = Some(vec![
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".into(),
        ]);
        policy.allowed_digest_algorithms = Some(vec!["sha256".into()]);
    } else if mode == "algorithm-reject" {
        policy.on_deprecated = SsoDeprecatedAlgorithmBehavior::Reject;
    } else if mode == "algorithm-override" {
        policy.on_deprecated = SsoDeprecatedAlgorithmBehavior::Reject;
        policy.allowed_signature_algorithms = Some(vec!["sha1".into()]);
        policy.allowed_digest_algorithms =
            Some(vec!["http://www.w3.org/2000/09/xmldsig#sha1".into()]);
    } else if mode == "algorithm-empty" {
        policy.allowed_signature_algorithms = Some(vec![]);
        policy.allowed_digest_algorithms = Some(vec![]);
    }
    policy
}
