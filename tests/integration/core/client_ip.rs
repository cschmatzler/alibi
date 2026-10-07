//! The initialized IP policy must reach session persistence through dispatch.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests fail at the exact missing response field or persisted session"
)]

use crate::contract::helpers::{TestHarness, post_json, send_request, test_config};
use alibi_core::AuthSession;
use serde_json::json;

#[tokio::test]
async fn dispatched_signup_persists_configured_metadata_and_honors_tracking_opt_out() {
    for disabled in [false, true] {
        let mut config = test_config();
        config.advanced.ip_address.headers = vec!["x-client-chain".into()];
        config.advanced.ip_address.trusted_proxies = vec!["10.0.0.0/8".into()];
        config.advanced.ip_address.disable_ip_tracking = disabled;
        // Opt-out must win even when the fallback would otherwise return an IP.
        config.advanced.ip_address.localhost_fallback = true;
        let harness = TestHarness::minimal_with_config(config).await;
        let mut request = post_json(
            "/sign-up/email",
            json!({"email":"metadata@example.test", "password":"password123", "name":"Metadata"}),
        );
        request.headers.extend([
            ("x-client-chain".into(), "198.51.100.7, 10.0.0.1".into()),
            ("x-forwarded-for".into(), "203.0.113.99".into()),
            ("user-agent".into(), "native-integration".into()),
        ]);
        let (status, body) = send_request(harness.auth(), request).await;
        assert_eq!(status, 200, "{body}");
        let session = harness
            .auth()
            .store()
            .get_session(body["token"].as_str().expect("issued token"))
            .await
            .expect("read persisted session")
            .expect("session exists");
        assert_eq!(
            // Stores may represent absent metadata as an empty string. Neither
            // representation may retain a forwarded or fallback address.
            session.ip_address().filter(|address| !address.is_empty()),
            if disabled { None } else { Some("198.51.100.7") }
        );
        assert_eq!(session.user_agent(), Some("native-integration"));
    }
}
