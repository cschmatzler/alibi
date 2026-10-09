//! Enforced runtime route inventory. Behavioral evidence is checked by the Bun suite.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test fixture validation fails immediately"
)]

use crate::contract::helpers::{TestAuthOptions, create_test_auth_with_options};
use serde_json::Value;
use std::collections::BTreeSet;

fn canonical(path: &str) -> String {
    path.split('/')
        .map(|part| {
            if part.starts_with(':') || part.starts_with('{') {
                "{}"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_routes_match_capability_inventory() {
        let auth = create_test_auth_with_options(TestAuthOptions {
            teams_enabled: true,
            dynamic_roles_enabled: true,
            phone_enabled: true,
            multi_session_enabled: true,
            one_tap_enabled: true,
            anonymous_enabled: true,
            oauth_proxy_enabled: true,
            ..Default::default()
        })
        .await;
        // Documentation intentionally hides its own endpoints and native extensions.
        // Inventory actual dispatch registrations, retaining every upstream route.
        let registered = auth.registered_routes();
        assert!(
            registered
                .iter()
                .any(|route| route.method == alibi::HttpMethod::Get
                    && route.path == alibi::core_paths::OPENAPI_SPEC)
        );
        let actual: BTreeSet<String> = registered
            .into_iter()
            .filter(|route| {
                !(route.method == alibi::HttpMethod::Get
                    && route.path == alibi::core_paths::OPENAPI_SPEC)
            })
            .map(|route| {
                format!(
                    "{} {}",
                    format!("{:?}", route.method).to_uppercase(),
                    canonical(&route.path)
                )
            })
            .collect();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(root.join("coverage")).expect("artifact directory");
        std::fs::write(
            root.join("coverage/runtime-routes.json"),
            serde_json::to_string_pretty(&actual).expect("serialize routes"),
        )
        .expect("write routes");
        if std::env::var("BETTER_AUTH_UPDATE_CAPABILITIES").as_deref() == Ok("1") {
            return;
        }
        let inventory: Value = serde_json::from_str(include_str!("capabilities.json"))
            .expect("capability inventory JSON");
        let expected: BTreeSet<String> = inventory["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .filter(|entry| entry["implemented"] == true)
            .map(|entry| entry["route"].as_str().expect("route").to_owned())
            .collect();
        assert_eq!(
            actual, expected,
            "Runtime route inventory changed. Review and update tests/compat/capabilities.json; no route may silently appear or disappear."
        );
    }
}
