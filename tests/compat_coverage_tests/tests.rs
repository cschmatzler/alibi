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
            .any(|route| route.method == better_auth_core::HttpMethod::Get
                && route.path == better_auth_core::core_paths::OPENAPI_SPEC)
    );
    let actual: BTreeSet<String> = registered
        .into_iter()
        .filter(|route| {
            !(route.method == better_auth_core::HttpMethod::Get
                && route.path == better_auth_core::core_paths::OPENAPI_SPEC)
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
    let inventory: Value = serde_json::from_str(include_str!("../../compat-tests/capabilities.json"))
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
        "Runtime route inventory changed. Review and update compat-tests/capabilities.json; no route may silently appear or disappear."
    );
}
