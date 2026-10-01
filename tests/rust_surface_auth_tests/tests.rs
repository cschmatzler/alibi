use super::*;

// Rust-specific surface: `AuthBuilder::build` is the Rust entry point that
// validates configuration before producing a `BetterAuth` instance.
#[tokio::test]
async fn test_builder_rejects_invalid_config() {
    let config = AuthConfig::default();
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);
    let result = BetterAuth::<TestSchema>::new(config)
        .store(store)
        .build()
        .await;
    assert!(result.is_err());
}

// Rust-specific surface: `BetterAuth::plugin_names` and `BetterAuth::get_plugin`
// are public Rust introspection APIs with no TS analogue.
#[tokio::test]
async fn test_plugin_registry_accessors() {
    let auth = build_auth_with_route_plugin().await;

    let plugin_names = auth.plugin_names();
    assert!(plugin_names.contains(&"email-password"));
    assert!(plugin_names.contains(&"route-test"));
    assert!(auth.get_plugin("route-test").is_some());
    assert!(auth.get_plugin("missing-plugin").is_none());
}

// Rust-specific surface: `BetterAuth::routes` exposes only plugin-declared
// routes for embedding and router composition.
#[tokio::test]
async fn test_routes_lists_plugin_routes_only() {
    let auth = build_auth_with_route_plugin().await;

    let routes = auth.routes();
    assert!(routes.iter().any(|(path, _)| path == "/route-test"));
    assert!(!routes.iter().any(|(path, _)| path == "/update-user"));
}

// Rust-specific surface: `disabled_path` must affect direct `handle_request`
// callers, not only framework integrations.
#[tokio::test]
async fn test_disabled_path_blocks_direct_dispatch() {
    let config = test_config().disabled_path("/ok");
    let store = SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await);
    let auth = BetterAuth::<TestSchema>::new(config)
        .store(store)
        .build()
        .await
        .expect("build should succeed");

    let response = auth
        .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
        .await
        .expect("request should return a response");

    assert_eq!(response.status, 404);
}

// Rust-specific surface: `BetterAuth::openapi_spec` is a Rust API for embedded
// schema generation and should include both core and plugin routes.
#[tokio::test]
async fn test_openapi_spec_includes_core_and_plugin_routes() {
    let auth = build_auth_with_route_plugin().await;
    let spec = auth
        .openapi_spec()
        .to_value()
        .expect("OpenAPI spec should serialize to JSON");

    // The pinned /ok metadata omits an operationId; its actual registration
    // retains the Rust routing identifier independently of document policy.
    assert!(
        auth.registered_routes()
            .iter()
            .any(|route| route.method == HttpMethod::Get
                && route.path == "/ok"
                && route.operation_id == "ok")
    );
    assert_eq!(
        spec["paths"]["/ok"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            ["ok"]["type"],
        "boolean"
    );
    assert_eq!(
        spec["paths"]["/route-test"]["get"]["operationId"],
        "route_test"
    );
    assert_eq!(
        spec["paths"]["/route-test"]["post"]["operationId"],
        "route_test_post"
    );
}
