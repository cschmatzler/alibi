use super::*;

// Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
#[test]
fn test_builder_core_routes() {
    let spec = OpenApiBuilder::new("Better Auth", "0.1.0")
        .description("Authentication API")
        .core_routes()
        .build();

    assert_eq!(spec.openapi, "3.1.1");
    assert_eq!(spec.info.title, "Better Auth");
    assert!(spec.paths.contains_key("/ok"));
    assert!(spec.paths.contains_key("/error"));
    assert!(spec.paths.contains_key("/update-user"));

    // /ok should have a GET operation
    let ok_path = (spec.paths)
        .get("/ok")
        .expect("fixture contains the requested index");
    assert!(ok_path.contains_key("get"));
    assert_eq!(ok_path["get"].operation_id, "ok");
}

// Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
#[test]
fn test_builder_custom_route() {
    let spec = OpenApiBuilder::new("Test", "1.0.0")
        .route(
            &HttpMethod::Post,
            "/sign-in/email",
            "sign_in_email",
            "email-password",
        )
        .build();

    let path = (spec.paths)
        .get("/sign-in/email")
        .expect("fixture contains the requested index");
    assert!(path.contains_key("post"));
    assert_eq!(path["post"].tags, vec!["email-password"]);
}

// Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
#[test]
fn test_spec_to_json() {
    let spec = OpenApiBuilder::new("Test", "1.0.0").core_routes().build();

    let json = spec.to_json().unwrap();
    assert!(json.contains("\"openapi\": \"3.1.1\""));
    assert!(json.contains("\"/ok\""));
}

// Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
#[test]
fn test_spec_to_value() {
    let spec = OpenApiBuilder::new("Test", "1.0.0").core_routes().build();

    let value = spec.to_value().unwrap();
    assert_eq!((*(value).get("openapi").unwrap_or(&Value::Null)), "3.1.1");
    assert!(
        (*(*(*(*(value).get("paths").unwrap_or(&Value::Null))
            .get("/ok")
            .unwrap_or(&Value::Null))
        .get("get")
        .unwrap_or(&Value::Null))
        .get("operationId")
        .unwrap_or(&Value::Null))
        .is_string()
    );
}
