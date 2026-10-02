#![cfg(test)]
//! Unit tests for the compatibility framework's internal logic.
//!
//! Tests for camelCase detection, rendered-text decoding, and schema resolution
//! against generated upstream OpenAPI profiles.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests intentionally use panic-on-failure assertions and direct indexing for compact fixture checks"
)]

#[path = "support/compat/mod.rs"]
mod compat;

use compat::helpers::html_text_content;
use compat::schema::{
    OpenApiProfile, extract_success_schema, load_openapi_spec, load_openapi_spec_with_profile,
    resolve_object_schema,
};
use compat::shapes::check_camel_case_fields;

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // camelCase
    // ---------------------------------------------------------------------------

    #[test]
    fn test_camel_case_check() {
        let val =
            serde_json::json!({"userId": "1", "user_name": "Alice", "created_at": "2024-01-01"});
        let violations = check_camel_case_fields(&val, "");
        assert_eq!(violations.len(), 2, "Should detect 2 snake_case fields");
    }

    // ---------------------------------------------------------------------------
    // Schema resolution
    // ---------------------------------------------------------------------------

    #[test]
    fn test_schema_resolution() {
        let spec = load_openapi_spec();
        let components = spec.components.as_ref().expect("spec must have components");

        // Verify User schema can be resolved
        let user_ref = components.schemas.get("User");
        assert!(user_ref.is_some(), "Should have User schema in components");

        if let Some(obj_or_ref) = user_ref {
            let user = resolve_object_schema(&spec, obj_or_ref);
            assert!(user.is_some(), "Should resolve User schema");
            let user = user.unwrap();
            assert!(
                user.properties.contains_key("id"),
                "User should have 'id' property"
            );
            assert!(
                user.properties.contains_key("email"),
                "User should have 'email' property"
            );
        }

        // Verify Session schema can be resolved
        let session_ref = components.schemas.get("Session");
        assert!(
            session_ref.is_some(),
            "Should have Session schema in components"
        );
    }

    #[test]
    fn test_success_schema_extraction() {
        let spec = load_openapi_spec();

        // Extract signup success schema
        let schema = extract_success_schema(&spec, "/sign-up/email", "post");
        assert!(
            schema.is_some(),
            "Should extract /sign-up/email success schema"
        );

        let signup_schema = schema.unwrap();
        assert!(
            signup_schema.fields.contains_key("token"),
            "Signup schema should have 'token' field"
        );
        assert!(
            signup_schema.fields.contains_key("user"),
            "Signup schema should have 'user' field"
        );

        // Extract signin success schema
        let schema_2 = extract_success_schema(&spec, "/sign-in/email", "post");
        assert!(
            schema_2.is_some(),
            "Should extract /sign-in/email success schema"
        );

        let signin_schema = schema_2.unwrap();
        assert!(
            signin_schema.fields.contains_key("token"),
            "Signin schema should have 'token' field"
        );
        assert!(
            signin_schema.fields.contains_key("redirect"),
            "Signin schema should have 'redirect' field"
        );
        assert!(
            signin_schema.fields.contains_key("user"),
            "Signin schema should have 'user' field"
        );
    }

    #[test]
    fn test_default_profile_is_core() {
        let spec = load_openapi_spec();
        let paths = spec.paths.as_ref().expect("spec must have paths");

        assert!(
            paths.contains_key("/sign-up/email"),
            "core profile should include default auth endpoints"
        );
        assert!(
            paths.contains_key("/list-sessions"),
            "core profile should include session endpoints"
        );
        assert!(
            !paths.contains_key("/admin/list-users"),
            "default core profile should not include admin endpoints"
        );
        assert!(
            !paths.contains_key("/passkey/generate-register-options"),
            "default core profile should not include passkey endpoints"
        );
    }

    #[test]
    fn test_aligned_profile_includes_passkey_and_admin_surface() {
        let spec = load_openapi_spec_with_profile(OpenApiProfile::AlignedRs);
        let paths = spec.paths.as_ref().expect("spec must have paths");

        assert!(
            paths.contains_key("/passkey/generate-register-options"),
            "aligned-rs profile should include passkey endpoints"
        );
        assert!(
            paths.contains_key("/admin/list-users"),
            "aligned-rs profile should include admin endpoints"
        );
    }

    #[test]
    fn test_all_in_profile_includes_admin_surface() {
        let spec = load_openapi_spec_with_profile(OpenApiProfile::AllIn);
        let paths = spec.paths.as_ref().expect("spec must have paths");

        assert!(
            paths.contains_key("/admin/list-users"),
            "all-in profile should include admin endpoints"
        );
        assert!(
            paths.contains_key("/passkey/generate-register-options"),
            "all-in profile should retain aligned-rs endpoints"
        );
    }

    #[test]
    fn html_text_content_decodes_entities_and_normalizes_whitespace() {
        assert_eq!(
            html_text_content("<div><span>CODE&#58;</span>&nbsp;<span>UNKNOWN</span></div>"),
            "CODE: UNKNOWN"
        );
        assert_eq!(
            html_text_content("<p>A&amp;B &lt;ok&gt; &#x26; &#38;</p>"),
            "A&B <ok> & &"
        );
    }
}
