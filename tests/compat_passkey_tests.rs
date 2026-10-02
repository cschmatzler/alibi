#![cfg(test)]
//! Passkey plugin endpoint validation tests.
//!
//! Tests passkey registration, authentication, and management endpoints
//! against the `OpenAPI` spec. Note: `WebAuthn` flows require browser interaction,
//! so we validate response shapes for the options-generation endpoints and
//! error shapes for verification endpoints (which need real attestation data).
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "passkey contract tests use direct JSON indexing for concise response assertions"
)]

#[path = "support/compat/mod.rs"]
mod compat;

use compat::helpers::*;
use compat::schema::OpenApiProfile;
use compat::validator::SpecValidator;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Test passkey registration and authentication option generation endpoints.
    #[tokio::test]
    async fn test_passkey_option_generation_endpoints() {
        let auth = create_test_auth().await;
        let mut validator = SpecValidator::with_profile(OpenApiProfile::AlignedRs);

        // Sign up a user
        let (token, _) = signup_user(&auth, "passkey@example.com", "password123", "PK User").await;

        // --- GET /passkey/generate-register-options ---
        let (status, body) = send_request(
            &auth,
            get_with_auth("/passkey/generate-register-options", &token),
        )
        .await;
        assert_eq!(status, 200, "generate-register-options failed: {body}");
        // WebAuthn options must have challenge and rp fields
        assert!(
            body["challenge"].is_string(),
            "register options should have challenge"
        );
        assert!(
            body["rp"].is_object(),
            "register options should have rp object"
        );
        validator.validate_endpoint("/passkey/generate-register-options", "get", status, &body);

        // --- GET /passkey/generate-authenticate-options ---
        let (status_2, body_2) = send_request(
            &auth,
            get_with_auth("/passkey/generate-authenticate-options", &token),
        )
        .await;
        assert_eq!(
            status_2, 200,
            "generate-authenticate-options failed: {body_2}"
        );
        assert!(
            body_2["challenge"].is_string(),
            "authenticate options should have challenge"
        );
        validator.validate_endpoint(
            "/passkey/generate-authenticate-options",
            "get",
            status_2,
            &body_2,
        );

        // Print report
        let report = validator.report();
        drop(writeln!(std::io::stderr().lock(), "\n{report}\n"));

        assert!(
            validator.results.iter().all(|result| result.passed
                && !result.skipped
                && (200..300).contains(&result.status)),
            "Every schema-covered endpoint must pass without skips:\n{report}"
        );
    }

    /// Test passkey verification endpoints (expect errors without real attestation data).
    #[tokio::test]
    async fn test_passkey_verification_endpoints() {
        let auth = create_test_auth().await;

        let (token, _) =
            signup_user(&auth, "pk_verify@example.com", "password123", "PK Verify").await;

        // --- POST /passkey/verify-registration ---
        // Without real WebAuthn attestation, this should return an error
        let (status, body) = send_request(
            &auth,
            post_json_with_auth(
                "/passkey/verify-registration",
                serde_json::json!({
                    "id": "fake-credential-id",
                    "rawId": "fake-raw-id",
                    "response": {
                        "attestationObject": "fake",
                        "clientDataJSON": "fake"
                    },
                    "type": "public-key"
                }),
                &token,
            ),
        )
        .await;
        // Expect 4xx error since attestation data is fake
        assert!(
            (400..500).contains(&status),
            "verify-registration with fake data should fail, got status {status}"
        );
        // Error response should have message field per spec
        assert!(
            body["message"].is_string() || body["error"].is_string(),
            "error response should have message or error field: {body}"
        );

        // --- POST /passkey/verify-authentication ---
        let (status_2, body_2) = send_request(
            &auth,
            post_json_with_auth(
                "/passkey/verify-authentication",
                serde_json::json!({
                    "id": "fake-credential-id",
                    "rawId": "fake-raw-id",
                    "response": {
                        "authenticatorData": "fake",
                        "clientDataJSON": "fake",
                        "signature": "fake"
                    },
                    "type": "public-key"
                }),
                &token,
            ),
        )
        .await;
        assert!(
            (400..500).contains(&status_2),
            "verify-authentication with fake data should fail, got status {status_2}"
        );
        assert!(
            body_2["message"].is_string() || body_2["error"].is_string(),
            "error response should have message or error field: {body_2}"
        );
    }

    /// Test passkey management endpoints (list, delete, update).
    #[tokio::test]
    async fn test_passkey_management_endpoints() {
        let auth = create_test_auth().await;

        let (token, _) = signup_user(&auth, "pk_mgmt@example.com", "password123", "PK Mgmt").await;

        // --- GET /passkey/list-user-passkeys ---
        let (status, body) =
            send_request(&auth, get_with_auth("/passkey/list-user-passkeys", &token)).await;
        assert_eq!(status, 200, "list-user-passkeys failed: {body}");
        assert_eq!(body, serde_json::json!([]));

        // --- POST /passkey/delete-passkey ---
        // Try to delete a non-existent passkey
        let (status_2, body_2) = send_request(
            &auth,
            post_json_with_auth(
                "/passkey/delete-passkey",
                serde_json::json!({ "id": "non-existent-id" }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_2, 404);
        assert_eq!(
            body_2,
            serde_json::json!({
                "code": "PASSKEY_NOT_FOUND",
                "message": "Passkey not found"
            })
        );

        // --- POST /passkey/update-passkey ---
        let (status_3, body_3) = send_request(
            &auth,
            post_json_with_auth(
                "/passkey/update-passkey",
                serde_json::json!({
                    "id": "non-existent-id",
                    "name": "My Passkey"
                }),
                &token,
            ),
        )
        .await;
        assert_eq!(status_3, 404);
        assert_eq!(
            body_3,
            serde_json::json!({
                "code": "PASSKEY_NOT_FOUND",
                "message": "Passkey not found"
            })
        );
    }
}
