//! Cross-endpoint consistency tests — verify user/session objects are
//! identical across different API responses.
#![allow(
    clippy::indexing_slicing,
    reason = "consistency tests use direct JSON indexing to compare response object shapes"
)]

use crate::contract::helpers::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Signup, signin and session retrieval expose the same persisted user.
    #[tokio::test]
    async fn test_auth_flow_user_object_consistency() {
        let auth = create_test_auth().await;

        // Step 1: Sign up
        let (_signup_token, signup_body) =
            signup_user(&auth, "flow@example.com", "password123", "Flow User").await;
        let signup_user_obj = &signup_body["user"];

        // Step 2: Sign in
        let (signin_token, signin_body) =
            signin_user(&auth, "flow@example.com", "password123").await;
        let signin_user_obj = &signin_body["user"];

        // Step 3: Get session
        let (status, session_body) =
            send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
        assert_eq!(status, 200);
        let session_user_obj = &session_body["user"];

        assert_eq!(signup_user_obj, signin_user_obj);
        assert_eq!(signup_user_obj, session_user_obj);
    }

    /// Test that duplicate signup returns proper error shape.
    #[tokio::test]
    async fn test_duplicate_signup_error_shape() {
        let auth = create_test_auth().await;

        // First signup succeeds
        drop(signup_user(&auth, "dup@example.com", "password123", "Dup User").await);

        // Second signup with same email should fail
        let (status, body) = send_request(
            &auth,
            post_json(
                "/sign-up/email",
                serde_json::json!({
                    "name": "Dup User 2",
                    "email": "dup@example.com",
                    "password": "password123"
                }),
            ),
        )
        .await;

        assert!(
            (400..500).contains(&status),
            "Duplicate signup should return 4xx, got {status}"
        );
        assert!(
            body["message"].is_string(),
            "Error response must have 'message' field, got: {body}"
        );
    }

    /// Listing sessions returns the complete session exposed by get-session.
    #[tokio::test]
    async fn test_session_object_consistency() {
        let auth = create_test_auth().await;
        let (token, _) = signup_user(&auth, "sess@example.com", "password123", "Sess User").await;
        let (status, session_body) =
            send_request(&auth, get_with_auth("/get-session", &token)).await;
        assert_eq!(status, 200);
        assert!(session_body["session"].is_object());

        let (status, list_body) =
            send_request(&auth, get_with_auth("/list-sessions", &token)).await;
        assert_eq!(status, 200);
        assert_eq!(list_body, serde_json::json!([session_body["session"]]));
    }
}
