//! Field-level checks for the public camelCase response contract.
#![allow(
    clippy::indexing_slicing,
    reason = "field-level compatibility tests use direct JSON indexing for concise response shape assertions"
)]

use crate::contract::helpers::*;
use crate::contract::shapes::check_camel_case_fields;
use better_auth::prelude::CreateAccount;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// All response fields must use camelCase (not `snake_case`) for frontend compatibility.
    #[tokio::test]
    async fn test_all_responses_use_camel_case() {
        let auth = create_test_auth().await;

        // Sign up a user to test all authenticated endpoints
        let (token, signup_body) =
            signup_user(&auth, "camel@example.com", "password123", "Camel User").await;

        // Collect all responses to check
        let test_cases: Vec<(&str, serde_json::Value)> =
            vec![("POST /sign-up/email", signup_body.clone())];

        // Endpoints that require auth
        let auth_endpoints: Vec<(&str, better_auth::prelude::AuthRequest)> = vec![
            ("GET /get-session", get_with_auth("/get-session", &token)),
            (
                "GET /list-sessions",
                get_with_auth("/list-sessions", &token),
            ),
            (
                "GET /list-accounts",
                get_with_auth("/list-accounts", &token),
            ),
        ];

        let account_info_account = auth
            .store()
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                user_id: signup_body["user"]["id"]
                    .as_str()
                    .expect("sign-up should return user id")
                    .to_owned(),
                account_id: "mock-account-id".to_owned(),
                provider_id: "mock".to_owned(),
                access_token: Some("mock-access-token".to_owned()),
                refresh_token: Some("mock-refresh-token".to_owned()),
                id_token: None,
                access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                refresh_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(2)),
                scope: Some("openid,email,profile".to_owned()),
                password: None,
            })
            .await
            .expect("account-info test account should be created");
        let account_info_req = get_with_auth_and_query(
            "/account-info",
            &token,
            vec![("accountId", account_info_account.id.as_str())],
        );

        let mut all_violations = Vec::new();

        // Check pre-collected responses
        for (endpoint, body) in &test_cases {
            let violations = check_camel_case_fields(body, "");
            if !violations.is_empty() {
                all_violations.push(format!("{endpoint}: {violations:?}"));
            }
        }

        // Check authenticated endpoint responses
        for (endpoint, req) in auth_endpoints {
            let (status, body) = send_request(&auth, req).await;
            assert_eq!(status, 200, "{endpoint} failed: {body}");
            let violations = check_camel_case_fields(&body, "");
            if !violations.is_empty() {
                all_violations.push(format!("{endpoint}: {violations:?}"));
            }
        }

        let (status, body) = send_request(&auth, account_info_req).await;
        assert_eq!(status, 200, "GET /account-info failed: {body}");
        let violations = check_camel_case_fields(&body, "");
        if !violations.is_empty() {
            all_violations.push(format!("GET /account-info: {violations:?}"));
        }

        // Sign in response
        let (_, signin_body) = signin_user(&auth, "camel@example.com", "password123").await;
        let violations = check_camel_case_fields(&signin_body, "");
        if !violations.is_empty() {
            all_violations.push(format!("POST /sign-in/email: {violations:?}"));
        }

        if !all_violations.is_empty() {
            drop(writeln!(
                std::io::stderr().lock(),
                "\n=== camelCase Violations ==="
            ));
            for v in &all_violations {
                drop(writeln!(std::io::stderr().lock(), "  {v}"));
            }
            drop(writeln!(
                std::io::stderr().lock(),
                "===========================\n"
            ));
        }

        assert!(
            all_violations.is_empty(),
            "Found snake_case fields in responses. All field names must use camelCase for frontend compatibility.\n\
         Violations:\n{}",
            all_violations.join("\n")
        );
    }
}
