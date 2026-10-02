use super::*;

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn account_management_client_compat() {
    run_client_compat(&["tests/account-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn admin_client_compat() {
    run_client_compat(&["tests/admin"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn api_key_client_compat() {
    run_client_compat(&["tests/api-key"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn core_client_compat() {
    run_client_compat(&["tests/core"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn additional_fields_client_compat() {
    run_client_compat(&["tests/core/additional-fields.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn device_authorization_client_compat() {
    run_client_compat(&["tests/device-authorization"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn email_verification_client_compat() {
    run_client_compat(&["tests/email-verification"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn generic_oauth_client_compat() {
    run_client_compat(&["tests/generic-oauth"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn oauth_client_compat() {
    run_client_compat(&["tests/oauth"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_client_compat() {
    run_client_compat(&["tests/organization"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn passkey_client_compat() {
    run_client_compat(&["tests/passkey"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn password_management_client_compat() {
    run_client_compat(&["tests/password-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn sessions_client_compat() {
    run_client_compat(&["tests/sessions"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn siwe_client_compat() {
    run_client_compat(&["tests/siwe"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_client_compat() {
    run_client_compat(&["tests/two-factor"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn user_management_client_compat() {
    run_client_compat(&["tests/user-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn full_client_compat() {
    run_client_compat(&["tests"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers and Chromium"]
async fn browser_client_compat() {
    run_client_compat(&["browser"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn one_time_token_client_compat() {
    run_client_compat(&["tests/one-time-token"]).await;
}

#[tokio::test]
#[ignore = "requires local TypeScript/Rust fixture servers"]
async fn jwt_client_compat() {
    run_client_compat(&["tests/jwt"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn server_endpoints_client_compat() {
    run_client_compat(&["tests/server-endpoints"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_teams_client_compat() {
    run_client_compat(&["tests/organization-extensions/teams.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_dynamic_roles_client_compat() {
    run_client_compat(&["tests/organization-extensions/dynamic-roles.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn json_numbers_client_compat() {
    run_client_compat(&["tests/core/json-numbers.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phone_number_client_compat() {
    run_client_compat(&["tests/phone-number"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_trust_client_compat() {
    run_client_compat(&["tests/two-factor/trust-ttl.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn username_availability_client_compat() {
    run_client_compat(&["tests/username"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn multiple_sessions_client_compat() {
    run_client_compat(&["tests/multiple-sessions"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_totp_client_compat() {
    run_client_compat(&["tests/two-factor/totp-config.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires Bun and the compatibility fixtures"]
async fn two_factor_lockout_client_compat() {
    run_client_compat(&["tests/two-factor/lockout.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_skip_order_client_compat() {
    run_client_compat(&["tests/two-factor/skip-order.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_pending_cancel_client_compat() {
    run_client_compat(&["tests/two-factor/pending-cancel.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_passwordless_client_compat() {
    run_client_compat(&["tests/two-factor/passwordless.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_otp_config_client_compat() {
    run_client_compat(&["tests/two-factor/otp-config.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_hooks_client_compat() {
    run_client_compat(&[
        "tests/organization-extensions/creation-hooks.test.ts",
        "tests/organization-extensions/deletion-hooks.test.ts",
    ])
    .await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn captcha_client_compat() {
    run_client_compat(&["tests/captcha"]).await;
}
