use super::*;
use crate::plugins::test_helpers;
use better_auth_core::config::AccountConfig;
use better_auth_core::utils::cookie_utils::related_cookie_name;
use better_auth_core::wire::SessionView;
use better_auth_core::{CreateSession, CreateUser};
use chrono::{Duration, Utc};

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_get_session_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/get-session",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_get_session(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(
        (*(*(response_data)
            .get("session")
            .unwrap_or(&serde_json::Value::Null))
        .get("token")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap(),
        session.token
    );
    assert_eq!(
        (*(*(response_data)
            .get("user")
            .unwrap_or(&serde_json::Value::Null))
        .get("email")
        .unwrap_or(&serde_json::Value::Null))
        .as_str()
        .map(ToOwned::to_owned),
        Some("test@example.com".to_owned())
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_get_session_unauthorized() {
    // /get-session returns 200 with null body when unauthenticated.
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req =
        test_helpers::create_auth_request_no_query(HttpMethod::Get, "/get-session", None, None);
    let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid JSON");
    assert!(body.is_null());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_sign_out_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(&session.token),
        Some(b"{}".to_vec()),
    );
    let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let response_data: SuccessResponse = serde_json::from_str(&body_str).unwrap();
    assert!(response_data.success);

    let session_check = ctx.database.get_session(&session.token).await.unwrap();
    assert!(session_check.is_none());
}

#[tokio::test]
async fn test_sign_out_clears_account_cookie_when_enabled() {
    let plugin = SessionManagementPlugin::new();
    let config = test_helpers::create_test_config().account(AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    });
    let ctx = test_helpers::create_test_context_with_config(config).await;
    let (_user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(&session.token),
        Some(b"{}".to_vec()),
    );
    let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "sign-out should clear the account_data cookie when store_account_cookie is enabled"
    );
}

#[tokio::test]
async fn test_sign_out_does_not_emit_account_cookie_when_disabled() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-out",
        Some(&session.token),
        Some(b"{}".to_vec()),
    );
    let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

    let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
    assert!(
        !response
            .headers
            .get_all("Set-Cookie")
            .any(|cookie| cookie.starts_with(&account_cookie_name)),
        "sign-out should not emit account_data clearing cookies when store_account_cookie is disabled"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_list_sessions_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_owned()),
        user_agent: Some("another-agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    ctx.database.create_session(create_session2).await.unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn test_list_sessions_filters_impersonated_sessions_when_admin_plugin_is_enabled() {
    let plugin = SessionManagementPlugin::new();
    let (mut ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;
    ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));

    let direct_session = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_owned()),
        user_agent: Some("another-agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    ctx.database.create_session(direct_session).await.unwrap();

    let impersonated_session = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("10.0.0.5".to_owned()),
        user_agent: Some("impersonated-agent".to_owned()),
        impersonated_by: Some("admin-user".to_owned()),
        active_organization_id: None,
        active_team_id: None,
    };
    let impersonated = ctx
        .database
        .create_session(impersonated_session)
        .await
        .unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(&session.token),
        None,
    );
    let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let body_str = String::from_utf8(response.body).unwrap();
    let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|candidate| candidate.token != impersonated.token),
        "impersonated sessions should not be returned from /list-sessions"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_session_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_owned()),
        user_agent: Some("another-agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    let session2 = ctx.database.create_session(create_session2).await.unwrap();

    let body = serde_json::json!({ "token": session2.token });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(&session.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let session2_check = ctx.database.get_session(&session2.token).await.unwrap();
    assert!(session2_check.is_none());

    let session1_check = ctx.database.get_session(&session.token).await.unwrap();
    assert!(session1_check.is_some());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_session_forbidden_different_user() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user1, session1) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_user2 = CreateUser::new()
        .with_email("user2@example.com")
        .with_name("User Two");
    let user2 = ctx.database.create_user(create_user2).await.unwrap();

    let create_session2 = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user2.id,
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_owned()),
        user_agent: Some("another-agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    let session2 = ctx.database.create_session(create_session2).await.unwrap();

    let body = serde_json::json!({ "token": session2.token });
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(&session1.token),
        Some(body.to_string().into_bytes()),
    );

    let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
    assert_eq!(response.status, 200);

    let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        (*(body_2).get("status").unwrap_or(&serde_json::Value::Null)),
        true
    );

    let still_exists = ctx.database.get_session(&session2.token).await.unwrap();
    assert!(
        still_exists.is_some(),
        "other user's session must not be revoked"
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_revoke_sessions_success() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, user, session1) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let create_session2 = CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
        token: None,
        user_id: user.id.clone(),
        expires_at: Utc::now() + Duration::hours(24),
        ip_address: Some("192.168.1.1".to_owned()),
        user_agent: Some("another-agent".to_owned()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    ctx.database.create_session(create_session2).await.unwrap();

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-sessions",
        Some(&session1.token),
        Some(b"{}".to_vec()),
    );
    let response = plugin.handle_revoke_sessions(&req, &ctx).await.unwrap();

    assert_eq!(response.status, 200);

    let user_sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert_eq!(user_sessions.len(), 0);
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_plugin_routes() {
    let plugin = SessionManagementPlugin::new();
    let routes = AuthPlugin::<
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
    >::routes(&plugin);

    assert_eq!(routes.len(), 8);
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
    );
    // Upstream serves `/get-session` on both methods.
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/get-session" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/sign-out" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/list-sessions" && r.method == HttpMethod::Get)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/revoke-session" && r.method == HttpMethod::Post)
    );
    assert!(
        routes
            .iter()
            .any(|r| r.path == "/revoke-sessions" && r.method == HttpMethod::Post)
    );
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_plugin_on_request_routing() {
    let plugin = SessionManagementPlugin::new();
    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    // Test valid route
    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/get-session",
        Some(&session.token),
        None,
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().status, 200);

    // POST /get-session is served, but rejected with 405 until
    // `session.defer_session_refresh` is enabled.
    let req_2 = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/get-session",
        Some(&session.token),
        Some(b"{}".to_vec()),
    );
    let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
    assert_eq!(response_2.status, 405);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response_2.body).unwrap(),
        serde_json::json!({
            "code": "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
            "message": "POST method requires deferSessionRefresh to be enabled in session config",
        }),
    );
    assert_eq!(
        response_2.headers.get("cache-control"),
        Some(&"no-store".to_owned())
    );
    assert_eq!(
        response_2.headers.get("pragma"),
        Some(&"no-cache".to_owned())
    );

    // Test invalid route
    let req_3 = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/invalid-route",
        Some(&session.token),
        None,
    );
    let response_3 = plugin.on_request(&req_3, &ctx).await.unwrap();
    assert!(response_3.is_none());
}

// Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
#[tokio::test]
async fn test_configuration() {
    let plugin = SessionManagementPlugin::new()
        .enable_session_listing(false)
        .enable_session_revocation(false)
        .require_authentication(false);

    assert!(!plugin.config.enable_session_listing);
    assert!(!plugin.config.enable_session_revocation);
    assert!(!plugin.config.require_authentication);

    let (ctx, _user, session) = test_helpers::create_test_context_with_user(
        CreateUser::new()
            .with_email("test@example.com")
            .with_name("Test User"),
        Duration::hours(24),
    )
    .await;

    let req = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/list-sessions",
        Some(&session.token),
        None,
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap();
    assert!(response.is_none());

    let req_2 = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/revoke-session",
        Some(&session.token),
        Some(b"{}".to_vec()),
    );
    let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap();
    assert!(response_2.is_none());
}
