#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "SQLite plugin contract assertions"
)]

use super::*;
use crate::plugins::test_helpers::{
    create_auth_json_request_no_query, create_auth_request_no_query, create_test_context,
    create_user_and_session,
};
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::{CreateSession, CreateUser};
use chrono::Duration;

fn request_with_cookies(
    method: HttpMethod,
    path: &str,
    cookies: &[String],
    body: Option<serde_json::Value>,
) -> AuthRequest {
    let mut request = create_auth_json_request_no_query(method, path, None, body);
    request.headers.insert("cookie".into(), cookies.join("; "));
    request
}

fn pair(header: &str) -> String {
    header.split(';').next().unwrap().to_owned()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn signed_browser_sessions_select_other_accounts_and_reject_unrelated_tokens() {
    let ctx = create_test_context().await;
    let plugin = MultiSessionPlugin::new();
    let (bob, _) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("bob@example.test"),
        Duration::days(1),
    )
    .await;
    let (alice, _) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("alice@example.test"),
        Duration::days(1),
    )
    .await;
    let custom = |user_id: String, token: &str| CreateSession {
        user_id,
        token: Some(token.to_owned()),
        expires_at: Utc::now() + Duration::days(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
    };
    let bob_session = ctx
        .database
        .create_session(custom(bob.id.clone(), "z-last"))
        .await
        .unwrap();
    let alice_session = ctx
        .database
        .create_session(custom(alice.id.clone(), "a-first"))
        .await
        .unwrap();
    let cookie_for = |token: &str| {
        format!(
            "{}={}",
            MultiSessionPlugin::cookie_name(token, &ctx),
            sign_cookie_value(token, &ctx.config.secret)
        )
    };
    let cookies = vec![
        pair(&create_session_cookie(&bob_session.token, &ctx.config)),
        cookie_for(&bob_session.token),
        cookie_for(&alice_session.token),
    ];
    let request = request_with_cookies(
        HttpMethod::Get,
        "/multi-session/list-device-sessions",
        &cookies,
        None,
    );
    let listed = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&listed.body).unwrap();
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["user"]["id"], alice.id);
    assert_eq!(body[1]["user"]["id"], bob.id);
    let duplicate = request_with_cookies(
        HttpMethod::Get,
        "/multi-session/list-device-sessions",
        &[
            cookie_for(&alice_session.token),
            format!(
                "{}=invalid-last",
                MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
            ),
            cookie_for(&bob_session.token),
        ],
        None,
    );
    let duplicate = plugin.on_request(&duplicate, &ctx).await.unwrap().unwrap();
    let listed_2: serde_json::Value = serde_json::from_slice(&duplicate.body).unwrap();
    assert_eq!(listed_2.as_array().unwrap().len(), 1);
    assert_eq!(listed_2[0]["user"]["id"], bob.id);
    for (values, succeeds) in [
        (
            vec![
                cookie_for(&alice_session.token),
                format!(
                    "{}=invalid-last",
                    MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
                ),
            ],
            false,
        ),
        (
            vec![
                format!(
                    "{}=invalid-first",
                    MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
                ),
                cookie_for(&alice_session.token),
            ],
            true,
        ),
    ] {
        let selection = request_with_cookies(
            HttpMethod::Post,
            "/multi-session/set-active",
            &values,
            Some(json!({"sessionToken":alice_session.token})),
        );
        let result = plugin.on_request(&selection, &ctx).await;
        if succeeds {
            assert_eq!(result.unwrap().unwrap().status, 200);
        } else {
            assert_eq!(result.unwrap_err().status_code(), 401);
        }
    }
    for path in ["/multi-session/revoke", "/multi-session/set-active"] {
        let empty_proof = request_with_cookies(
            HttpMethod::Post,
            path,
            &[
                pair(&create_session_cookie(&bob_session.token, &ctx.config)),
                format!(
                    "{}={}",
                    MultiSessionPlugin::cookie_name(&alice_session.token, &ctx),
                    sign_cookie_value("", &ctx.config.secret)
                ),
            ],
            Some(json!({"sessionToken":alice_session.token})),
        );
        let rejected = plugin
            .on_request(&empty_proof, &ctx)
            .await
            .unwrap_or_else(|error| Some(error.to_auth_response()))
            .unwrap();
        assert_eq!(rejected.status, 401);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rejected.body).unwrap()["code"],
            "INVALID_SESSION_TOKEN"
        );
        assert!(rejected.headers.get_all("set-cookie").next().is_none());
        assert!(
            ctx.database
                .get_session(&alice_session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            ctx.database
                .get_session(&bob_session.token)
                .await
                .unwrap()
                .is_some()
        );
    }
    let select = request_with_cookies(
        HttpMethod::Post,
        "/multi-session/set-active",
        &cookies,
        Some(json!({"sessionToken":alice_session.token})),
    );
    let selected = plugin.on_request(&select, &ctx).await.unwrap().unwrap();
    assert_eq!(selected.status, 200);
    let body_2: serde_json::Value = serde_json::from_slice(&selected.body).unwrap();
    assert_eq!(body_2["user"]["id"], alice.id);
    assert_eq!(body_2["session"]["userId"], alice.id);
    let unrelated = create_auth_json_request_no_query(
        HttpMethod::Post,
        "/multi-session/set-active",
        Some(&bob_session.token),
        Some(json!({"sessionToken":alice_session.token})),
    );
    assert_eq!(
        plugin
            .on_request(&unrelated, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    assert!(
        ctx.database
            .get_session(&alice_session.token)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn cookie_tampering_expiry_revocation_fallback_and_logout_preserve_state() {
    let ctx = create_test_context().await;
    let plugin = MultiSessionPlugin::new();
    let (_, one) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("one@example.test"),
        Duration::days(1),
    )
    .await;
    let (_, two) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("two@example.test"),
        Duration::days(1),
    )
    .await;
    let first = format!(
        "{}={}",
        MultiSessionPlugin::cookie_name(&one.token, &ctx),
        sign_cookie_value(&one.token, &ctx.config.secret)
    );
    let second = format!(
        "{}={}",
        MultiSessionPlugin::cookie_name(&two.token, &ctx),
        sign_cookie_value(&two.token, &ctx.config.secret)
    );
    let cookies = vec![
        pair(&create_session_cookie(&one.token, &ctx.config)),
        first.clone(),
        second.clone(),
    ];
    let revoke = request_with_cookies(
        HttpMethod::Post,
        "/multi-session/revoke",
        &cookies,
        Some(json!({"sessionToken":one.token})),
    );
    let revoked = plugin.on_request(&revoke, &ctx).await.unwrap().unwrap();
    assert_eq!(revoked.status, 200);
    assert!(
        ctx.database
            .get_session(&one.token)
            .await
            .unwrap()
            .is_none()
    );
    let new_session_cookie = revoked
        .headers
        .get_all("set-cookie")
        .filter_map(|v| cookie::Cookie::parse(v.clone()).ok())
        .find(|v| v.name() == ctx.config.session.cookie_name)
        .unwrap();
    assert_eq!(
        verify_cookie_value(new_session_cookie.value(), &ctx.config.secret),
        Some(two.token.clone())
    );
    let tampered = vec![second.replace('=', "=tampered-")];
    let select = request_with_cookies(
        HttpMethod::Post,
        "/multi-session/set-active",
        &tampered,
        Some(json!({"sessionToken":two.token})),
    );
    assert_eq!(
        plugin
            .on_request(&select, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    ctx.database
        .update_session_expiry(&two.token, Utc::now() - Duration::seconds(1))
        .await
        .unwrap();
    let expired = request_with_cookies(
        HttpMethod::Post,
        "/multi-session/set-active",
        std::slice::from_ref(&second),
        Some(json!({"sessionToken":two.token})),
    );
    let expired = plugin.on_request(&expired, &ctx).await.unwrap().unwrap();
    assert_eq!(expired.status, 401);
    assert!(
        expired
            .headers
            .get("set-cookie")
            .unwrap()
            .contains("Max-Age=0")
    );
    let signout = request_with_cookies(HttpMethod::Post, "/sign-out", &[second], None);
    drop(
        plugin
            .after_request(
                &signout,
                &ctx,
                AuthResponse::json(200, &json!({"success":true})).unwrap(),
            )
            .await
            .unwrap(),
    );
    assert!(
        ctx.database
            .get_session(&two.token)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn new_session_hook_replaces_same_user_cookie_and_respects_browser_limit() {
    let ctx = create_test_context().await;
    let plugin = MultiSessionPlugin::with_config(MultiSessionConfig {
        maximum_sessions: 1,
    });
    let (user, old) = create_user_and_session(
        &ctx,
        CreateUser::new().with_email("same@example.test"),
        Duration::days(1),
    )
    .await;
    let new = ctx
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    let old_cookie = format!(
        "{}={}",
        MultiSessionPlugin::cookie_name(&old.token, &ctx),
        sign_cookie_value(&old.token, &ctx.config.secret)
    );
    let request = request_with_cookies(HttpMethod::Post, "/sign-in/email", &[old_cookie], None);
    let mut response = AuthResponse::json(200, &json!({"token":new.token()})).unwrap();
    response.headers.append(
        "set-cookie",
        create_session_cookie(new.token(), &ctx.config),
    );
    let response = plugin
        .after_request(&request, &ctx, response)
        .await
        .unwrap();
    assert!(
        ctx.database
            .get_session(&old.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|value| value.starts_with(&MultiSessionPlugin::cookie_name(new.token(), &ctx)))
    );
    let multi_cookie = response
        .headers
        .get_all("set-cookie")
        .filter_map(|header| cookie::Cookie::parse(header.clone()).ok())
        .find(|cookie| cookie.name() == MultiSessionPlugin::cookie_name(new.token(), &ctx))
        .unwrap();
    assert_eq!(multi_cookie.max_age().unwrap().whole_seconds(), 604_800);
    let invalid_existing = request_with_cookies(
        HttpMethod::Post,
        "/sign-in/email",
        &["other_multi-invalid=bad".to_owned()],
        None,
    );
    let mut response_2 = AuthResponse::json(200, &json!({"token":new.token()})).unwrap();
    response_2.headers.append(
        "set-cookie",
        create_session_cookie(new.token(), &ctx.config),
    );
    let response_2_3 = plugin
        .after_request(&invalid_existing, &ctx, response_2)
        .await
        .unwrap();
    assert_eq!(response_2_3.headers.get_all("set-cookie").count(), 1);
    let empty = create_auth_request_no_query(
        HttpMethod::Get,
        "/multi-session/list-device-sessions",
        None,
        None,
    );
    assert_eq!(
        plugin.on_request(&empty, &ctx).await.unwrap().unwrap().body,
        b"[]"
    );
}
