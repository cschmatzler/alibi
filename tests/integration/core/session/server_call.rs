//! Logical session calls must preserve the HTTP session lifecycle and cookie headers.

use crate::storage::{Backend, Db, TestResult, backend_tests};
use alibi::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointOptions,
    EndpointResponse,
};
use alibi::plugins::jwt::JwtPlugin;
use alibi::plugins::{GetSessionQuery, GetSessionResponse, SessionManagementPlugin};
use alibi::utils::json::JsValue;
use alibi::{
    Alibi, AuthBuilder, AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, AuthSession,
    AuthUser, CookieCacheConfig, CreateUser, Headers, HttpMethod,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn absent_session_is_a_typed_none_with_response_headers() {
    let auth = AuthBuilder::without_database(AuthConfig::new(
        "server-session-test-secret-at-least-32-characters",
    ))
    .plugin(SessionManagementPlugin::new())
    .build()
    .await
    .unwrap();
    for query in [
        JsValue::Array(Vec::new()),
        JsValue::String("invalid".into()),
    ] {
        let error = auth
            .dispatch_endpoint(
                SessionManagementPlugin::get_session_endpoint().with_query_value(query),
                EndpointOptions {
                    headers: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(error.error, alibi::AuthError::Api {
            status: 400, code: Some(code), ..
        } if code == "VALIDATION_ERROR"));
    }
    let output = auth
        .dispatch_endpoint(
            SessionManagementPlugin::get_session_endpoint(),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let session: Option<GetSessionResponse> = output.decode().unwrap();
    assert!(session.is_none());
    assert_eq!(output.status(), None);
    let headers: &Headers = output.headers();
    assert_eq!(
        headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert!(headers.get_all("set-cookie").next().is_none());
}

backend_tests!(
    stored_and_cached_reads_preserve_projection_and_storage_errors,
    refresh_options_and_expiry_preserve_all_response_cookies,
    endpoint_hooks_patch_input_and_project_the_final_response,
);

fn config() -> AuthConfig {
    AuthConfig::new("server-session-test-secret-at-least-32-characters")
        .base_url("http://session.fixture.test")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            ..Default::default()
        })
}

async fn builder<B: Backend>(db: &Db, config: AuthConfig) -> TestResult<AuthBuilder<B::Schema>> {
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    alibi::store::SchemaMigrator::migrate(&store).await?;
    Ok(AuthBuilder::new(config)
        .store(store)
        .plugin(SessionManagementPlugin::new()))
}

async fn issue<S: AuthSchema>(auth: &Alibi<S>) -> TestResult<(String, String, String)> {
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("owner@fixture.test")
                .with_name("Stored name"),
        )
        .await?;
    let session = auth
        .session_manager()
        .create_session(&user, None, None)
        .await?;
    let cookie = alibi::utils::cookie_utils::create_session_cookie(session.token(), auth.config())?;
    Ok((
        user.id().into_owned(),
        session.token().into(),
        cookie.split(';').next().unwrap().into(),
    ))
}

fn options(cookie: &str) -> EndpointOptions {
    EndpointOptions {
        headers: Some(HashMap::from([("Cookie".into(), cookie.into())])),
        ..Default::default()
    }
}

async fn http_get<S: AuthSchema>(auth: &Alibi<S>, cookie: &str) -> alibi::AuthResponse {
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
    _ = request.headers.insert("cookie".into(), cookie.into());
    auth.handle_request(request).await.unwrap()
}

fn cookies(headers: &Headers) -> Vec<String> {
    headers.get_all("set-cookie").cloned().collect()
}

async fn stored_and_cached_reads_preserve_projection_and_storage_errors<B: Backend>(
    db: Db,
) -> TestResult {
    let mut config = config();
    _ = config.user.additional_fields.insert(
        "name".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"string"}))
            .transform_output(|_| async { Ok(Some(JsValue::String("Projected name".into()))) }),
    );
    let auth = builder::<B>(&db, config).await?.build().await?;
    let (user_id, token, cookie) = issue(&auth).await?;
    let output = auth
        .dispatch_endpoint(
            SessionManagementPlugin::get_session_endpoint(),
            options(&cookie),
        )
        .await?;
    let session = output.decode()?.unwrap();
    assert_eq!(session.user.id, user_id);
    assert_eq!(session.user.name.as_deref(), Some("Projected name"));
    assert_eq!(session.session.token, token);
    assert_eq!(session.needs_refresh, None);
    let http = http_get(&auth, &cookie).await;
    assert_eq!(http.status, 200);
    assert_eq!(
        output.value().to_json_value()?,
        serde_json::from_slice::<Value>(&http.body)?
    );
    let cache = output
        .headers()
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cache.contains("session_data="));
    let cached_cookie = format!("{cookie}; {cache}");

    // A real storage outage distinguishes cache hits from accidental database fallbacks.
    _ = db.raw.execute("DROP TABLE sessions", &[]).await?;
    let cached = auth
        .dispatch_endpoint(
            SessionManagementPlugin::get_session_endpoint()
                .with_query(&GetSessionQuery::default())?,
            options(&cached_cookie),
        )
        .await?;
    let cached_session = cached.decode()?.unwrap();
    assert_eq!(cached_session.user.name.as_deref(), Some("Projected name"));
    assert_eq!(cached_session.user.id, user_id);
    assert_eq!(cached_session.session.token, token);
    assert!(cookies(cached.headers()).is_empty());
    assert_eq!(http_get(&auth, &cached_cookie).await.status, 200);
    let error = auth
        .dispatch_endpoint(
            SessionManagementPlugin::get_session_endpoint().with_query(&GetSessionQuery {
                disable_cookie_cache: true,
                ..Default::default()
            })?,
            options(&cached_cookie),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.error,
        alibi::AuthError::Upstream {
            status: 500,
            code: "FAILED_TO_GET_SESSION",
            ..
        }
    ));
    assert_eq!(
        error
            .headers
            .unwrap()
            .get("cache-control")
            .map(String::as_str),
        Some("no-store")
    );
    assert_eq!(http_get(&auth, &cookie).await.status, 500);
    Ok(())
}

async fn refresh_options_and_expiry_preserve_all_response_cookies<B: Backend>(
    db: Db,
) -> TestResult {
    for (deferred, disabled) in [(false, false), (true, false), (false, true)] {
        let db = db.fresh().await?;
        let mut config = config();
        config.session.defer_session_refresh = deferred;
        config.session.disable_session_refresh = disabled;
        let auth = builder::<B>(&db, config).await?.build().await?;
        let (_, token, cookie) = issue(&auth).await?;
        auth.store()
            .update_session_expiry(&token, Utc::now() + Duration::hours(1))
            .await?;
        let stale = auth
            .store()
            .get_session(&token)
            .await?
            .unwrap()
            .expires_at();
        let suppressed = auth
            .dispatch_endpoint(
                SessionManagementPlugin::get_session_endpoint().with_query(&GetSessionQuery {
                    disable_refresh: true,
                    ..Default::default()
                })?,
                options(&cookie),
            )
            .await?;
        assert_eq!(
            suppressed
                .decode()?
                .unwrap()
                .session
                .expires_at
                .timestamp_millis(),
            stale.timestamp_millis()
        );
        assert!(cookies(suppressed.headers()).is_empty());
        assert_eq!(
            auth.store()
                .get_session(&token)
                .await?
                .unwrap()
                .expires_at(),
            stale
        );

        let get = auth
            .dispatch_endpoint(
                SessionManagementPlugin::get_session_endpoint(),
                options(&cookie),
            )
            .await?;
        assert_eq!(
            get.decode()?.unwrap().needs_refresh,
            deferred.then_some(true)
        );
        let mut write_options = options(&cookie);
        write_options.method = Some(HttpMethod::Post);
        let post = auth
            .dispatch_endpoint(
                SessionManagementPlugin::get_session_endpoint(),
                write_options,
            )
            .await;
        let renewed = if deferred {
            assert_eq!(
                get.decode()?.unwrap().session.expires_at.timestamp_millis(),
                stale.timestamp_millis()
            );
            post?
        } else {
            assert!(matches!(
                post.unwrap_err().error,
                alibi::AuthError::Upstream {
                    status: 405,
                    code: "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
                    ..
                }
            ));
            get
        };
        let persisted = auth.store().get_session(&token).await?.unwrap();
        assert_eq!(
            renewed
                .decode()?
                .unwrap()
                .session
                .expires_at
                .timestamp_millis(),
            persisted.expires_at().timestamp_millis()
        );
        if disabled {
            assert_eq!(persisted.expires_at(), stale);
        } else {
            assert!(persisted.expires_at() > stale + Duration::days(6));
            let emitted = cookies(renewed.headers());
            assert!(emitted.len() >= 2, "token and cache cookies: {emitted:?}");
            assert!(emitted.iter().any(|cookie| {
                cookie.starts_with(&format!("{}=", auth.config().session.cookie_name))
            }));
            assert!(
                emitted
                    .iter()
                    .any(|cookie| cookie.contains("session_data="))
            );
        }
        let http = http_get(&auth, &cookie).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&http.body)?.pointer("/session/expiresAt"),
            renewed
                .value()
                .to_json_value()?
                .pointer("/session/expiresAt")
        );

        auth.store()
            .update_session_expiry(&token, Utc::now() - Duration::seconds(10))
            .await?;
        let expired = auth
            .dispatch_endpoint(
                SessionManagementPlugin::get_session_endpoint(),
                options(&cookie),
            )
            .await?;
        assert!(expired.decode()?.is_none());
        let cleared = cookies(expired.headers());
        assert_eq!(cleared.len(), 3);
        assert!(cleared.iter().all(|cookie| cookie.contains("Max-Age=0")));
        assert_eq!(auth.store().get_session(&token).await?.is_some(), deferred);
        let http = http_get(&auth, &cookie).await;
        assert_eq!(http.body, b"null");
        assert_eq!(cleared, cookies(&http.headers));
    }
    Ok(())
}

struct SessionHooks;

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for SessionHooks {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "get_session")
    }

    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "get_session")
    }

    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        assert_eq!(call.path(), Some("/get-session"));
        assert_eq!(call.operation_id(), "get_session");
        assert!(call.request().is_none());
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                query: Some(JsValue::from(json!({"disableRefresh": true}))),
                ..Default::default()
            },
        ))))
    }

    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        let (user, session) = call.session().unwrap();
        assert_eq!(user.id, session.user_id);
        let mut value = response.result().as_ref().unwrap().to_json_value()?;
        if value.is_null() {
            assert!(session.expires_at < Utc::now());
            assert!(call.virtual_session().is_none());
        } else {
            *value.pointer_mut("/user/name").unwrap() = json!("Hook name");
            response.replace(JsValue::from(value));
        }
        Ok(response
            .with_header("set-cookie", "hook_a=one; Path=/")
            .with_header("Set-Cookie", "hook_b=two; Path=/"))
    }
}

async fn endpoint_hooks_patch_input_and_project_the_final_response<B: Backend>(
    db: Db,
) -> TestResult {
    let auth = Box::pin(
        builder::<B>(&db, config())
            .await?
            .plugin(JwtPlugin::new())
            .endpoint_hook(SessionHooks)
            .build(),
    )
    .await?;
    let (user_id, token, cookie) = issue(&auth).await?;
    let foreign_user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("foreign-session-owner@fixture.test")
                .with_name("Foreign owner"),
        )
        .await?;
    let foreign_session = auth
        .session_manager()
        .create_session(&foreign_user, None, None)
        .await?;
    let foreign_token = foreign_session.token().to_owned();
    let foreign_expiry = auth
        .store()
        .get_session(&foreign_token)
        .await?
        .unwrap()
        .expires_at();
    auth.store()
        .update_session_expiry(&token, Utc::now() + Duration::hours(1))
        .await?;
    let before = auth
        .store()
        .get_session(&token)
        .await?
        .unwrap()
        .expires_at();
    let output = Box::pin(auth.dispatch_endpoint(
        SessionManagementPlugin::get_session_endpoint(),
        options(&cookie),
    ))
    .await?;
    let session = output.decode()?.unwrap();
    assert_eq!(session.user.name.as_deref(), Some("Hook name"));
    assert_eq!(session.session.token, token);
    assert_eq!(
        auth.store()
            .get_session(&token)
            .await?
            .unwrap()
            .expires_at(),
        before
    );
    assert_eq!(
        cookies(output.headers()),
        ["hook_a=one; Path=/", "hook_b=two; Path=/"]
    );
    let jwt = output
        .headers()
        .get("set-auth-jwt")
        .expect("JWT publication from logical session hooks");
    assert!(
        output
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .split(',')
            .any(|name| name.trim() == "set-auth-jwt")
    );
    let verified = Box::pin(auth.dispatch_endpoint(
        JwtPlugin::verify_endpoint(jwt.clone(), None),
        EndpointOptions::default(),
    ))
    .await?
    .decode()?
    .payload
    .unwrap();
    assert_eq!(
        verified.get("sub").and_then(Value::as_str),
        Some(user_id.as_str())
    );

    auth.store()
        .update_session_expiry(&token, Utc::now() - Duration::hours(1))
        .await?;
    let expired = Box::pin(auth.dispatch_endpoint(
        SessionManagementPlugin::get_session_endpoint(),
        options(&cookie),
    ))
    .await?;
    assert!(expired.decode()?.is_none());
    let jwt = expired
        .headers()
        .get("set-auth-jwt")
        .expect("expired lookup remains visible to completed hooks");
    let verified = Box::pin(auth.dispatch_endpoint(
        JwtPlugin::verify_endpoint(jwt.clone(), None),
        EndpointOptions::default(),
    ))
    .await?
    .decode()?
    .payload
    .unwrap();
    assert_eq!(
        verified.get("sub").and_then(Value::as_str),
        Some(user_id.as_str())
    );
    assert!(auth.store().get_session(&token).await?.is_none());
    let foreign_session = auth.store().get_session(&foreign_token).await?.unwrap();
    assert_eq!(foreign_session.user_id(), foreign_user.id());
    assert_eq!(foreign_session.expires_at(), foreign_expiry);
    assert!(
        cookies(expired.headers())
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.session_token=")
                && cookie.contains("Max-Age=0"))
    );
    Ok(())
}
