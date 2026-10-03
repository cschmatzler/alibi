//! Application-owned asynchronous session response projection.
use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use serde_json::Value;
use std::sync::Arc;

/// Project an authenticated session response into application response data.
///
/// The input is the actual public session/user projection, including configured
/// fields and deferred-refresh information. Transforming it does not change the
/// stored principal or the authentication context used by subsequent plugins.
#[async_trait]
pub trait SessionTransform<S: AuthSchema>: Send + Sync {
    /// # Errors
    /// Return an intentional API error or an application callback failure.
    async fn transform(
        &self,
        session: Value,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Value>;
}

/// Replace GET session responses while retaining core authentication and cookies.
/// Register before an explicitly installed `SessionManagementPlugin` so this
/// plugin owns the GET route. The replacement accepts GET only, including
/// when deferred refresh is enabled.
pub struct CustomSessionPlugin<S: AuthSchema> {
    transform: Arc<dyn SessionTransform<S>>,
    mutate_device_sessions: bool,
}

impl<S: AuthSchema> CustomSessionPlugin<S> {
    #[must_use]
    pub fn new(transform: impl SessionTransform<S> + 'static) -> Self {
        Self {
            transform: Arc::new(transform),
            mutate_device_sessions: false,
        }
    }

    /// Apply the same projection to each genuine multiple-device-session entry.
    #[must_use]
    pub fn mutate_device_sessions(mut self, enabled: bool) -> Self {
        self.mutate_device_sessions = enabled;
        self
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for CustomSessionPlugin<S> {
    fn name(&self) -> &'static str {
        "custom-session"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "get_session"),
            AuthRoute::post("/get-session", "custom_session_post"),
        ]
    }

    fn openapi_metadata(
        &self,
        ctx: &better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::openapi::PluginOpenApiMetadata {
        let mut metadata = better_auth_core::openapi::annotations::instance_plugin_metadata(
            "session-management",
            &self.routes(),
            ctx,
        );
        // Pinned documentation retains the base endpoint and excludes the
        // replacement that shares its logical API key, despite GET-only HTTP.
        for (_, _, endpoint) in &mut metadata.endpoints {
            endpoint.native_extension = true;
        }
        metadata
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() != "/get-session" {
            return Ok(None);
        }
        if req.method() == &HttpMethod::Post {
            return Ok(Some(AuthResponse::new(404)));
        }
        if req.method() != &HttpMethod::Get {
            return Ok(None);
        }
        let prior_headers = req.take_response_headers();
        let mut response = match super::session_management::SessionManagementPlugin::new()
            .handle_get_session(req, ctx)
            .await
        {
            Ok(response) => response,
            Err(_) => AuthResponse::json(200, &Value::Null)?,
        };
        let session: Value = if response.status >= 400 {
            Value::Null
        } else {
            serde_json::from_slice(&response.body)?
        };
        let core_headers = req.take_response_headers();
        for (name, value) in prior_headers {
            req.queue_response_header(name, value);
        }
        let (issued_cookies, _) = better_auth_core::cache::runtime::take_issuance(req.extensions());
        if session.is_null() {
            // The replaced endpoint does not forward headers from a missing or
            // failed core response. Preserve headers emitted before that read.
            return Ok(Some(AuthResponse::json(200, &Value::Null)?));
        }
        let transformed = self
            .transform
            .transform(session, req, ctx)
            .await
            .map_err(callback_error)?;
        response.body = serde_json::to_vec(&transformed)?;
        for (name, value) in core_headers {
            response.headers.append(name, value);
        }
        for cookie in issued_cookies {
            response.headers.append("Set-Cookie", cookie);
        }
        Ok(Some(response))
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !self.mutate_device_sessions
            || req.path() != "/multi-session/list-device-sessions"
            || response.status >= 400
        {
            return Ok(response);
        }
        let value: Value = serde_json::from_slice(&response.body)?;
        if let Value::Array(sessions) = value {
            let transformed = self.transform_list(sessions, req, ctx).await?;
            response.body = serde_json::to_vec(&transformed)?;
        }
        Ok(response)
    }
}

impl<S: AuthSchema> CustomSessionPlugin<S> {
    async fn transform_list(
        &self,
        sessions: Vec<Value>,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Vec<Value>> {
        if sessions.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = vec![None; sessions.len()];
        let transform = self.transform.clone();
        let request = request.clone();
        let context = AuthContext::<S> {
            config: context.config.clone(),
            database: context.database.clone(),
            email_provider: context.email_provider.clone(),
            metadata: context.metadata.clone(),
            extensions: context.extensions.clone(),
        };
        let endpoint = better_auth_core::endpoint::current_endpoint_call_context();
        let hook = better_auth_core::hooks::current_request_hook_context();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        // Launched callbacks retain ownership after the aggregate rejects,
        // matching the independent application work of a device-session list.
        drop(tokio::spawn(async move {
            let project = async {
                drop(
                    futures_util::future::join_all(sessions.into_iter().enumerate().map(
                        |(index, session)| {
                            let transform = &transform;
                            let request = &request;
                            let context = &context;
                            let sender = &sender;
                            async move {
                                let result = transform
                                    .transform(session, request, context)
                                    .await
                                    .map_err(callback_error);
                                let _closed = sender.send((index, result));
                            }
                        },
                    ))
                    .await,
                );
            };
            if let Some(endpoint) = endpoint {
                better_auth_core::endpoint::with_endpoint_call_context(
                    endpoint,
                    better_auth_core::hooks::with_optional_request_hook_context(hook, project),
                )
                .await;
            } else {
                better_auth_core::hooks::with_optional_request_hook_context(hook, project).await;
            }
        }));
        for _ in 0..results.len() {
            let (index, value) = receiver.recv().await.ok_or_else(|| {
                better_auth_core::AuthError::internal("Session transformation stopped")
            })?;
            let slot = results.get_mut(index).ok_or_else(|| {
                better_auth_core::AuthError::internal("Invalid session transformation row")
            })?;
            *slot = Some(value?);
        }
        Ok(results.into_iter().flatten().collect())
    }
}

fn callback_error(error: better_auth_core::AuthError) -> better_auth_core::AuthError {
    use better_auth_core::AuthError;
    match error {
        AuthError::Api { .. } | AuthError::Upstream { .. } | AuthError::CallbackFailure(_) => error,
        error => AuthError::CallbackFailure(Box::new(error)),
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers::{
        create_auth_request_no_query, create_test_context, create_user_and_session,
    };
    use better_auth_core::hooks::with_request_hook_context;
    use better_auth_core::{CreateUser, UpdateUser};
    use std::sync::Arc;
    use tokio::sync::Notify;
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    struct Transform {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        finished: Arc<Notify>,
    }
    #[async_trait]
    impl SessionTransform<Schema> for Transform {
        async fn transform(
            &self,
            value: Value,
            req: &AuthRequest,
            ctx: &AuthContext<Schema>,
        ) -> AuthResult<Value> {
            let id = value
                .pointer("/user/id")
                .and_then(Value::as_str)
                .expect("actual user id");
            let name = value
                .pointer("/user/name")
                .and_then(Value::as_str)
                .expect("actual user name");
            if name == "Reject" {
                self.entered.notified().await;
                return Err(better_auth_core::AuthError::internal("application failure"));
            }
            self.entered.notify_one();
            self.release.notified().await;
            assert_eq!(req.path(), "/multi-session/list-device-sessions");
            assert_eq!(
                better_auth_core::hooks::current_request_hook_context()
                    .expect("retained real request")
                    .headers
                    .get("x-application"),
                Some(&"original".to_owned())
            );
            ctx.database
                .update_user(
                    id,
                    UpdateUser {
                        name: Some("Completed".into()),
                        ..Default::default()
                    },
                )
                .await?;
            self.finished.notify_one();
            Ok(value)
        }
    }

    #[tokio::test]
    async fn rejected_device_list_preserves_launched_callback_request_and_database_ownership() {
        let ctx = create_test_context().await;
        let (reject, reject_session) = create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("reject@custom.fixture.test")
                .with_name("Reject"),
            chrono::Duration::hours(1),
        )
        .await;
        let (slow, slow_session) = create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("slow@custom.fixture.test")
                .with_name("Slow"),
            chrono::Duration::hours(1),
        )
        .await;
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let finished = Arc::new(Notify::new());
        let plugin = CustomSessionPlugin::new(Transform {
            entered,
            release: release.clone(),
            finished: finished.clone(),
        })
        .mutate_device_sessions(true);
        let mut req = create_auth_request_no_query(
            HttpMethod::Get,
            "/multi-session/list-device-sessions",
            Some(&reject_session.token),
            None,
        );
        drop(
            req.headers
                .insert("x-application".into(), "original".into()),
        );
        use better_auth_core::utils::cookie_utils::sign_cookie_value;
        let cookies = [&reject_session.token, &slow_session.token]
            .into_iter()
            .map(|token| {
                format!(
                    "{}_multi-{}={}",
                    ctx.config.session.cookie_name,
                    token.to_lowercase(),
                    sign_cookie_value(token, ctx.config.current_secret())
                )
            })
            .collect::<Vec<_>>();
        let ordinary = req.header("cookie").expect("signed current cookie").clone();
        drop(req.headers.insert(
            "cookie".into(),
            format!("{ordinary}; {}", cookies.join("; ")),
        ));
        let response = super::super::multi_session::MultiSessionPlugin::new()
            .on_request(&req, &ctx)
            .await
            .expect("real list")
            .expect("list route");
        assert_eq!(response.status, 200);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            with_request_hook_context(&req, plugin.after_request(&req, &ctx, response)),
        )
        .await
        .expect("aggregate rejects without waiting for held callback");
        assert!(matches!(
            result,
            Err(better_auth_core::AuthError::CallbackFailure(_))
        ));
        assert_eq!(
            ctx.database
                .get_user_by_id(&slow.id)
                .await
                .expect("read")
                .expect("stored slow owner")
                .name
                .as_deref(),
            Some("Slow")
        );
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), finished.notified())
            .await
            .expect("launched callback completes after observer rejection");
        assert_eq!(
            ctx.database
                .get_user_by_id(&slow.id)
                .await
                .expect("read")
                .expect("stored slow owner")
                .name
                .as_deref(),
            Some("Completed")
        );
        assert_eq!(
            ctx.database
                .get_user_by_id(&reject.id)
                .await
                .expect("read")
                .expect("stored reject owner")
                .name
                .as_deref(),
            Some("Reject")
        );
    }
}
// LCOV_EXCL_STOP
