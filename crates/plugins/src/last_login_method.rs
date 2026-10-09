//! Remember successful session issuance without changing authentication authority.
use alibi_core::hooks::current_request_hook_context;
use alibi_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, RequestHookContext, UpdateUser,
};
use async_trait::async_trait;
use std::sync::Arc;

/// Request context retained at the actual adapter or completed-response boundary.
#[derive(Clone, Debug)]
pub struct LastLoginMethodContext {
    pub request: RequestHookContext,
    /// Endpoint input at this callback phase; original HTTP bytes remain in request.body.
    pub body: Option<alibi_core::utils::json::JsValue>,
    /// Admitted endpoint template; original request.path remains the actual URI.
    pub route_path: String,
    pub params: std::collections::HashMap<String, String>,
    /// Present only at the completed-response boundary. Contains original
    /// returned bytes and accumulated cookies, including authentication failures.
    pub response: Option<AuthResponse>,
    /// Original trusted issuance snapshot; later user-row writes do not replace it.
    pub new_session: Option<LastLoginMethodSession>,
}
#[derive(Clone, Debug)]
pub struct LastLoginMethodSession {
    pub user: alibi_core::wire::UserView,
    pub session: alibi_core::wire::SessionView,
}
/// A synchronous application resolver. `None` falls back to the built-in resolver;
/// an empty string suppresses tracking. Errors propagate at the invoking boundary.
pub trait ResolveLastLoginMethod: Send + Sync {
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>>;
}
/// Cookie consent does not decide whether the authenticated session may persist.
#[async_trait]
pub trait BeforeStoreLastLoginMethodCookie: Send + Sync {
    async fn before_store(
        &self,
        context: &LastLoginMethodContext,
        method: &str,
    ) -> AuthResult<bool>;
}
#[derive(Clone)]
pub struct LastLoginMethodConfig {
    pub cookie_name: String,
    pub max_age: f64,
    pub store_in_database: bool,
    pub resolver: Option<Arc<dyn ResolveLastLoginMethod>>,
    pub before_store_cookie: Option<Arc<dyn BeforeStoreLastLoginMethodCookie>>,
}
impl std::fmt::Debug for LastLoginMethodConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LastLoginMethodConfig")
            .field("cookie_name", &self.cookie_name)
            .field("max_age", &self.max_age)
            .field("store_in_database", &self.store_in_database)
            .finish_non_exhaustive()
    }
}
impl Default for LastLoginMethodConfig {
    fn default() -> Self {
        Self {
            cookie_name: "better-auth.last_used_login_method".into(),
            max_age: 2_592_000.0,
            store_in_database: false,
            resolver: None,
            before_store_cookie: None,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct LastLoginMethodPlugin {
    config: LastLoginMethodConfig,
}
impl LastLoginMethodPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: LastLoginMethodConfig) -> Self {
        Self { config }
    }
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
        if let Some(resolver) = &self.config.resolver
            && let Some(method) = resolver.resolve(context).map_err(|error| match error {
                ordinary @ alibi_core::AuthError::Internal(_) => {
                    alibi_core::AuthError::CallbackFailure(Box::new(ordinary))
                }
                other => other,
            })?
        {
            return Ok(Some(method));
        }
        let path = &context.route_path;
        let method = if path.starts_with("/callback/") {
            context
                .params
                .get("id")
                .map(String::as_str)
                .or_else(|| path.rsplit('/').next())
        } else if matches!(path.as_str(), "/sign-in/email" | "/sign-up/email") {
            Some("email")
        } else if path.contains("siwe") {
            Some("siwe")
        } else if path.contains("/passkey/verify-authentication") {
            Some("passkey")
        } else if path.starts_with("/magic-link/verify") {
            Some("magic-link")
        } else if path == "/sign-in/email-otp" {
            Some("email-otp")
        } else {
            None
        };
        Ok(method.map(str::to_owned))
    }
    fn adapter_context<S: AuthSchema>(ctx: &AuthContext<S>) -> Option<LastLoginMethodContext> {
        let mut request = current_request_hook_context()?;
        request.path = request
            .path
            .strip_prefix(&ctx.config.base_path)
            .unwrap_or(&request.path)
            .to_owned();
        let body = request
            .extensions
            .get::<alibi_core::hooks::ValidatedRequestBody>()
            .map(|body| body.0.clone())
            .or_else(|| {
                request
                    .extensions
                    .get::<alibi_core::hooks::TransformedRequestBody>()
                    .map(|body| body.0.clone())
            })
            .or_else(|| {
                request
                    .body
                    .as_deref()
                    .and_then(|body| alibi_core::utils::json::from_slice(body).ok())
            });
        let new_session = request
            .extensions
            .get::<super::helpers::CompletedSession<S>>()
            .map(|completed| LastLoginMethodSession {
                user: completed.callback_user(ctx),
                session: completed.callback_session(ctx),
            });
        let endpoint = request
            .extensions
            .get::<alibi_core::plugin::ResolvedEndpoint>();
        let route_path = endpoint
            .as_ref()
            .map_or_else(|| request.path.clone(), |endpoint| endpoint.path.clone());
        let params = endpoint
            .map(|endpoint| endpoint.params.clone())
            .unwrap_or_default();
        Some(LastLoginMethodContext {
            body,
            request,
            route_path,
            params,
            response: None,
            new_session,
        })
    }
    fn cookie(&self, method: &str, config: &alibi_core::AuthConfig) -> AuthResult<String> {
        if self.config.max_age > 34_560_000.0 {
            return Err(alibi_core::AuthError::CallbackFailure(Box::new(
                alibi_core::AuthError::internal("Invalid login-method cookie lifetime"),
            )));
        }
        let defaults = &config.advanced.default_cookie_attributes;
        let overrides = config
            .advanced
            .cookies
            .get("session_token")
            .map(|cookie| &cookie.attributes);
        let secure = overrides
            .and_then(|attrs| attrs.secure)
            .or(defaults.secure)
            .unwrap_or(config.session.cookie_secure);
        let same_site = overrides
            .and_then(|attrs| attrs.same_site.as_ref())
            .or(defaults.same_site.as_ref())
            .unwrap_or(&config.session.cookie_same_site);
        let path = overrides
            .and_then(|attrs| attrs.path.as_deref())
            .or(defaults.path.as_deref())
            .unwrap_or("/");
        let domain = overrides
            .and_then(|attrs| attrs.domain.as_deref())
            .or(defaults.domain.as_deref())
            .or(config
                .advanced
                .cross_sub_domain_cookies
                .as_ref()
                .map(|cross| cross.domain.as_str()));
        let value = urlencoding::encode(method)
            .replace("%21", "!")
            .replace("%27", "'")
            .replace("%28", "(")
            .replace("%29", ")")
            .replace("%2A", "*");
        let mut cookie = cookie::Cookie::build((self.config.cookie_name.clone(), value))
            .path(path)
            .secure(secure)
            .http_only(false)
            .same_site(match same_site {
                alibi_core::config::SameSite::Strict => cookie::SameSite::Strict,
                alibi_core::config::SameSite::Lax => cookie::SameSite::Lax,
                alibi_core::config::SameSite::None => cookie::SameSite::None,
            });
        if let Some(domain) = domain {
            cookie = cookie.domain(domain.to_owned());
        }
        if self.config.max_age >= 0.0 {
            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "Cookie max age is finite, bounded, and floors nonnegative JavaScript seconds"
            )]
            let seconds = self.config.max_age.floor() as i64;
            cookie = cookie.max_age(cookie::time::Duration::seconds(seconds));
        }
        Ok(cookie.build().to_string())
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for LastLoginMethodPlugin {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &alibi_core::AuthInitContext<S>,
    ) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "last-login-method"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.set_metadata(
            "last-login-method.store-in-database",
            serde_json::json!(self.config.store_in_database),
        );
        if !self.config.store_in_database {
            return Ok(());
        }
        ctx.set_metadata("last-login-method.enabled", serde_json::json!(true));
        let plugin = self.clone();
        let runtime = Arc::new(AuthContext {
            config: Arc::clone(&ctx.config),
            database: Arc::clone(&ctx.database),
            email_provider: ctx.email_provider.clone(),
            metadata: ctx.metadata.clone(),
            extensions: ctx.extensions.clone(),
        });
        let runtime_create = Arc::clone(&runtime);
        ctx.register_user_create_transform(move |mut data| {
            if let Some(context) = Self::adapter_context(&runtime_create)
                && let Some(method) = plugin
                    .resolve(&context)?
                    .filter(|method| !method.is_empty())
            {
                data.last_login_method = Some(method);
            }
            Ok(data)
        });
        ctx.register_session_created_hook(Arc::new(LastLoginSessionHook {
            plugin: self.clone(),
            context: runtime,
        }));
        Ok(())
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let new_session =
            super::helpers::completed_response_session(req, ctx, &response).map(|completed| {
                LastLoginMethodSession {
                    user: completed.callback_user(ctx),
                    session: completed.callback_session(ctx),
                }
            });
        let endpoint = req
            .extensions()
            .get::<alibi_core::plugin::ResolvedEndpoint>();
        let context = LastLoginMethodContext {
            route_path: endpoint
                .as_ref()
                .map_or_else(|| req.path().to_owned(), |endpoint| endpoint.path.clone()),
            params: endpoint
                .map(|endpoint| endpoint.params.clone())
                .unwrap_or_default(),
            body: req
                .extensions()
                .get::<alibi_core::hooks::TransformedRequestBody>()
                .map(|body| body.0.clone())
                .or_else(|| {
                    req.body
                        .as_deref()
                        .and_then(|body| alibi_core::utils::json::from_slice(body).ok())
                }),
            request: RequestHookContext::from_request(req),
            response: Some(response.clone()),
            new_session,
        };
        if let Some(method) = self.resolve(&context)?.filter(|method| !method.is_empty())
            && response
                .headers
                .get_all("set-cookie")
                .any(|header| header.contains(&ctx.config.session.cookie_name))
        {
            let permitted = match &self.config.before_store_cookie {
                None => true,
                Some(callback) => match callback.before_store(&context, &method).await {
                    Ok(permitted) => permitted,
                    Err(error) => {
                        tracing::error!(%error,"[LastLoginMethod] Error in beforeStoreCookie hook");
                        false
                    }
                },
            };
            if permitted {
                response
                    .headers
                    .append("set-cookie", self.cookie(&method, &ctx.config)?);
            }
        }
        Ok(response)
    }
}

struct LastLoginSessionHook<S: AuthSchema> {
    plugin: LastLoginMethodPlugin,
    context: Arc<AuthContext<S>>,
}
#[async_trait]
impl<S: AuthSchema> alibi_core::store::SessionCreatedHook<S> for LastLoginSessionHook<S> {
    async fn after_create(
        &self,
        session: &S::Session,
        database: &dyn alibi_core::store::AuthStore<S>,
    ) -> AuthResult<()> {
        if let Some(context) = LastLoginMethodPlugin::adapter_context(&self.context)
            && let Some(method) = self
                .plugin
                .resolve(&context)?
                .filter(|method| !method.is_empty())
            && let Err(error) = database
                .update_user_record(
                    session.user_id().as_ref(),
                    UpdateUser {
                        last_login_method: Some(Some(method)),
                        ..Default::default()
                    },
                )
                .await
        {
            tracing::error!(%error,"Failed to update lastLoginMethod");
        }
        Ok(())
    }
}

/// Reject caller-supplied tracking values when the registered database field is
/// server managed. Call after the endpoint's ordinary admission validation.
///
/// # Errors
/// Returns the published FIELD_NOT_ALLOWED response for truthy supplied values.
pub fn reject_last_login_method_input<S: AuthSchema>(
    ctx: &AuthContext<S>,
    value: Option<&alibi_core::utils::json::JsValue>,
) -> AuthResult<()> {
    use alibi_core::utils::json::JsValue;
    let truthy = match value {
        None | Some(JsValue::Null) => false,
        Some(JsValue::Bool(value)) => *value,
        Some(JsValue::Number(value)) => *value != 0.0 && !value.is_nan(),
        Some(JsValue::String(value)) => !value.is_empty(),
        Some(JsValue::Array(_) | JsValue::Object(_)) => true,
    };
    if ctx
        .get_metadata("last-login-method.enabled")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && truthy
    {
        return Err(alibi_core::AuthError::Upstream {
            status: 400,
            code: "FIELD_NOT_ALLOWED",
            message: "lastLoginMethod is not allowed to be set",
        });
    }
    Ok(())
}
