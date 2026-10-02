#[cfg(test)]
mod tests;

use crate::config::AuthConfig;
use crate::email::EmailProvider;
use crate::entity::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::session::SessionManager;
use crate::store::AuthStore;
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

type MetadataMap = HashMap<String, serde_json::Value>;

/// Typed settings and callbacks published during plugin initialization.
///
/// Registration is complete before requests begin; readers share immutable
/// values rather than interpreting configuration through JSON metadata.
#[derive(Clone, Default)]
pub struct ContextExtensions(HashMap<TypeId, Arc<dyn Any + Send + Sync>>);

impl ContextExtensions {
    pub fn insert<T: Any + Send + Sync>(&mut self, value: T) {
        drop(self.0.insert(TypeId::of::<T>(), Arc::new(value)));
    }

    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        Arc::clone(self.0.get(&TypeId::of::<T>())?).downcast().ok()
    }
}

pub struct AuthInitParts {
    pub metadata: MetadataMap,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub extensions: ContextExtensions,
}

/// A plugin override for delivery of the core email-verification challenge.
#[async_trait]
pub trait VerificationEmailOverride<S: AuthSchema>: Send + Sync {
    async fn send(
        &self,
        user: &crate::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()>;

    async fn send_in_transaction(
        &self,
        user: &crate::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        _transaction: &dyn crate::store::AuthTransaction<S>,
    ) -> AuthResult<()> {
        self.send(user, request, ctx).await
    }
}

pub struct VerificationEmailOverrideHandle<S: AuthSchema>(
    pub Arc<dyn VerificationEmailOverride<S>>,
);

/// Action returned by [`AuthPlugin::before_request`].
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve public InjectSession construction as session views gain configured output policies"
)]
pub enum BeforeRequestAction {
    /// Short-circuit with this response (e.g. return session JSON).
    Respond(AuthResponse),
    /// Inject a virtual session so downstream handlers see it as authenticated.
    InjectSession { session: crate::wire::SessionView },
    /// Replace headers for subsequent hooks, endpoint dispatch and response hooks.
    /// Authentication adapters can establish a verified signed cookie while
    /// retaining normal session lookup, expiry and revocation checks.
    ReplaceHeaders { headers: HashMap<String, String> },
}

/// Plugin trait that all authentication plugins must implement.
///
#[async_trait]
pub trait AuthPlugin<S: AuthSchema>: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Media types accepted before request hooks and endpoint dispatch. An empty
    /// list disables the media restriction for an application-owned endpoint.
    fn allowed_media_types(&self, _route: &AuthRoute) -> Vec<&'static str> {
        vec!["application/json"]
    }

    /// Session field policies contributed by this registered plugin.
    fn session_fields(&self) -> indexmap::IndexMap<String, crate::field_policy::FieldConfig> {
        indexmap::IndexMap::new()
    }

    fn user_fields(&self) -> crate::field_policy::FieldConfigs {
        crate::field_policy::FieldConfigs::new()
    }

    fn account_fields(&self) -> crate::field_policy::FieldConfigs {
        crate::field_policy::FieldConfigs::new()
    }

    /// Documentation annotations collected after all plugins initialize.
    /// Override this hook for custom endpoints and model field policies.
    fn openapi_metadata(&self, ctx: &AuthInitContext<S>) -> crate::openapi::PluginOpenApiMetadata {
        crate::openapi::annotations::instance_plugin_metadata(self.name(), &self.routes(), ctx)
    }

    /// Called when the plugin is initialized
    async fn on_init(&self, _ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Inspect the original physical HTTP request before routing, body parsing,
    /// origin validation and endpoint hooks. Disabled paths and transport/rate
    /// limiting middleware run first. Returning a response stops dispatch and
    /// later plugin hooks. Server-only endpoint calls do not invoke this hook.
    async fn on_http_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    /// Called after route matching and before endpoint dispatch.
    ///
    /// Return `Some(BeforeRequestAction::Respond(..))` to short-circuit with a
    /// response, `Some(BeforeRequestAction::InjectSession { .. })` to attach a
    /// virtual session (e.g. API-key → session emulation),
    /// `Some(BeforeRequestAction::ReplaceHeaders { .. })` to transform request
    /// headers, or `None` to continue endpoint dispatch.
    async fn before_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(None)
    }

    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>>;

    /// Transform a completed response, including redirects and rejections.
    ///
    /// Hooks run in plugin registration order with the normalized auth path.
    /// This supports cookie and header lifecycles that span other plugins.
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        Ok(response)
    }

    /// Called after a user is created
    async fn on_user_created(&self, _user: &S::User, _ctx: &AuthContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Called after a session is created
    async fn on_session_created(
        &self,
        _session: &S::Session,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a user is deleted
    async fn on_user_deleted(&self, _user_id: &str, _ctx: &AuthContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a session is deleted
    async fn on_session_deleted(
        &self,
        _session_token: &str,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        Ok(())
    }
}

/// Generates the [`AuthPlugin`] impl for a plugin with static route dispatch.
///
/// Eliminates the dual declaration of routes in `routes()` and `on_request()`
/// by generating both from a single route table.
///
/// # Exceptions (must keep manual impl)
/// - `OAuthPlugin` — dynamic path matching for `/callback/{provider}`
/// - `SessionManagementPlugin` — match guards and OR patterns
/// - `EmailPasswordPlugin` — conditional routes based on config
/// - `UserManagementPlugin` — conditional routes based on config
/// - `PasswordManagementPlugin` — dynamic path matching for `/reset-password/{token}`
/// - `OrganizationPlugin` — handlers accept extra `&self.config` argument
#[macro_export]
macro_rules! impl_auth_plugin {
    (@pat get) => { $crate::HttpMethod::Get };
    (@pat post) => { $crate::HttpMethod::Post };
    (@pat put) => { $crate::HttpMethod::Put };
    (@pat delete) => { $crate::HttpMethod::Delete };
    (@pat patch) => { $crate::HttpMethod::Patch };
    (@pat head) => { $crate::HttpMethod::Head };

    (@route get) => { $crate::AuthRoute::get };
    (@route post) => { $crate::AuthRoute::post };
    (@route put) => { $crate::AuthRoute::put };
    (@route delete) => { $crate::AuthRoute::delete };

    (
        $plugin:ty, $name:expr;
        routes {
            $( $method:ident $path:literal => $handler:ident, $op_id:literal );* $(;)?
        }
        $( extra { $($extra:tt)* } )?
    ) => {
        #[::async_trait::async_trait]
        impl<S: $crate::AuthSchema> $crate::AuthPlugin<S> for $plugin {
            fn name(&self) -> &'static str { $name }

            fn routes(&self) -> Vec<$crate::AuthRoute> {
                vec![
                    $( $crate::AuthRoute::new($crate::impl_auth_plugin!(@pat $method), $path, $op_id), )*
                ]
            }

            async fn on_request(
                &self,
                req: &$crate::AuthRequest,
                ctx: &$crate::AuthContext<S>,
            ) -> $crate::AuthResult<Option<$crate::AuthResponse>> {
                match (req.method(), req.path()) {
                    $(
                        ($crate::impl_auth_plugin!(@pat $method), $path) => {
                            Ok(Some(self.$handler(req, ctx).await?))
                        }
                    )*
                    _ => Ok(None),
                }
            }

            $( $($extra)* )?
        }
    };
}

/// The admitted endpoint's logical callback path and matched path parameters.
/// Original request bytes and URI remain in the request itself.
#[derive(Clone, Debug, Default)]
pub struct ResolvedEndpoint {
    pub path: String,
    pub params: HashMap<String, String>,
}

/// Route definition for plugins.
#[derive(Debug, Clone)]
pub struct AuthRoute {
    pub path: String,
    /// Logical callback template when it differs from native routing syntax.
    pub context_path: Option<String>,
    pub method: HttpMethod,
    /// Identifier used as the `OpenAPI` `operationId` for this route.
    pub operation_id: String,
}

/// Initialization context passed to plugin setup.
pub struct AuthInitContext<S: AuthSchema> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: MetadataMap,
    pub extensions: ContextExtensions,
}

/// Context passed to plugin methods.
pub struct AuthContext<S: AuthSchema> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: MetadataMap,
    pub extensions: ContextExtensions,
}

impl AuthRoute {
    #[must_use]
    pub fn new(
        method: HttpMethod,
        path: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            context_path: None,
            method,
            operation_id: operation_id.into(),
        }
    }

    #[must_use]
    pub fn with_context_path(mut self, path: impl Into<String>) -> Self {
        self.context_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn get(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path, operation_id)
    }

    #[must_use]
    pub fn post(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path, operation_id)
    }

    #[must_use]
    pub fn put(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path, operation_id)
    }

    #[must_use]
    pub fn delete(path: impl Into<String>, operation_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path, operation_id)
    }
}

impl<S: AuthSchema> AuthInitContext<S> {
    #[must_use]
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        let email_provider = config.email_provider.clone();
        Self {
            config,
            database,
            email_provider,
            metadata: MetadataMap::new(),
            extensions: ContextExtensions::default(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        drop(self.metadata.insert(key.into(), value));
    }

    /// Decorate the instance's actual password hashing boundary. Later
    /// registrations run first, matching initialized hash wrappers.
    pub fn register_password_hash_hook(
        &mut self,
        hook: Arc<dyn crate::utils::password::PasswordHashHook>,
    ) {
        let mut hooks = self
            .extensions
            .get::<crate::utils::password::PasswordHashHooks>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        hooks.0.push(hook);
        self.extensions.insert(hooks);
    }

    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    /// Register a transform for user creation, including transactional creation.
    pub fn register_user_create_transform<F>(&mut self, transform: F)
    where
        F: Fn(crate::types::CreateUser) -> AuthResult<crate::types::CreateUser>
            + Send
            + Sync
            + 'static,
    {
        let mut transforms = self
            .extensions
            .get::<crate::store::UserTransforms>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        transforms.creates.push(Arc::new(transform));
        self.extensions.insert(transforms);
    }

    /// Register model defaults applied after creation hooks to an identity
    /// candidate admitted by the configured user validation policy.
    pub fn register_user_creation_adapter_default<F>(&mut self, default: F)
    where
        F: Fn(crate::types::CreateUser) -> AuthResult<crate::types::CreateUser>
            + Send
            + Sync
            + 'static,
    {
        let mut transforms = self
            .extensions
            .get::<crate::store::UserTransforms>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        transforms.adapter_defaults.0.push(Arc::new(default));
        self.extensions.insert(transforms);
    }

    /// Register a transform applied to every user update through this auth instance.
    pub fn register_user_update_transform<F>(&mut self, transform: F)
    where
        F: Fn(&str, crate::types::UpdateUser) -> AuthResult<crate::types::UpdateUser>
            + Send
            + Sync
            + 'static,
    {
        let mut transforms = self
            .extensions
            .get::<crate::store::UserTransforms>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        transforms.updates.push(Arc::new(transform));
        self.extensions.insert(transforms);
    }

    /// Register an adapter lifecycle callback for each committed session creation.
    /// Transactional creations defer callbacks until commit and discard them on
    /// rollback. A callback error propagates after persistence, as for other
    /// adapter after callbacks. Trusted server operations have no request context.
    pub fn register_session_created_hook(
        &mut self,
        callback: Arc<dyn crate::store::SessionCreatedHook<S>>,
    ) {
        let mut callbacks = self
            .extensions
            .get::<crate::store::SessionCreatedCallbacks<S>>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        callbacks.callbacks.push(callback);
        self.extensions.insert(callbacks);
    }

    /// Observe genuine retained adapter output after a write, with transaction
    /// callbacks deferred until commit. Existing typed physical hooks are separate.
    pub fn register_adapter_after_hook(
        &mut self,
        callback: Arc<dyn crate::store::AdapterAfterHook<S>>,
    ) {
        let mut callbacks = self
            .extensions
            .get::<crate::store::AdapterCallbacks<S>>()
            .map(|callbacks| (*callbacks).clone())
            .unwrap_or_default();
        callbacks.0.push(callback);
        self.extensions.insert(callbacks);
    }

    /// Finalize the instance's store without mutating a shared underlying adapter.
    #[must_use]
    pub fn database_with_registered_transforms(&self) -> Arc<dyn AuthStore<S>> {
        let transforms = self
            .extensions
            .get::<crate::store::UserTransforms>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        let session_callbacks = self
            .extensions
            .get::<crate::store::SessionCreatedCallbacks<S>>()
            .map(|value| (*value).clone())
            .unwrap_or_default();
        let fields = self.extensions.get::<crate::field_policy::SessionFields>();
        if transforms.creates.is_empty()
            && transforms.updates.is_empty()
            && session_callbacks.callbacks.is_empty()
            && fields.is_none()
            && self.config.user_validation.is_none()
        {
            return Arc::clone(&self.database);
        }
        Arc::new(crate::store::PluginStore::new(
            Arc::clone(&self.database),
            Arc::clone(&self.config),
            transforms,
            session_callbacks,
            fields.map(|fields| (*fields).clone()).unwrap_or_default(),
            self.extensions
                .get::<crate::field_policy::SessionAdapterFields>()
                .map(|fields_2| (*fields_2).clone())
                .unwrap_or_default(),
            AuthContext::with_metadata(
                Arc::clone(&self.config),
                Arc::clone(&self.database),
                self.metadata.clone(),
            )
            .with_extensions(self.extensions.clone()),
        ))
    }

    pub fn set_email_verification_override(
        &mut self,
        sender: Arc<dyn VerificationEmailOverride<S>>,
    ) {
        self.extensions
            .insert(VerificationEmailOverrideHandle(sender));
    }

    #[must_use]
    pub fn into_parts(self) -> AuthInitParts {
        AuthInitParts {
            metadata: self.metadata,
            email_provider: self.email_provider,
            extensions: self.extensions,
        }
    }
}

impl<S: AuthSchema> AuthContext<S> {
    /// Parse configured user fields at the endpoint boundary before creation
    /// validation or adapter hooks. Unknown fields are ignored by this policy.
    pub fn parse_user_fields(
        &self,
        input: &indexmap::IndexMap<String, crate::utils::json::JsValue>,
        creation: bool,
    ) -> Result<crate::field_policy::FieldValues, crate::field_policy::FieldInputError> {
        let registered = self.extensions.get::<crate::field_policy::UserFields>();
        let configured =
            crate::field_policy::SessionFields(self.config.user.additional_fields.clone());
        let fields = registered.as_ref().map_or(&configured, |fields| &fields.0);
        if creation {
            fields.parse_create(input)
        } else {
            fields.parse_update(input)
        }
    }

    /// Hash through initialized policies at the current actual endpoint.
    ///
    /// # Errors
    /// Propagates policy rejections and original hasher errors.
    pub async fn hash_password(
        &self,
        hasher: Option<&Arc<dyn crate::utils::password::PasswordHasher>>,
        password: &str,
    ) -> AuthResult<String> {
        let context = crate::hooks::current_request_hook_context()
            .map(crate::utils::password::PasswordHashContext::from_request);
        self.hash_password_with_context(hasher, password, context.as_ref())
            .await
    }

    /// Hash for a trusted endpoint call whose logical context is independent
    /// of an optional physical request, including server-only APIs.
    ///
    /// # Errors
    /// Propagates policy rejections and original hasher errors.
    pub async fn hash_password_with_context(
        &self,
        hasher: Option<&Arc<dyn crate::utils::password::PasswordHasher>>,
        password: &str,
        context: Option<&crate::utils::password::PasswordHashContext>,
    ) -> AuthResult<String> {
        if let Some(hooks) = self
            .extensions
            .get::<crate::utils::password::PasswordHashHooks>()
        {
            for hook in hooks.0.iter().rev() {
                hook.before_hash(password, context).await?;
            }
        }
        crate::utils::password::hash_password(hasher, password).await
    }

    #[must_use]
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        let email_provider = config.email_provider.clone();
        Self {
            config,
            database,
            email_provider,
            metadata: MetadataMap::new(),
            extensions: ContextExtensions::default(),
        }
    }

    #[must_use]
    pub fn with_metadata(
        config: Arc<AuthConfig>,
        database: Arc<dyn AuthStore<S>>,
        metadata: MetadataMap,
    ) -> Self {
        let email_provider = config.email_provider.clone();
        Self {
            config,
            database,
            email_provider,
            metadata,
            extensions: ContextExtensions::default(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        drop(self.metadata.insert(key.into(), value));
    }

    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    #[must_use]
    pub fn with_extensions(mut self, extensions: ContextExtensions) -> Self {
        self.extensions = extensions;
        self
    }

    #[must_use]
    pub fn email_verification_override(&self) -> Option<Arc<VerificationEmailOverrideHandle<S>>> {
        self.extensions.get()
    }

    pub fn user_view(&self, user: &impl crate::entity::AuthUser) -> crate::wire::UserView {
        self.project_user_view(user, true)
    }

    /// Project trusted adapter output without removing declared hidden fields.
    /// Canonical identity accessors still refer to the physical model.
    pub fn trusted_user_view(&self, user: &impl crate::entity::AuthUser) -> crate::wire::UserView {
        self.project_user_view(user, false)
    }

    fn project_user_view(
        &self,
        user: &impl crate::entity::AuthUser,
        public: bool,
    ) -> crate::wire::UserView {
        if let Some(view) = user.retained_user_view() {
            let mut view = view.clone();
            if public {
                let registered = self.extensions.get::<crate::field_policy::UserFields>();
                let fields = registered
                    .as_ref()
                    .map_or(&self.config.user.additional_fields, |fields| &fields.0.0);
                view.extension_fields
                    .retain(|name, _| fields.get(name).is_none_or(|field| field.returned));
            }
            return view;
        }
        let mut view = crate::wire::UserView::from(user);
        if self.feature_enabled("username.enabled") {
            for (key, absent) in [
                ("username", view.username.is_none()),
                ("displayUsername", view.display_username.is_none()),
            ] {
                if absent {
                    drop(
                        view.extension_fields
                            .insert(key.into(), serde_json::Value::Null),
                    );
                }
            }
        } else {
            view.username = None;
            view.display_username = None;
        }
        if self.feature_enabled("two_factor.enabled") {
            view.two_factor_enabled = user.two_factor_enabled_value();
            if view.two_factor_enabled.is_none() {
                drop(
                    view.extension_fields
                        .insert("twoFactorEnabled".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.two_factor_enabled = None;
        }
        if self.feature_enabled("admin.enabled") {
            view.banned = user.banned_value();
            for (key, absent) in [
                ("role", view.role.is_none()),
                ("banned", view.banned.is_none()),
                ("banReason", view.ban_reason.is_none()),
                ("banExpires", view.ban_expires.is_none()),
            ] {
                if absent {
                    drop(
                        view.extension_fields
                            .insert(key.into(), serde_json::Value::Null),
                    );
                }
            }
        } else {
            view.role = None;
            view.banned = None;
            view.ban_reason = None;
            view.ban_expires = None;
        }

        if self.feature_enabled("anonymous.enabled") {
            view.is_anonymous = Some(user.is_anonymous().unwrap_or(false));
        } else {
            view.is_anonymous = None;
        }
        if self.feature_enabled("phone-number.enabled") {
            if view.phone_number.is_none() {
                drop(
                    view.extension_fields
                        .insert("phoneNumber".into(), serde_json::Value::Null),
                );
            }
            if view.phone_number_verified.is_none() {
                drop(
                    view.extension_fields
                        .insert("phoneNumberVerified".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.phone_number = None;
            view.phone_number_verified = None;
        }
        if self.feature_enabled("last-login-method.enabled") {
            if view.last_login_method.is_none() {
                drop(
                    view.extension_fields
                        .insert("lastLoginMethod".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.last_login_method = None;
        }
        let registered = self.extensions.get::<crate::field_policy::UserFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.user.additional_fields, |fields| &fields.0.0);
        let physical = user.additional_fields();
        let values = user.adapter_output().unwrap_or(&physical);
        for (name, field) in fields {
            drop(view.extension_fields.remove(name));
            if (!public || field.returned)
                && let Some(value) = values.get(name).or_else(|| {
                    field
                        .field_name
                        .as_ref()
                        .and_then(|physical| values.get(physical))
                })
            {
                drop(view.extension_fields.insert(name.clone(), value.clone()));
            }
        }
        view
    }

    pub fn session_view(&self, session: &impl AuthSession) -> crate::wire::SessionView {
        self.project_session_view(session, true)
    }

    pub fn trusted_session_view(&self, session: &impl AuthSession) -> crate::wire::SessionView {
        self.project_session_view(session, false)
    }

    fn project_session_view(
        &self,
        session: &impl AuthSession,
        public: bool,
    ) -> crate::wire::SessionView {
        if let Some(view) = session.retained_session_view() {
            let mut view = view.clone();
            if public {
                let registered = self.extensions.get::<crate::field_policy::SessionFields>();
                let fields = registered
                    .as_ref()
                    .map_or(&self.config.session.additional_fields, |fields| &fields.0);
                for (name, field) in fields {
                    if !field.returned {
                        let _ignored_clone = view.omitted_fields.insert(name.clone());
                    }
                }
            }
            return view;
        }
        let mut view = crate::wire::SessionView::from(session);
        let registered = self.extensions.get::<crate::field_policy::SessionFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.session.additional_fields, |fields| &fields.0);
        view.extension_fields
            .retain(|name, _| fields.contains_key(name));
        if let Some(output) = session.adapter_output() {
            for name in fields.keys() {
                drop(view.extension_fields.remove(name));
                if let Some(value) = output.get(name) {
                    drop(view.extension_fields.insert(name.clone(), value.clone()));
                } else {
                    let _ignored_clone = view.omitted_fields.insert(name.clone());
                }
            }
        }
        for (name, field) in fields {
            if public && !field.returned {
                let _ignored_clone = view.omitted_fields.insert(name.clone());
            }
        }
        let declared = |name: &str| fields.contains_key(name);
        if self.feature_enabled("admin.enabled") || declared("impersonatedBy") {
            if view.impersonated_by.is_none() {
                drop(
                    view.extension_fields
                        .insert("impersonatedBy".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.impersonated_by = None;
        }
        if self.feature_enabled("organization.enabled") || declared("activeOrganizationId") {
            if view.active_organization_id.is_none() {
                drop(
                    view.extension_fields
                        .insert("activeOrganizationId".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.active_organization_id = None;
        }

        if self.feature_enabled("organization.teams.enabled") || declared("activeTeamId") {
            if view.active_team_id.is_none() {
                drop(
                    view.extension_fields
                        .insert("activeTeamId".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.active_team_id = None;
        }
        view
    }

    pub fn invitation_view(
        &self,
        invitation: &impl crate::entity::AuthInvitation,
    ) -> crate::wire::InvitationView {
        let mut view = crate::wire::InvitationView::from(invitation);
        if self.feature_enabled("organization.teams.enabled") {
            if view.team_id.is_none() {
                drop(
                    view.extension_fields
                        .insert("teamId".into(), serde_json::Value::Null),
                );
            }
        } else {
            view.team_id = None;
        }
        view
    }

    fn feature_enabled(&self, key: &str) -> bool {
        self.metadata
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// Get the email provider, returning an error if none is configured.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if no email provider is configured.
    pub fn email_provider(&self) -> AuthResult<&dyn EmailProvider> {
        self.email_provider
            .as_deref()
            .ok_or_else(|| AuthError::config("No email provider configured"))
    }

    /// Create a `SessionManager` from this context's config and database.
    #[must_use]
    pub fn session_manager(&self) -> SessionManager<S> {
        SessionManager::new(Arc::clone(&self.config), Arc::clone(&self.database))
    }

    /// Extract a session token from the request, validate the session, and
    /// return the authenticated `(User, Session)` pair.
    ///
    /// This centralises the pattern previously duplicated across many plugins
    /// (`get_authenticated_user`, `require_session`, etc.).
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a missing or invalid session, or propagates storage errors.
    pub async fn require_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(S::User, crate::wire::SessionView)> {
        let (user, session, _) = self.require_session_with_refresh_state(req).await?;
        Ok((user, session))
    }

    /// Read an ordinary HTTP session from the configured cache or storage.
    /// Sensitive stateful operations must continue using the physical APIs.
    /// Nested source get-session errors become an unauthenticated session;
    /// errors from later application/store operations are not caught here.
    /// # Errors
    /// Returns an error if the request has no valid session or session lookup fails.
    pub async fn require_cached_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(crate::AuthenticatedUser<S>, crate::wire::SessionView)> {
        let read = crate::cache::runtime::authenticated(self, req, false)
            .await
            .map_err(|_error| AuthError::Unauthenticated)?
            .ok_or(AuthError::Unauthenticated)?;
        Ok((read.user, read.session))
    }

    /// Authorize once and retain the optional deferred-refresh response field.
    /// Payload callbacks can observe the same context as nested session middleware
    /// without issuing another session read or refresh.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a missing or invalid session, or propagates storage errors.
    pub async fn require_session_with_refresh_state(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(S::User, crate::wire::SessionView, Option<bool>)> {
        self.authenticated_session(req, true).await
    }

    /// Authorize against the persisted signed-cookie session.
    /// This bypasses hook-provided virtual sessions while preserving normal
    /// refresh, browser preferences and deferred-read behavior.
    ///
    /// # Errors
    ///
    /// Returns an authentication error if no valid persisted session exists, or propagates storage errors.
    pub async fn require_authoritative_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(S::User, crate::wire::SessionView)> {
        crate::cache::runtime::clear_established_session::<S>(req);
        let (user, session, _) = self.authenticated_session(req, false).await?;
        Ok((user, session))
    }

    async fn authenticated_session(
        &self,
        req: &AuthRequest,
        allow_virtual: bool,
    ) -> AuthResult<(S::User, crate::wire::SessionView, Option<bool>)> {
        if allow_virtual && let Some(session) = req.virtual_session() {
            let user = self
                .database
                .get_user_by_id(&session.user_id)
                .await?
                .ok_or(AuthError::Unauthenticated)?;
            return Ok((user, session.clone(), None));
        }
        let session_manager = self.session_manager();

        let suppressed = session_manager.request_disables_refresh(req);
        let options = crate::session::SessionReadOptions {
            allow_refresh: !suppressed && !self.config.session.defer_session_refresh,
            cleanup_expired: !self.config.session.defer_session_refresh,
        };
        let Some(token) = session_manager.extract_session_token(req) else {
            return Err(AuthError::Unauthenticated);
        };
        let read = session_manager
            .read_session(&token, options)
            .await
            .map_err(|_error| AuthError::Unauthenticated)?;
        let Some(session) = read.session else {
            self.queue_session_cleanup(req);
            return Err(AuthError::Unauthenticated);
        };
        let Some(user) = self
            .database
            .get_user_by_id(&session.user_id())
            .await
            .map_err(|_error| AuthError::Unauthenticated)?
        else {
            self.queue_session_cleanup(req);
            return Err(AuthError::Unauthenticated);
        };
        if read.refreshed {
            req.queue_response_header(
                "Set-Cookie",
                crate::utils::cookie_utils::create_session_cookie(session.token(), &self.config),
            );
        }
        Ok((
            user,
            self.session_view(&session),
            (self.config.session.defer_session_refresh && !suppressed)
                .then_some(read.needs_refresh),
        ))
    }

    fn queue_session_cleanup(&self, req: &AuthRequest) {
        for cookie in crate::utils::cookie_utils::delete_session_cookie_headers(&self.config) {
            req.queue_response_header("Set-Cookie", cookie);
        }
    }

    /// Read the request's established session without extending its lifetime.
    /// Before hooks can establish a virtual session; otherwise a signed cookie
    /// must identify the persistent session.
    ///
    /// # Errors
    ///
    /// Propagates errors from session or user lookups.
    pub async fn session_without_refresh(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<Option<(S::User, crate::wire::SessionView)>> {
        if let Some(session) = req.virtual_session() {
            return Ok(self
                .database
                .get_user_by_id(&session.user_id)
                .await?
                .map(|user| (user, session.clone())));
        }
        self.persistent_session(req).await
    }

    /// Inspect a signed-cookie session without treating a missing login as an error.
    ///
    /// # Errors
    ///
    /// Propagates errors from session or user lookups.
    pub async fn persistent_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<Option<(S::User, crate::wire::SessionView)>> {
        let Some(token) = self.session_manager().extract_session_token(req) else {
            return Ok(None);
        };
        let Some(session) = self.database.get_session(&token).await? else {
            return Ok(None);
        };
        if !session.active() || session.expires_at() <= chrono::Utc::now() {
            return Ok(None);
        }
        let Some(user) = self
            .database
            .get_user_by_id(session.user_id().as_ref())
            .await?
        else {
            return Ok(None);
        };
        Ok(Some((user, self.session_view(&session))))
    }
}

impl std::fmt::Debug for ContextExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextExtensions").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuthInitParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInitParts").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> std::fmt::Debug for VerificationEmailOverrideHandle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationEmailOverrideHandle")
            .finish_non_exhaustive()
    }
}

impl<S: AuthSchema> std::fmt::Debug for AuthInitContext<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInitContext").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> std::fmt::Debug for AuthContext<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext").finish_non_exhaustive()
    }
}
