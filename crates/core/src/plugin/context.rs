use crate::plugin::MetadataMap;
use crate::session::SessionRequest;
use crate::wire::{InvitationView, SessionView, UserView};
use crate::{
    AdapterOutput, AdapterRecord, AuthAccount, AuthConfig, AuthError, AuthInvitation, AuthRequest,
    AuthResult, AuthSchema, AuthSession, AuthStore, AuthUser, AuthenticatedUser, ContextExtensions,
    EmailProvider, SessionManager, VerificationEmailOverrideHandle,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Context passed to plugin methods.
pub struct AuthContext<S: AuthSchema> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: MetadataMap,
    pub extensions: ContextExtensions,
}

fn insert_null(fields: &mut BTreeMap<String, serde_json::Value>, name: &str) {
    _ = fields.insert(name.to_owned(), serde_json::Value::Null);
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
        let context = crate::endpoint::current_endpoint_call_context().map_or_else(
            || {
                crate::hooks::current_request_hook_context()
                    .map(crate::utils::password::PasswordHashContext::from_request)
            },
            |call| {
                Some(crate::utils::password::PasswordHashContext {
                    path: call.path().map(str::to_owned),
                    request: call
                        .request()
                        .map(crate::hooks::RequestHookContext::from_request),
                })
            },
        );
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
        Self::with_metadata(config, database, MetadataMap::new())
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
        _ = self.metadata.insert(key.into(), value);
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

    pub fn user_view(&self, user: &impl AuthUser) -> UserView {
        self.project_user_view(user, true)
    }

    /// Project trusted adapter output without removing declared hidden fields.
    /// Canonical identity accessors still refer to the physical model.
    pub fn trusted_user_view(&self, user: &impl AuthUser) -> UserView {
        self.project_user_view(user, false)
    }

    pub(in crate::plugin) fn project_user_view(
        &self,
        user: &impl AuthUser,
        public: bool,
    ) -> UserView {
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
        let mut view = UserView::from(user);
        if self.feature_enabled("username.enabled") {
            for (key, absent) in [
                ("username", view.username.is_none()),
                ("displayUsername", view.display_username.is_none()),
            ] {
                if absent {
                    insert_null(&mut view.extension_fields, key);
                }
            }
        } else {
            view.username = None;
            view.display_username = None;
        }
        if self.feature_enabled("two_factor.enabled") {
            view.two_factor_enabled = user.two_factor_enabled_value();
            if view.two_factor_enabled.is_none() {
                insert_null(&mut view.extension_fields, "twoFactorEnabled");
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
                    insert_null(&mut view.extension_fields, key);
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
                insert_null(&mut view.extension_fields, "phoneNumber");
            }
            if view.phone_number_verified.is_none() {
                insert_null(&mut view.extension_fields, "phoneNumberVerified");
            }
        } else {
            view.phone_number = None;
            view.phone_number_verified = None;
        }
        if self.feature_enabled("last-login-method.enabled") {
            if view.last_login_method.is_none() {
                insert_null(&mut view.extension_fields, "lastLoginMethod");
            }
        } else {
            view.last_login_method = None;
        }
        let registered = self.extensions.get::<crate::field_policy::UserFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.user.additional_fields, |fields| &fields.0.0);
        let physical = user.additional_fields();
        let values = user
            .adapter_snapshot()
            .map_or(&physical, AdapterOutput::values);
        for (name, field) in fields {
            _ = view.extension_fields.remove(name);
            if (!public || field.returned)
                && let Some(value) = values.get(name).or_else(|| {
                    field
                        .field_name
                        .as_ref()
                        .and_then(|physical| values.get(physical))
                })
            {
                _ = view.extension_fields.insert(name.clone(), value.clone());
            }
        }
        if let Some(snapshot) = user.adapter_snapshot() {
            // An ephemeral adapter can omit a property rather than persist SQL
            // NULL. Output snapshots retain that distinction through caching.
            for name in [
                "id",
                "name",
                "email",
                "emailVerified",
                "image",
                "createdAt",
                "updatedAt",
                "username",
                "displayUsername",
                "twoFactorEnabled",
                "role",
                "banned",
                "banReason",
                "banExpires",
                "isAnonymous",
                "phoneNumber",
                "phoneNumberVerified",
                "lastLoginMethod",
            ] {
                if !snapshot.contains_field(name) || snapshot.field_is_undefined(name) {
                    _ = view.omitted_fields.insert(name.into());
                }
            }
        }
        if self.config.session.stateless {
            for (name, absent) in [
                ("image", view.image.is_none()),
                ("username", view.username.is_none()),
                ("displayUsername", view.display_username.is_none()),
                ("banReason", view.ban_reason.is_none()),
                ("banExpires", view.ban_expires.is_none()),
            ] {
                if absent
                    && view
                        .extension_fields
                        .get(name)
                        .is_none_or(serde_json::Value::is_null)
                {
                    _ = view.omitted_fields.insert(name.into());
                }
            }
        }
        view
    }

    /// Retain configured output for an already authenticated physical user.
    pub(crate) async fn user_adapter_record(
        &self,
        user: S::User,
    ) -> AuthResult<AdapterRecord<S::User>> {
        use crate::AuthUser;
        let registered = self
            .extensions
            .get::<crate::field_policy::AdapterFieldPolicies>();
        let fields = registered.as_ref().map_or_else(
            || {
                crate::field_policy::SessionAdapterFields(Arc::new(
                    self.config.user.additional_fields.clone(),
                ))
            },
            |fields| fields.user.clone(),
        );
        let output = fields
            .record_output(
                serde_json::to_value(
                    user.retained_user_view()
                        .cloned()
                        .unwrap_or_else(|| UserView::from(&user)),
                )?,
                user.additional_fields(),
                serde_json::to_value(self.trusted_user_view(&user))?,
            )
            .await?;
        Ok(AdapterRecord::with_output(user, output))
    }

    /// Preserve the initialized adapter result's physical authority and declared
    /// undefined presence while applying the public user field policy once.
    #[must_use]
    pub fn filter_user_record(&self, record: AdapterRecord<S::User>) -> AdapterRecord<S::User> {
        let registered = self.extensions.get::<crate::field_policy::UserFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.user.additional_fields, |fields| &fields.0.0);
        let output = record.raw_snapshot().filter_returned(fields);
        AdapterRecord::with_output(record.into_stored(), output)
    }

    /// Public account output retains declared adapter projections and always
    /// removes credentials, including explicitly returned additional fields.
    ///
    /// # Errors
    /// Returns an error when the canonical account view cannot be serialized.
    pub fn account_view(
        &self,
        account: &impl AuthAccount,
    ) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
        let serde_json::Value::Object(mut view) =
            serde_json::to_value(crate::wire::AccountView::from(account))?
        else {
            return Err(AuthError::internal("Account view must be an object"));
        };
        let registered = self.extensions.get::<crate::field_policy::AccountFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.account.additional_fields, |fields| &fields.0.0);
        let physical = account.additional_fields();
        let values = account
            .adapter_snapshot()
            .map_or(&physical, AdapterOutput::values);
        for (name, field) in fields {
            _ = view.remove(name);
            if field.returned
                && let Some(value) = values.get(name).or_else(|| {
                    field
                        .field_name
                        .as_ref()
                        .and_then(|physical| values.get(physical))
                })
            {
                _ = view.insert(name.clone(), value.clone());
            }
        }
        for credential in [
            "accessToken",
            "refreshToken",
            "idToken",
            "accessTokenExpiresAt",
            "refreshTokenExpiresAt",
            "password",
        ] {
            _ = view.remove(credential);
        }
        Ok(view)
    }

    pub fn session_view(&self, session: &impl AuthSession) -> SessionView {
        self.project_session_view(session, true)
    }

    pub fn trusted_session_view(&self, session: &impl AuthSession) -> SessionView {
        self.project_session_view(session, false)
    }

    pub(in crate::plugin) fn project_session_view(
        &self,
        session: &impl AuthSession,
        public: bool,
    ) -> SessionView {
        if let Some(view) = session.retained_session_view() {
            let mut view = view.clone();
            if public {
                let registered = self.extensions.get::<crate::field_policy::SessionFields>();
                let fields = registered
                    .as_ref()
                    .map_or(&self.config.session.additional_fields, |fields| &fields.0);
                for (name, field) in fields {
                    if !field.returned {
                        _ = view.omitted_fields.insert(name.clone());
                    }
                }
            }
            return view;
        }
        let mut view = SessionView::from(session);
        let registered = self.extensions.get::<crate::field_policy::SessionFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.session.additional_fields, |fields| &fields.0);
        view.extension_fields
            .retain(|name, _| fields.contains_key(name));
        if let Some(output) = session.adapter_snapshot().map(AdapterOutput::values) {
            for name in fields.keys() {
                _ = view.extension_fields.remove(name);
                if let Some(value) = output.get(name) {
                    _ = view.extension_fields.insert(name.clone(), value.clone());
                } else {
                    _ = view.omitted_fields.insert(name.clone());
                }
            }
        }
        for (name, field) in fields {
            if public && !field.returned {
                _ = view.omitted_fields.insert(name.clone());
            }
        }
        let declared = |name: &str| fields.contains_key(name);
        if self.feature_enabled("admin.enabled") || declared("impersonatedBy") {
            if view.impersonated_by.is_none() {
                insert_null(&mut view.extension_fields, "impersonatedBy");
            }
        } else {
            view.impersonated_by = None;
        }
        if self.feature_enabled("organization.enabled") || declared("activeOrganizationId") {
            if view.active_organization_id.is_none() {
                insert_null(&mut view.extension_fields, "activeOrganizationId");
            }
        } else {
            view.active_organization_id = None;
        }

        if self.feature_enabled("organization.teams.enabled") || declared("activeTeamId") {
            if view.active_team_id.is_none() {
                insert_null(&mut view.extension_fields, "activeTeamId");
            }
        } else {
            view.active_team_id = None;
        }
        if self.config.session.stateless {
            for (name, absent) in [
                (
                    "activeOrganizationId",
                    view.active_organization_id.is_none(),
                ),
                ("impersonatedBy", view.impersonated_by.is_none()),
            ] {
                if absent
                    && view
                        .extension_fields
                        .get(name)
                        .is_none_or(serde_json::Value::is_null)
                {
                    _ = view.omitted_fields.insert(name.into());
                }
            }
        }
        view
    }

    pub fn invitation_view(&self, invitation: &impl AuthInvitation) -> InvitationView {
        let mut view = InvitationView::from(invitation);
        if self.feature_enabled("organization.teams.enabled") {
            if view.team_id.is_none() {
                insert_null(&mut view.extension_fields, "teamId");
            }
        } else {
            view.team_id = None;
        }
        view
    }

    pub(in crate::plugin) fn feature_enabled(&self, key: &str) -> bool {
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
        req: &impl SessionRequest,
    ) -> AuthResult<(S::User, SessionView)> {
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
        req: &impl SessionRequest,
    ) -> AuthResult<(AuthenticatedUser<S>, SessionView)> {
        let read = crate::session::cookie_cache::runtime::authenticated(self, req, false)
            .await
            .map_err(|_| AuthError::Unauthenticated)?
            .ok_or(AuthError::Unauthenticated)?;
        Ok((read.user, read.session))
    }

    /// Read an ordinary HTTP session from the configured cache or storage for
    /// an application route. Unlike [`Self::require_cached_session`], which
    /// mirrors upstream's nested get-session and answers every failure with
    /// `Unauthenticated`, only a missing or invalid session (including a
    /// malformed cache cookie) is `Unauthenticated` here.
    /// # Errors
    /// Returns `Unauthenticated` without a valid session, and propagates
    /// storage and callback errors.
    pub async fn require_cached_session_strict(
        &self,
        req: &impl SessionRequest,
    ) -> AuthResult<(AuthenticatedUser<S>, SessionView)> {
        let read = crate::session::cookie_cache::runtime::authenticated_with(
            self,
            req,
            false,
            crate::session::cookie_cache::runtime::CacheDecoding::MalformedIsMiss,
        )
        .await
        .map_err(|error| {
            if error.status_code() == 401 {
                AuthError::Unauthenticated
            } else {
                error
            }
        })?
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
        req: &impl SessionRequest,
    ) -> AuthResult<(S::User, SessionView, Option<bool>)> {
        self.authenticated_session(req, true).await
    }

    /// Authoritative session authority without reconstructing an application
    /// model from a cookie. Stateless deployments authorize the authenticated
    /// cache snapshot; stateful deployments always bypass it.
    pub async fn require_authoritative_cached_session(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(AuthenticatedUser<S>, SessionView)> {
        self.require_cached_session(&self.physical_request(req))
            .await
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
        req: &impl SessionRequest,
    ) -> AuthResult<(S::User, SessionView)> {
        crate::session::cookie_cache::runtime::clear_established_session::<S>(req);
        let (user, session, _) = self.authenticated_session(req, false).await?;
        Ok((user, session))
    }

    /// Resolve physical signed-cookie authority while retaining the actual
    /// initialized adapter output for downstream public and callback projections.
    ///
    /// # Errors
    /// Propagates authentication, storage and output callback failures.
    pub async fn require_authoritative_session_record(
        &self,
        req: &AuthRequest,
    ) -> AuthResult<(AdapterRecord<S::User>, SessionView)> {
        let physical = self.physical_request(req);
        let read = crate::session::cookie_cache::runtime::authenticated(self, &physical, false)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        match read.user {
            AuthenticatedUser::Stored(user) => Ok((user, read.session)),
            AuthenticatedUser::Cached(user) if self.config.session.stateless => {
                let user = S::user_from_cookie_cache(*user).ok_or_else(|| {
                    AuthError::config("This schema requires cache-aware session authority")
                })?;
                Ok((AdapterRecord::physical(user)?, read.session))
            }
            AuthenticatedUser::Cached(_) => Err(AuthError::Unauthenticated),
        }
    }

    /// Resolve the actual owner snapshot belonging to a stored session credential.
    /// Secondary-backed sessions retain their cached user; combined fallback uses SQL.
    ///
    /// # Errors
    /// Propagates backend failures and rejects mismatched cached ownership.
    pub async fn session_user(&self, session: &impl AuthSession) -> AuthResult<Option<S::User>> {
        use crate::AuthUser;
        if let Some(user) = self.database.get_session_user(session.token()).await? {
            if user.id() != session.user_id() {
                return Err(AuthError::Unauthenticated);
            }
            return Ok(Some(user));
        }
        if self.config.session.secondary_storage.is_some()
            && (!self.config.session.store_in_database || self.config.session.preserve_in_database)
        {
            return Ok(None);
        }
        self.database
            .get_user_by_id(session.user_id().as_ref())
            .await
    }

    /// A copy of `req` that ignores hook-provided virtual sessions and, with a
    /// server session store, the cookie cache.
    fn physical_request(&self, req: &AuthRequest) -> AuthRequest {
        crate::session::cookie_cache::runtime::clear_established_session::<S>(req);
        let mut physical = req.clone();
        physical.virtual_session = None;
        if self.config.session.has_server_session_store() {
            _ = physical
                .query
                .insert("disableCookieCache".into(), "true".into());
        }
        physical
    }

    pub(in crate::plugin) async fn authenticated_session(
        &self,
        req: &impl SessionRequest,
        allow_virtual: bool,
    ) -> AuthResult<(S::User, SessionView, Option<bool>)> {
        if allow_virtual && let Some(session) = req.virtual_session(self) {
            let user = if let Some(user) = req.authenticated_user::<S>(self) {
                user
            } else {
                self.database
                    .get_user_by_id(&session.user_id)
                    .await?
                    .ok_or(AuthError::Unauthenticated)?
            };
            return Ok((user, session.clone(), None));
        }
        if self.config.session.stateless
            && let Some(cache) = crate::session::cookie_cache::runtime::read(self, req).await?
        {
            crate::session::cookie_cache::runtime::renew_cache(self, req, &cache).await?;
            let user = S::user_from_cookie_cache(cache.user).ok_or_else(|| {
                AuthError::config("This schema requires cache-aware session authority")
            })?;
            return Ok((user, cache.session, None));
        }
        let session_manager = self.session_manager();

        let suppressed = session_manager.request_disables_refresh(req);
        let skip = req
            .extensions()
            .get::<crate::session::SessionRefreshSuppressed>()
            .is_some();
        let options = crate::session::SessionReadOptions {
            allow_refresh: !suppressed && !self.config.session.defer_session_refresh && !skip,
            cleanup_expired: !self.config.session.defer_session_refresh,
        };
        let Some(token) = session_manager.extract_session_token(req) else {
            return Err(AuthError::Unauthenticated);
        };
        let read = session_manager
            .read_session(&token, options)
            .await
            .map_err(|_| AuthError::Unauthenticated)?;
        let Some(session) = read.session else {
            self.queue_session_cleanup(req)?;
            return Err(AuthError::Unauthenticated);
        };
        let user = self
            .session_user(&session)
            .await
            .map_err(|_| AuthError::Unauthenticated)?;
        let Some(user) = user else {
            self.queue_session_cleanup(req)?;
            return Err(AuthError::Unauthenticated);
        };
        if read.refreshed {
            req.queue_response_header(
                "Set-Cookie",
                crate::utils::cookie_utils::create_session_cookie(session.token(), &self.config)?,
            );
        }
        Ok((
            user,
            self.session_view(&session),
            (self.config.session.defer_session_refresh && !suppressed)
                .then_some(read.needs_refresh && !skip),
        ))
    }

    pub(in crate::plugin) fn queue_session_cleanup(
        &self,
        req: &impl SessionRequest,
    ) -> AuthResult<()> {
        for cookie in crate::utils::cookie_utils::delete_session_cookie_headers(&self.config)? {
            req.queue_response_header("Set-Cookie", cookie);
        }
        Ok(())
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
        req: &impl SessionRequest,
    ) -> AuthResult<Option<(S::User, SessionView)>> {
        if let Some(session) = req.virtual_session(self) {
            if let Some(user) = req.authenticated_user::<S>(self) {
                return Ok(Some((user, session)));
            }
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
        req: &impl SessionRequest,
    ) -> AuthResult<Option<(S::User, SessionView)>> {
        if self.config.session.stateless
            && let Some(cache) = crate::session::cookie_cache::runtime::read(self, req).await?
        {
            let user = S::user_from_cookie_cache(cache.user).ok_or_else(|| {
                AuthError::config("This schema requires cache-aware session authority")
            })?;
            return Ok(Some((user, cache.session)));
        }
        let Some(token) = self.session_manager().extract_session_token(req) else {
            return Ok(None);
        };
        let Some(session) = self.database.get_session(&token).await? else {
            return Ok(None);
        };
        if !session.active() || session.expires_at() <= chrono::Utc::now() {
            return Ok(None);
        }
        let user = self.session_user(&session).await?;
        let Some(user) = user else {
            return Ok(None);
        };
        Ok(Some((user, self.session_view(&session))))
    }
}

impl<S: AuthSchema> std::fmt::Debug for AuthContext<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext").finish_non_exhaustive()
    }
}
