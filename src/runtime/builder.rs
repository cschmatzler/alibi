use super::{
    Arc, AuthBuilder, AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthResult,
    AuthSchema, AuthStore, BetterAuth, BodyLimitMiddleware, CorsConfig, CorsMiddleware,
    CsrfMiddleware, EmailProvider, Middleware, OpenApiRegistry, RateLimitConfig,
    RateLimitMiddleware, SessionManager,
};
impl<S: AuthSchema> AuthBuilder<S> {
    /// Create an instance builder with the core API installed at build time.
    /// Email/password and username authentication remain disabled until an
    /// explicit email/password plugin enables them. Explicit core plugins keep
    /// their configuration; custom plugins keep their dispatch priority.
    #[must_use]
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            telemetry: crate::telemetry::TelemetryConfig::default(),
            store: None,
            has_external_store: false,
            plugins: Vec::new(),
            csrf_config: None,
            rate_limit_config: None,
            cors_config: None,
            body_limit_config: None,
            custom_middlewares: Vec::new(),
            endpoint_hooks: Vec::new(),
        }
    }

    /// Set the shared auth store implementation.
    #[must_use]
    pub fn store<T>(mut self, store: T) -> Self
    where
        T: AuthStore<S> + 'static,
    {
        self.store = Some(Arc::new(store));
        self.has_external_store = true;
        self
    }

    /// Set the shared auth store implementation using an existing [`Arc`].
    #[must_use]
    pub fn store_arc(mut self, store: Arc<dyn AuthStore<S>>) -> Self {
        self.store = Some(store);
        self.has_external_store = true;
        self
    }

    /// Add a plugin to the authentication system.
    #[must_use]
    pub fn plugin<P: AuthPlugin<S> + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Register configured application hooks before installed plugin endpoint hooks.
    #[must_use]
    pub fn endpoint_hook<H: alibi_core::endpoint::EndpointHook<S> + 'static>(
        mut self,
        hook: H,
    ) -> Self {
        self.endpoint_hooks.push(Arc::new(hook));
        self
    }

    /// Configure rate limiting.
    #[must_use]
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Configure CORS.
    #[must_use]
    pub fn cors(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Set the email provider.
    #[must_use]
    pub fn email_provider<E: EmailProvider + 'static>(mut self, provider: E) -> Self {
        self.config.email_provider = Some(Arc::new(provider));
        self
    }

    /// Add a custom middleware.
    #[must_use]
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.custom_middlewares.push(Box::new(mw));
        self
    }

    /// Build the `BetterAuth` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation or plugin initialization fails.
    pub async fn build(mut self) -> AuthResult<BetterAuth<S>> {
        self.resolve_oauth_state_strategy();
        self.config.validate()?;
        self.resolve_trusted_providers().await?;
        normalize_session_cookie_name(&mut self.config);
        self.install_core_plugins();

        let config = Arc::new(self.config);
        let store = self
            .store
            .ok_or_else(|| AuthError::config("Auth store not configured"))?;

        let mut init_context = AuthInitContext::new(Arc::clone(&config), Arc::clone(&store));
        for plugin in &self.plugins {
            plugin.on_init(&mut init_context).await?;
        }
        register_field_policies(&mut init_context, &config, &self.plugins);
        register_openapi(&mut init_context, &config, &self.plugins);
        let openapi = init_context
            .extensions
            .get::<OpenApiRegistry>()
            .ok_or_else(|| AuthError::internal("OpenAPI registry initialization failed"))?;

        let store = init_context.database_with_registered_transforms();
        let init_parts = init_context.into_parts();
        let session_manager = SessionManager::new(Arc::clone(&config), Arc::clone(&store));
        let mut context = AuthContext::with_metadata(
            Arc::clone(&config),
            Arc::clone(&store),
            init_parts.metadata,
        )
        .with_extensions(init_parts.extensions);
        context.email_provider = init_parts.email_provider;

        let body_limit = self.body_limit_config.unwrap_or_default();
        let request_protection =
            CsrfMiddleware::new(self.csrf_config.unwrap_or_default(), Arc::clone(&config));
        // Transport and application request middleware precede router resolution.
        let transport_middlewares: Vec<Box<dyn Middleware>> = vec![
            Box::new(BodyLimitMiddleware::new(body_limit.clone())),
            Box::new(
                RateLimitMiddleware::new(self.rate_limit_config.unwrap_or_default())
                    .with_base_path(config.base_path.clone())
                    .with_plugin_rules(
                        self.plugins
                            .iter()
                            .flat_map(|plugin| plugin.rate_limits())
                            .collect(),
                    ),
            ),
        ];
        let cors = CorsMiddleware::new(self.cors_config.unwrap_or_default());

        if self.telemetry.is_enabled() {
            self.telemetry
                .publish(crate::telemetry::TelemetryEvent::new(
                    "init",
                    serde_json::json!({
                        "libraryVersion": env!("CARGO_PKG_VERSION"),
                        "runtime": "rust",
                        "platform": std::env::consts::OS,
                        "architecture": std::env::consts::ARCH,
                        "plugins": self.plugins.iter().map(|plugin| plugin.name()).collect::<Vec<_>>(),
                    }),
                ))
                .await;
        }

        Ok(BetterAuth {
            telemetry: self.telemetry,
            config,
            plugins: self.plugins,
            transport_middlewares,
            middlewares: self.custom_middlewares,
            cors,
            request_protection,
            body_limit,
            store,
            session_manager,
            context,
            openapi,
            endpoint_hooks: self.endpoint_hooks,
        })
    }

    /// Resolve the published deployment default once, before exposing config
    /// to any plugin. A SQL user store is still a server store even when the
    /// session policy suppresses durable session rows.
    fn resolve_oauth_state_strategy(&mut self) {
        if self.config.account.store_state_strategy == alibi_core::OAuthStateStrategy::Automatic {
            self.config.account.store_state_strategy =
                if self.has_external_store || self.config.session.secondary_storage.is_some() {
                    alibi_core::OAuthStateStrategy::Database
                } else {
                    alibi_core::OAuthStateStrategy::Cookie
                };
        }
    }

    async fn resolve_trusted_providers(&mut self) -> AuthResult<()> {
        let linking = &mut self.config.account.account_linking;
        if let Some(resolver) = &linking.trusted_providers_resolver {
            linking.trusted_providers = resolver
                .resolve(None)
                .await?
                .into_iter()
                .filter(|provider| !provider.is_empty())
                .collect();
        }
        Ok(())
    }

    /// Core modules exist on every instance. Explicit modules keep their own
    /// configuration and priority; defaults never enable credential login.
    fn install_core_plugins(&mut self) {
        let defaults: Vec<Box<dyn AuthPlugin<S>>> = vec![
            Box::new(alibi_plugins::SessionManagementPlugin::new()),
            Box::new(
                alibi_plugins::EmailPasswordPlugin::new()
                    .enabled(false)
                    .enable_username(false),
            ),
            Box::new(alibi_plugins::PasswordManagementPlugin::new()),
            Box::new(alibi_plugins::EmailVerificationPlugin::new()),
            Box::new(alibi_plugins::AccountManagementPlugin::new()),
            Box::new(alibi_plugins::OAuthPlugin::new()),
            Box::new(alibi_plugins::UserManagementPlugin::new()),
        ];
        for plugin in defaults {
            if !self
                .plugins
                .iter()
                .any(|installed| installed.name() == plugin.name())
            {
                self.plugins.push(plugin);
            }
        }
    }
}

/// Authentication and every producer use the same initialized token name;
/// related-cookie overrides remain independently configured. The unprefixed
/// legacy name is retained before storing the resolved name, which keeps name
/// resolution stable across producers and request clones. The secure prefix
/// follows the cookie policy, so a configured one is dropped rather than
/// applied twice.
fn normalize_session_cookie_name(config: &mut AuthConfig) {
    if let Some(name) = config.session.cookie_name.strip_prefix("__Secure-") {
        config.session.cookie_name = name.to_owned();
    }
    if config
        .advanced
        .cookie_prefix
        .as_ref()
        .is_none_or(String::is_empty)
    {
        if !config.advanced.cookies.contains_key("session_token")
            && let Some(prefix) = config.session.cookie_name.strip_suffix(".session_token")
            && prefix != "better-auth"
        {
            config.advanced.cookie_prefix = Some(prefix.to_owned());
        }
        let entry = config
            .advanced
            .cookies
            .entry("session_token".into())
            .or_default();
        if entry.name.as_ref().is_none_or(String::is_empty) {
            entry.name = Some(config.session.cookie_name.clone());
        }
    }
    config.session.cookie_name =
        alibi_core::utils::cookie_utils::related_cookie_name(config, "session_token");
}

/// Merge plugin-declared session, user and account fields with the configured
/// ones, for both request parsing and adapter output.
fn register_field_policies<S: AuthSchema>(
    init_context: &mut AuthInitContext<S>,
    config: &AuthConfig,
    plugins: &[Box<dyn AuthPlugin<S>>],
) {
    use alibi_core::field_policy::{
        AccountFields, AdapterFieldPolicies, FieldConfigs, SessionAdapterFields, SessionFields,
        UserFields,
    };

    let mut session_fields = SessionFields(config.session.additional_fields.clone());
    let mut session_adapter = FieldConfigs::new();
    let mut user_fields = SessionFields(config.user.additional_fields.clone());
    let mut user_adapter = FieldConfigs::new();
    let mut account_fields = SessionFields(config.account.additional_fields.clone());
    let mut account_adapter = FieldConfigs::new();
    for plugin in plugins {
        let fields = plugin.session_fields();
        session_adapter.extend(fields.clone());
        session_fields.0.extend(fields);
    }
    session_adapter.extend(config.session.additional_fields.clone());
    init_context
        .extensions
        .insert(SessionAdapterFields(Arc::new(session_adapter)));
    init_context.extensions.insert(session_fields);
    for plugin in plugins {
        let fields = plugin.user_fields();
        user_adapter.extend(fields.clone());
        user_fields.0.extend(fields);
        let fields = plugin.account_fields();
        account_adapter.extend(fields.clone());
        account_fields.0.extend(fields);
    }
    user_adapter.extend(config.user.additional_fields.clone());
    account_adapter.extend(config.account.additional_fields.clone());
    init_context.extensions.insert(UserFields(user_fields));
    init_context
        .extensions
        .insert(AccountFields(account_fields));
    init_context.extensions.insert(AdapterFieldPolicies {
        user: SessionAdapterFields(Arc::new(user_adapter)),
        account: SessionAdapterFields(Arc::new(account_adapter)),
    });
}

fn register_openapi<S: AuthSchema>(
    init_context: &mut AuthInitContext<S>,
    config: &AuthConfig,
    plugins: &[Box<dyn AuthPlugin<S>>],
) {
    let mut openapi = OpenApiRegistry::configured(S::openapi_models(), config);
    let core_routes = alibi_plugins::metadata::core_routes();
    let core_metadata = alibi_plugins::metadata::plugin_metadata("core", &core_routes);
    openapi.register("core", core_routes, core_metadata);
    for plugin in plugins {
        openapi.register(
            plugin.name(),
            plugin.routes(),
            plugin.openapi_metadata(init_context),
        );
        openapi.register_fields("User", &plugin.user_fields());
        openapi.register_fields("Session", &plugin.session_fields());
        openapi.register_fields("Account", &plugin.account_fields());
    }
    init_context.extensions.insert(openapi);
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Create a new `BetterAuth` builder.
    #[expect(
        clippy::new_ret_no_self,
        reason = "returns AuthBuilder by design — builder pattern entry point"
    )]
    #[must_use]
    pub fn new(config: AuthConfig) -> AuthBuilder<S> {
        AuthBuilder::new(config)
    }

    /// Get the shared auth store used by Better Auth.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn AuthStore<S>> {
        &self.store
    }
}

impl AuthBuilder<crate::store::StatelessSchema> {
    /// Build with ephemeral user/account provisioning and cookie-only sessions.
    /// User credentials are local to this instance and lost on restart. Session
    /// cookies remain independently valid until expiry/version/key invalidation.
    #[must_use]
    pub fn without_database(mut config: AuthConfig) -> Self {
        config.session = config.session.stateless();
        config.account.store_account_cookie = true;
        let store = crate::store::StatelessStore::with_find_many_limit(
            config.advanced.database.default_find_many_limit,
        );
        let mut builder = Self::new(config).store(store);
        builder.has_external_store = false;
        builder
    }
}
