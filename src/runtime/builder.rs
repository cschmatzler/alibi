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
        // Resolve the published deployment default once, before exposing config
        // to any plugin. A SQL user store is still a server store even when the
        // session policy suppresses durable session rows.
        if self.config.account.store_state_strategy == alibi_core::OAuthStateStrategy::Automatic {
            self.config.account.store_state_strategy =
                if self.has_external_store || self.config.session.secondary_storage.is_some() {
                    alibi_core::OAuthStateStrategy::Database
                } else {
                    alibi_core::OAuthStateStrategy::Cookie
                };
        }
        // Validate configuration
        self.config.validate()?;
        if let Some(resolver) = &self
            .config
            .account
            .account_linking
            .trusted_providers_resolver
        {
            self.config.account.account_linking.trusted_providers = resolver
                .resolve(None)
                .await?
                .into_iter()
                .filter(|provider| !provider.is_empty())
                .collect();
        }

        // Authentication and every producer use the same initialized token
        // name; related-cookie overrides remain independently configured.
        // Retain the unprefixed legacy name before storing the resolved name.
        // This keeps name resolution stable across producers and request clones.
        // The secure prefix follows the cookie policy, so a configured one is
        // dropped rather than applied twice.
        if let Some(name) = self.config.session.cookie_name.strip_prefix("__Secure-") {
            self.config.session.cookie_name = name.to_owned();
        }
        if self
            .config
            .advanced
            .cookie_prefix
            .as_ref()
            .is_none_or(|p| p.is_empty())
        {
            if !self.config.advanced.cookies.contains_key("session_token")
                && let Some(prefix) = self
                    .config
                    .session
                    .cookie_name
                    .strip_suffix(".session_token")
                && prefix != "better-auth"
            {
                self.config.advanced.cookie_prefix = Some(prefix.to_owned());
            }
            let entry = self
                .config
                .advanced
                .cookies
                .entry("session_token".into())
                .or_default();
            if entry
                .name
                .as_ref()
                .is_none_or(std::string::String::is_empty)
            {
                entry.name = Some(self.config.session.cookie_name.clone());
            }
        }
        self.config.session.cookie_name =
            alibi_core::utils::cookie_utils::related_cookie_name(&self.config, "session_token");

        // Core modules exist on every instance. Explicit modules keep their own
        // configuration and priority; defaults never enable credential login.
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

        let config = Arc::new(self.config);
        let store = self
            .store
            .ok_or_else(|| AuthError::config("Auth store not configured"))?;

        let mut init_context = AuthInitContext::new(Arc::clone(&config), Arc::clone(&store));

        // Initialize all plugins.
        for plugin in &self.plugins {
            plugin.on_init(&mut init_context).await?;
        }

        let mut session_fields =
            alibi_core::field_policy::SessionFields(config.session.additional_fields.clone());
        let mut adapter_fields = alibi_core::field_policy::FieldConfigs::new();
        for plugin in &self.plugins {
            let fields = plugin.session_fields();
            adapter_fields.extend(fields.clone());
            session_fields.0.extend(fields);
        }
        adapter_fields.extend(config.session.additional_fields.clone());
        init_context
            .extensions
            .insert(alibi_core::field_policy::SessionAdapterFields(Arc::new(
                adapter_fields,
            )));
        init_context.extensions.insert(session_fields);
        let mut user_fields =
            alibi_core::field_policy::SessionFields(config.user.additional_fields.clone());
        let mut account_fields =
            alibi_core::field_policy::SessionFields(config.account.additional_fields.clone());
        let mut user_adapter = alibi_core::field_policy::FieldConfigs::new();
        let mut account_adapter = alibi_core::field_policy::FieldConfigs::new();
        for plugin in &self.plugins {
            let fields = plugin.user_fields();
            user_adapter.extend(fields.clone());
            user_fields.0.extend(fields);
            let fields = plugin.account_fields();
            account_adapter.extend(fields.clone());
            account_fields.0.extend(fields);
        }
        user_adapter.extend(config.user.additional_fields.clone());
        account_adapter.extend(config.account.additional_fields.clone());
        init_context
            .extensions
            .insert(alibi_core::field_policy::UserFields(user_fields));
        init_context
            .extensions
            .insert(alibi_core::field_policy::AccountFields(account_fields));
        init_context
            .extensions
            .insert(alibi_core::field_policy::AdapterFieldPolicies {
                user: alibi_core::field_policy::SessionAdapterFields(Arc::new(user_adapter)),
                account: alibi_core::field_policy::SessionAdapterFields(Arc::new(account_adapter)),
            });
        let mut openapi = OpenApiRegistry::configured(S::openapi_models(), &config);
        let core_routes = alibi_plugins::metadata::core_routes();
        let core_metadata = alibi_plugins::metadata::plugin_metadata("core", &core_routes);
        openapi.register("core", core_routes, core_metadata);
        for plugin in &self.plugins {
            openapi.register(
                plugin.name(),
                plugin.routes(),
                plugin.openapi_metadata(&init_context),
            );
            openapi.register_fields("User", &plugin.user_fields());
            openapi.register_fields("Session", &plugin.session_fields());
            openapi.register_fields("Account", &plugin.account_fields());
        }
        init_context.extensions.insert(openapi);
        let openapi_2 = init_context
            .extensions
            .get::<OpenApiRegistry>()
            .ok_or_else(|| AuthError::internal("OpenAPI registry initialization failed"))?;

        let store_2 = init_context.database_with_registered_transforms();
        let init_parts = init_context.into_parts();

        // Create session manager
        let session_manager = SessionManager::new(Arc::clone(&config), Arc::clone(&store_2));

        // Create context
        let mut context = AuthContext::with_metadata(
            Arc::clone(&config),
            Arc::clone(&store_2),
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
        let middlewares = self.custom_middlewares;

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
            middlewares,
            cors,
            request_protection,
            body_limit,
            store: store_2,
            session_manager,
            context,
            openapi: openapi_2,
            endpoint_hooks: self.endpoint_hooks,
        })
    }
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
