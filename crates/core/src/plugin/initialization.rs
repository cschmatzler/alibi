use crate::plugin::MetadataMap;
use crate::{
    AuthConfig, AuthContext, AuthResult, AuthSchema, AuthStore, ContextExtensions, EmailProvider,
    VerificationEmailOverride, VerificationEmailOverrideHandle,
};
use std::sync::Arc;
pub struct AuthInitParts {
    pub metadata: MetadataMap,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub extensions: ContextExtensions,
}

/// Initialization context passed to plugin setup.
pub struct AuthInitContext<S: AuthSchema> {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn AuthStore<S>>,
    pub email_provider: Option<Arc<dyn EmailProvider>>,
    pub metadata: MetadataMap,
    pub extensions: ContextExtensions,
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
        _ = self.metadata.insert(key.into(), value);
    }

    /// Decorate the instance's actual password hashing boundary. Later
    /// registrations run first, matching initialized hash wrappers.
    pub fn register_password_hash_hook(
        &mut self,
        hook: Arc<dyn crate::utils::password::PasswordHashHook>,
    ) {
        let mut hooks = self
            .extensions
            .cloned_or_default::<crate::utils::password::PasswordHashHooks>();
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
            .cloned_or_default::<crate::store::UserTransforms>();
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
            .cloned_or_default::<crate::store::UserTransforms>();
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
            .cloned_or_default::<crate::store::UserTransforms>();
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
            .cloned_or_default::<crate::store::SessionCreatedCallbacks<S>>();
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
            .cloned_or_default::<crate::store::AdapterCallbacks<S>>();
        callbacks.0.push(callback);
        self.extensions.insert(callbacks);
    }

    /// Finalize the instance's store without mutating a shared underlying adapter.
    #[must_use]
    pub fn database_with_registered_transforms(&self) -> Arc<dyn AuthStore<S>> {
        let transforms = self
            .extensions
            .cloned_or_default::<crate::store::UserTransforms>();
        let session_callbacks = self
            .extensions
            .cloned_or_default::<crate::store::SessionCreatedCallbacks<S>>();
        let fields = self.extensions.get::<crate::field_policy::SessionFields>();
        if self.config.session.secondary_storage.is_none()
            && transforms.creates.is_empty()
            && transforms.updates.is_empty()
            && session_callbacks.callbacks.is_empty()
            && fields.is_none()
            && self.config.user.additional_fields.is_empty()
            && self.config.session.additional_fields.is_empty()
            && self.config.account.additional_fields.is_empty()
            && self
                .extensions
                .get::<crate::store::AdapterCallbacks<S>>()
                .is_none_or(|callbacks| callbacks.0.is_empty())
            && self.config.user_validation.is_none()
        {
            return Arc::clone(&self.database);
        }
        Arc::new(crate::store::PluginStore::new(
            Arc::clone(&self.database),
            Arc::clone(&self.config),
            transforms,
            session_callbacks,
            fields.map_or_else(
                || {
                    crate::field_policy::SessionFields(
                        self.config.session.additional_fields.clone(),
                    )
                },
                |fields| (*fields).clone(),
            ),
            self.extensions
                .get::<crate::field_policy::SessionAdapterFields>()
                .map_or_else(
                    || {
                        crate::field_policy::SessionAdapterFields(Arc::new(
                            self.config.session.additional_fields.clone(),
                        ))
                    },
                    |fields| (*fields).clone(),
                ),
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

impl std::fmt::Debug for AuthInitParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInitParts").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> std::fmt::Debug for AuthInitContext<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInitContext").finish_non_exhaustive()
    }
}
