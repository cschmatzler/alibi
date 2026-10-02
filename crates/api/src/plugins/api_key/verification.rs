use super::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyReferences,
    config_id_matches,
};
use better_auth_core::entity::AuthUser;
use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::wire::{ApiKeyView, SessionView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, BeforeRequestAction,
};
use serde::Serialize;

/// Inputs for server-only API key verification. Verification consumes one use.
pub struct VerifyApiKey<'a> {
    /// The plaintext API key presented by the caller.
    pub key: &'a str,
    /// Restrict verification to this configuration, or use the default lookup configuration.
    pub config_id: Option<&'a str>,
    /// Required resource permissions, checked before quota or rate-limit consumption.
    pub permissions: Option<&'a serde_json::Value>,
}

/// Additional information returned when a key reaches its rate limit.
#[derive(Debug, Serialize)]
pub struct ApiKeyErrorDetails {
    /// Milliseconds until the key's rate-limit window elapses.
    #[serde(rename = "tryAgainIn")]
    pub try_again_in: f64,
}

/// Upstream verification messages can contain either text or an error-code object.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiKeyErrorMessage {
    Text(String),
    CodeMessage {
        code: ApiKeyErrorCode,
        message: String,
    },
}

impl ApiKeyErrorMessage {
    fn text(&self) -> &str {
        match self {
            Self::Text(value) | Self::CodeMessage { message: value, .. } => value,
        }
    }
}

/// An API key rejection with the upstream error code and response fields.
#[derive(Debug, Serialize)]
pub struct ApiKeyValidationError {
    /// Stable upstream API key error code.
    pub code: ApiKeyErrorCode,
    /// Upstream error message.
    pub message: ApiKeyErrorMessage,
    /// Rate-limit timing, when the rejection is a rate limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ApiKeyErrorDetails>,
}

impl ApiKeyValidationError {
    pub(super) fn new(code: ApiKeyErrorCode) -> Self {
        Self {
            code,
            message: ApiKeyErrorMessage::Text(code.message().to_owned()),
            details: None,
        }
    }

    pub(super) const fn status(&self) -> u16 {
        match self.code {
            ApiKeyErrorCode::NoDefaultConfiguration => 400,
            ApiKeyErrorCode::RateLimited | ApiKeyErrorCode::UsageExceeded => 429,
            ApiKeyErrorCode::InvalidApiKey
            | ApiKeyErrorCode::KeyDisabled
            | ApiKeyErrorCode::KeyExpired
            | ApiKeyErrorCode::KeyNotFound
            | ApiKeyErrorCode::UnauthorizedSession
            | ApiKeyErrorCode::InvalidPrefixLength
            | ApiKeyErrorCode::InvalidNameLength
            | ApiKeyErrorCode::MetadataDisabled
            | ApiKeyErrorCode::NoValuesToUpdate
            | ApiKeyErrorCode::KeyDisabledExpiration
            | ApiKeyErrorCode::ExpiresInTooSmall
            | ApiKeyErrorCode::ExpiresInTooLarge
            | ApiKeyErrorCode::InvalidRemaining
            | ApiKeyErrorCode::RefillAmountAndIntervalRequired
            | ApiKeyErrorCode::RefillIntervalAndAmountRequired
            | ApiKeyErrorCode::NameRequired
            | ApiKeyErrorCode::InvalidUserIdFromApiKey
            | ApiKeyErrorCode::InvalidReferenceIdFromApiKey
            | ApiKeyErrorCode::OrganizationIdRequired
            | ApiKeyErrorCode::OrganizationPluginRequired
            | ApiKeyErrorCode::UserNotMemberOfOrganization
            | ApiKeyErrorCode::InsufficientApiKeyPermissions
            | ApiKeyErrorCode::ServerOnlyProperty
            | ApiKeyErrorCode::FailedToUpdateApiKey
            | ApiKeyErrorCode::InvalidMetadataType => 401,
        }
    }

    fn response(&self) -> AuthResult<AuthResponse> {
        Ok(AuthResponse::json(self.status(), self)?)
    }
}

/// Distinguishes a rejected credential from a storage or infrastructure failure.
#[derive(Debug)]
pub enum ApiKeyVerificationError {
    /// The credential or its permissions, quota, or configuration was rejected.
    Validation(ApiKeyValidationError),
    /// An internal operation failed. The original typed error is preserved.
    Internal(AuthError),
    /// An explicitly selected validator failed before verification's catch
    /// boundary. Server endpoint adapters propagate this original typed error.
    ExplicitValidator(AuthError),
}

impl std::fmt::Display for ApiKeyVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => f.write_str(error.message.text()),
            Self::Internal(error) | Self::ExplicitValidator(error) => {
                write!(f, "API key verification failed: {error}")
            }
        }
    }
}

impl std::error::Error for ApiKeyVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(error) | Self::ExplicitValidator(error) => Some(error),
            Self::Validation(_) => None,
        }
    }
}

impl From<AuthError> for ApiKeyVerificationError {
    fn from(error: AuthError) -> Self {
        Self::Internal(error)
    }
}

impl From<ApiKeyErrorCode> for ApiKeyVerificationError {
    fn from(code: ApiKeyErrorCode) -> Self {
        Self::Validation(ApiKeyValidationError::new(code))
    }
}

impl ApiKeyPlugin {
    /// Verify a machine credential without a user session or public HTTP endpoint.
    ///
    /// A successful verification consumes quota and a rate-limit slot. Permissions
    /// and configuration mismatches do not consume usage. The returned key omits
    /// the plaintext credential and stored hash.
    ///
    /// Without `config_id`, lookup uses the default configuration's hashing
    /// setting. Validation then uses the configuration that issued the key.
    ///
    /// # Errors
    ///
    /// Returns an error if verification hooks or storage operations fail.
    pub async fn verify_api_key(
        &self,
        input: &VerifyApiKey<'_>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        self.verify_api_key_with_registration(input, None, ctx)
            .await
    }

    /// Verify with the actual caller request available to trusted predicates.
    /// This performs the same server-only verification operation as `verify_api_key`.
    ///
    /// # Errors
    ///
    /// Propagates verification-hook or storage errors for the supplied request.
    pub async fn verify_api_key_with_request(
        &self,
        input: &VerifyApiKey<'_>,
        request: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        self.verify_api_key_with_registration(input, Some(request), ctx)
            .await
    }

    pub(super) async fn verify_api_key_with_registration(
        &self,
        input: &VerifyApiKey<'_>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let view = self
            .verify_api_key_checked(input, request, ctx, true)
            .await?;
        if self
            .resolve_configuration(Some(&view.config_id))?
            .defer_updates
        {
            self.register_expired_cleanup(ctx).await?;
        }
        Ok(view)
    }

    pub(super) async fn verify_api_key_checked(
        &self,
        input: &VerifyApiKey<'_>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        server_operation: bool,
    ) -> Result<ApiKeyView, ApiKeyVerificationError> {
        let lookup_config = self
            .resolve_configuration(input.config_id)
            .map_err(|_error| ApiKeyErrorCode::NoDefaultConfiguration)?;
        if server_operation
            && input.config_id.is_some()
            && let Some(validator) = &lookup_config.custom_api_key_validator
            && !validator
                .validate(
                    &ApiKeyCallbackContext::new(request, ctx, &lookup_config.config_id)
                        .with_verification_input(input),
                    input.key,
                )
                .await
                .map_err(ApiKeyVerificationError::ExplicitValidator)?
        {
            return Err(ApiKeyVerificationError::Validation(ApiKeyValidationError {
                code: ApiKeyErrorCode::KeyNotFound,
                message: ApiKeyErrorMessage::CodeMessage {
                    code: ApiKeyErrorCode::InvalidApiKey,
                    message: ApiKeyErrorCode::InvalidApiKey.message().to_owned(),
                },
                details: None,
            }));
        }
        let hashed = if lookup_config.disable_key_hashing {
            input.key.to_owned()
        } else {
            Self::hash_key(input.key)
        };
        let api_key = ctx
            .database
            .get_api_key_by_hash(&hashed)
            .await?
            .ok_or(ApiKeyErrorCode::InvalidApiKey)?;

        if input
            .config_id
            .is_some_and(|expected| !config_id_matches(&api_key.config_id, expected))
        {
            return Err(ApiKeyErrorCode::InvalidApiKey.into());
        }
        let config = self
            .resolve_configuration(Some(&api_key.config_id))
            .map_err(|_error| ApiKeyErrorCode::NoDefaultConfiguration)?;

        if server_operation
            && input.config_id.is_none()
            && let Some(validator) = &config.custom_api_key_validator
            && !validator
                .validate(
                    &ApiKeyCallbackContext::new(request, ctx, &config.config_id)
                        .with_verification_input(input),
                    input.key,
                )
                .await?
        {
            return Err(ApiKeyErrorCode::KeyNotFound.into());
        }

        if !api_key.enabled {
            return Err(ApiKeyErrorCode::KeyDisabled.into());
        }
        if let Some(expires_at) = api_key.expires_at.as_deref() {
            let expiration = chrono::DateTime::parse_from_rfc3339(expires_at).map_err(|error| {
                AuthError::internal(format!("Invalid stored API key expiration: {error}"))
            })?;
            if chrono::Utc::now() > expiration {
                Self::delete_rejected_key(&api_key.id, config, ctx).await?;
                return Err(ApiKeyErrorCode::KeyExpired.into());
            }
        }
        if let Some(required) = input.permissions {
            let permitted = match api_key.permissions.as_deref() {
                Some(permissions) => super::handlers::check_permissions(permissions, required)?,
                None => false,
            };
            if !permitted {
                return Err(ApiKeyErrorCode::KeyNotFound.into());
            }
        }

        // Source deletes only an initially observed zero/no-refill row.
        // A positive-snapshot loser of atomic consumption rejects without deletion.
        if api_key.remaining == Some(0.0) && api_key.refill_amount.is_none() {
            Self::delete_rejected_key(&api_key.id, config, ctx).await?;
            return Err(ApiKeyErrorCode::UsageExceeded.into());
        }

        let updated = match ctx
            .database
            .consume_api_key_usage_from_snapshot(&api_key, config.rate_limit.enabled)
            .await?
        {
            ConsumeApiKeyResult::Allowed(key) => key,
            ConsumeApiKeyResult::RateLimited { try_again_in } => {
                let mut error = ApiKeyValidationError::new(ApiKeyErrorCode::RateLimited);
                error.details = Some(ApiKeyErrorDetails { try_again_in });
                return Err(ApiKeyVerificationError::Validation(error));
            }
            ConsumeApiKeyResult::UsageExhausted => {
                return Err(ApiKeyErrorCode::UsageExceeded.into());
            }
        };
        Ok(ApiKeyView::from(updated.as_ref()))
    }

    async fn delete_rejected_key(
        id: &str,
        config: &ApiKeyConfig,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<()> {
        if !config.defer_updates {
            return ctx.database.delete_api_key(id).await;
        }
        let database = std::sync::Arc::clone(&ctx.database);
        let id = id.to_owned();
        let completion = Self::start_background_work(async move {
            if let Err(error) = database.delete_api_key(&id).await {
                tracing::error!(%error, "Deferred update failed");
            }
            Ok(())
        })
        .await?;
        if let Some(handler) = &ctx.config.background_tasks {
            handler.handle(completion)
        } else {
            drop(completion);
            Ok(())
        }
    }

    pub(super) fn find_session_key<'a>(
        &'a self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<(&'a ApiKeyConfig, String)>> {
        self.find_session_key_for_input(&req.headers, Some(req), None, ctx)
    }

    pub(super) fn find_session_key_for_input<'a>(
        &'a self,
        headers: &std::collections::HashMap<String, String>,
        request: Option<&AuthRequest>,
        endpoint: Option<&better_auth_core::endpoint::EndpointCall>,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<(&'a ApiKeyConfig, String)>> {
        for config in self
            .configurations
            .iter()
            .filter(|config| config.enable_session_for_api_keys)
        {
            let key = match &config.custom_api_key_getter {
                Some(getter) => {
                    let mut context = ApiKeyCallbackContext::new(request, ctx, &config.config_id);
                    if let Some(endpoint) = endpoint {
                        context = context.with_endpoint(endpoint);
                    }
                    getter.get_key(&context)?
                }
                None => config.api_key_headers.iter().find_map(|header| {
                    headers
                        .get(&header.to_ascii_lowercase())
                        .filter(|key| !key.is_empty())
                        .cloned()
                }),
            };
            if let Some(key) = key.filter(|key| !key.is_empty()) {
                return Ok(Some((config, key)));
            }
        }
        Ok(None)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep API key validation and session substitution in one ordered middleware decision"
    )]
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn api_key_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        // The Source hook matcher executes before its middleware handler. A
        // getter failure at that stage becomes the dispatcher's matcher error,
        // including an intentional API error thrown by the application.
        if self
            .find_session_key(req, ctx)
            .map_err(|_error| AuthError::Api {
                status: 500,
                code: None,
                message: "An error occurred during hook matcher execution. Check the logs for more details.".into(),
            })?
            .is_none()
        {
            return Ok(None);
        }
        let (config, key) = match self.find_session_key(req, ctx) {
            Ok(Some(value)) => value,
            Ok(None) => {
                tracing::error!("API key getter did not return a key after matching");
                return Ok(Some(BeforeRequestAction::Respond(AuthResponse::new(500))));
            }
            Err(error)
                if error.status_code() >= 500
                    && !matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. }) =>
            {
                tracing::error!(error = %error, "API key getter failed");
                return Ok(Some(BeforeRequestAction::Respond(AuthResponse::new(500))));
            }
            Err(error) => return Err(error),
        };

        if f64::from(
            u32::try_from(key.encode_utf16().count())
                .map_err(|error| AuthError::internal(error.to_string()))?,
        ) < config.key_length
        {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                403,
                &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
            )?)));
        }
        if let Some(validator) = &config.custom_api_key_validator {
            let valid = match validator
                .validate(
                    &ApiKeyCallbackContext::new(Some(req), ctx, &config.config_id),
                    &key,
                )
                .await
            {
                Ok(valid) => valid,
                Err(error)
                    if error.status_code() >= 500
                        && !matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. }) =>
                {
                    tracing::error!(error = %error, "API key validator failed");
                    return Ok(Some(BeforeRequestAction::Respond(AuthResponse::new(500))));
                }
                Err(error) => return Err(error),
            };
            if !valid {
                return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                    403,
                    &ApiKeyValidationError::new(ApiKeyErrorCode::InvalidApiKey),
                )?)));
            }
        }
        let input = VerifyApiKey {
            key: &key,
            config_id: Some(&config.config_id),
            permissions: None,
        };
        let view = match self
            .verify_api_key_checked(&input, Some(req), ctx, false)
            .await
        {
            Ok(view) => view,
            Err(ApiKeyVerificationError::Validation(error)) => {
                return Ok(Some(BeforeRequestAction::Respond(error.response()?)));
            }
            Err(
                ApiKeyVerificationError::Internal(error)
                | ApiKeyVerificationError::ExplicitValidator(error),
            ) => {
                // At this source middleware validation stage ordinary failures
                // become an empty 500; explicit application API errors survive.
                if error.status_code() >= 500
                    && !matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. })
                {
                    return Ok(Some(BeforeRequestAction::Respond(AuthResponse::new(500))));
                }
                return Err(error);
            }
        };
        if config.defer_updates {
            let completion = Self::start_expired_cleanup(ctx).await?;
            if let Some(handler) = &ctx.config.background_tasks {
                if let Err(error) = handler.handle(completion) {
                    if error.status_code() >= 500
                        && !matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. })
                    {
                        return Ok(Some(BeforeRequestAction::Respond(AuthResponse::new(500))));
                    }
                    return Err(error);
                }
            } else {
                drop(completion);
            }
        } else {
            self.maybe_delete_expired(ctx).await?;
        }

        if config.references != ApiKeyReferences::User {
            return Ok(Some(BeforeRequestAction::Respond(
                ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey)
                    .response()?,
            )));
        }
        let Some(user) = ctx.database.get_user_by_id(&view.reference_id).await? else {
            return Ok(Some(BeforeRequestAction::Respond(
                ApiKeyValidationError::new(ApiKeyErrorCode::InvalidReferenceIdFromApiKey)
                    .response()?,
            )));
        };

        let session = Self::virtual_session_from_key(&view, &key, &user, Some(req), ctx)?;
        // Upstream answers this path in its hook before the route method gate.
        if req.path() == "/get-session" {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &serde_json::json!({
                    "user": ctx.user_view(&user),
                    "session": session,
                }),
            )?)));
        }
        Ok(Some(BeforeRequestAction::InjectSession { session }))
    }
}

impl ApiKeyPlugin {
    pub(super) fn virtual_session_from_key<S: better_auth_core::AuthSchema>(
        view: &ApiKeyView,
        key: &str,
        user: &S::User,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<SessionView> {
        let now = chrono::Utc::now();
        let expires_at = match view.expires_at.as_deref() {
            Some(value) => chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|error| {
                    AuthError::internal(format!("Invalid stored API key expiration: {error}"))
                })?
                .with_timezone(&chrono::Utc),
            // Upstream passes its session lifetime in seconds to getDate(..., "ms").
            None => {
                now + chrono::Duration::milliseconds(ctx.config.session.expires_in.num_seconds())
            }
        };
        // Virtual principals retain the resolver's nullable result. Physical
        // session creation supplies empty defaults through RequestMeta.
        let ip_policy = request
            .and_then(|request| {
                request
                    .extensions()
                    .get::<better_auth_core::config::IpAddressConfig>()
            })
            .unwrap_or_default();
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            active_team_id: None,
            extension_fields: std::collections::BTreeMap::default(),
            id: view.id.clone(),
            token: key.to_owned(),
            user_id: user.id().into_owned(),
            created_at: now,
            updated_at: now,
            expires_at,
            ip_address: request.and_then(|request| ip_policy.resolve_ip(&request.headers)),
            user_agent: request.and_then(|request| {
                request
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                    .map(|(_, value)| value.clone())
            }),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        Ok(session)
    }
}

impl std::fmt::Debug for VerifyApiKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyApiKey").finish_non_exhaustive()
    }
}
