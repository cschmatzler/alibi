use super::*;
impl ApiKeyPlugin {
    /// Start automatic cleanup without awaiting its deletion.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn maybe_delete_expired(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<()> {
        drop(self.start_configured_cleanup(ctx).await?);
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn register_expired_cleanup(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<()> {
        let completion = self.start_configured_cleanup(ctx).await?;
        if let Some(handler) = &ctx.config.background_tasks {
            handler.handle(completion)
        } else {
            drop(completion);
            Ok(())
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn start_configured_cleanup(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<alibi_core::BackgroundTaskCompletion> {
        if self.configurations.iter().any(ApiKeyConfig::uses_database) {
            Self::start_expired_cleanup(ctx).await
        } else {
            Ok(Box::pin(async { Ok(()) }))
        }
    }

    pub(super) async fn start_expired_cleanup(
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<alibi_core::BackgroundTaskCompletion> {
        if !admit_expired_cleanup(false) {
            return Ok(Box::pin(async { Ok(()) }));
        }
        let database = Arc::clone(&ctx.database);
        Self::start_background_work(async move {
            if let Err(error) = database.delete_expired_api_keys().await {
                tracing::error!(%error, "Failed to delete expired API keys");
            }
            Ok(())
        })
        .await
    }

    // Both automatic bulk cleanup and deferred single-row rejection own their
    // work before application completion registration, preserving hook context.
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn start_background_work(
        operation: impl Future<Output = AuthResult<()>> + Send + 'static,
    ) -> AuthResult<alibi_core::BackgroundTaskCompletion> {
        alibi_core::start_background_task(operation).await
    }

    /// Force cleanup across owners/configurations, updating the same global
    /// automatic-cleanup timestamp and awaiting deletion despite the throttle.
    pub async fn delete_all_expired_api_keys(
        &self,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> DeleteExpiredApiKeysResponse {
        let _ignored_result = admit_expired_cleanup(true);
        if !self.configurations.iter().any(ApiKeyConfig::uses_database) {
            return DeleteExpiredApiKeysResponse {
                success: true,
                error: None,
            };
        }
        if let Err(error) = ctx.database.delete_expired_api_keys().await {
            tracing::error!(%error, "Failed to delete expired API keys");
        }
        DeleteExpiredApiKeysResponse {
            success: true,
            error: None,
        }
    }
}
