use alibi_core::{AuthContext, AuthResult, AuthSchema};
/// Log a noncritical callback or a notification whose policy permits continuation.
pub(crate) async fn run_notification(notification: impl Future<Output = AuthResult<()>>) {
    if let Err(error) = notification.await {
        tracing::error!(%error, "Failed to run background task");
    }
}

/// Apply the awaited error policy, or observe already running owned work when
/// the application supplies a background-task handler. Committed auth state is
/// retained; the caller's transaction controls uncommitted writes.
pub(crate) async fn run_owned_notification(
    context: &AuthContext<impl AuthSchema>,
    notification: impl Future<Output = AuthResult<()>> + Send + 'static,
    error_policy: alibi_core::AwaitedNotificationErrorPolicy,
) -> AuthResult<()> {
    if let Some(handler) = &context.config.background_tasks {
        let completion = alibi_core::start_background_task(async move {
            run_notification(notification).await;
            Ok(())
        })
        .await?;
        if let Err(error) = handler.handle(completion) {
            tracing::error!(%error, "Failed to observe background task");
        }
    } else {
        match error_policy {
            alibi_core::AwaitedNotificationErrorPolicy::Propagate => notification.await?,
            alibi_core::AwaitedNotificationErrorPolicy::LogAndContinue => {
                run_notification(notification).await;
            }
        }
    }
    Ok(())
}
