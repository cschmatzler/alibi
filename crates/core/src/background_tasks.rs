//! Application observation of already running background work.
use crate::AuthResult;
use std::{future::Future, pin::Pin};

/// Completion of an already started owned task.
/// Dropping this observation does not cancel its underlying work. Applications
/// may retain and await it to keep their executor alive until work completes.
pub type BackgroundTaskCompletion = Pin<Box<dyn Future<Output = AuthResult<()>> + Send + 'static>>;

/// Application integration for deferred operations, such as platform waitUntil.
///
/// The callback receives a completion rather than a task that it must start.
/// A synchronous callback error does not cancel work already started.
pub trait BackgroundTaskHandler: Send + Sync {
    ///
    /// # Errors
    ///
    /// Returns an error if the application rejects observation of the background completion.
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()>;
}

/// Start owned work immediately and retain the initiating request/tracing context.
/// The returned observation may be dropped without cancelling pending work.
///
/// # Errors
/// Returns an error when pending work cannot be scheduled on a Tokio executor.
pub async fn start_background_task(
    operation: impl Future<Output = AuthResult<()>> + Send + 'static,
) -> AuthResult<BackgroundTaskCompletion> {
    use tracing::{Instrument, instrument::WithSubscriber};
    let request_context = crate::hooks::current_request_hook_context();
    let work = async move {
        match request_context {
            Some(context) => {
                crate::hooks::with_request_hook_context_value(context, operation).await
            }
            None => operation.await,
        }
    }
    .instrument(tracing::Span::current())
    .with_current_subscriber();
    let mut work: BackgroundTaskCompletion = Box::pin(work);
    match std::future::poll_fn(|context| std::task::Poll::Ready(work.as_mut().poll(context))).await
    {
        std::task::Poll::Ready(result) => Ok(Box::pin(async move { result })),
        std::task::Poll::Pending => {
            let executor = tokio::runtime::Handle::try_current().map_err(|error| {
                crate::AuthError::internal(format!(
                    "Background task requires a Tokio executor: {error}"
                ))
            })?;
            let running = executor.spawn(work);
            Ok(Box::pin(async move {
                running.await.map_err(|error| {
                    crate::AuthError::internal(format!("Background task failed: {error}"))
                })?
            }))
        }
    }
}
