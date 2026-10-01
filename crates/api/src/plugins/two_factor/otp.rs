//! Delivery scheduling for the already persisted one-time password.
use std::{future::Future, sync::Arc};

use better_auth_core::{
    AuthError, AuthResult, BackgroundTaskCompletion, BackgroundTaskHandler, wire::UserView,
};

use super::SendTwoFactorOtp;

pub(super) async fn deliver(
    sender: Arc<dyn SendTwoFactorOtp>,
    user: UserView,
    otp: String,
    observer: Option<Arc<dyn BackgroundTaskHandler>>,
) -> AuthResult<()> {
    // The published endpoint catches a rejected delivery promise before handing
    // its completion to runInBackgroundOrAwait. Issued OTP state remains usable.
    let operation = async move {
        if let Err(error) = sender.send(&user, &otp).await {
            tracing::warn!(error = %error, "Failed to send two-factor OTP");
        }
        Ok(())
    };
    let Some(observer) = observer else {
        return operation.await;
    };
    let completion = start(operation).await?;
    // runInBackgroundOrAwait also catches the synchronous application observer
    // error, independently of the already running delivery's result.
    if let Err(error) = observer.handle(completion) {
        tracing::warn!(error = %error, "Failed to run two-factor OTP background task");
    }
    Ok(())
}

async fn start(
    operation: impl Future<Output = AuthResult<()>> + Send + 'static,
) -> AuthResult<BackgroundTaskCompletion> {
    use tracing::{Instrument, instrument::WithSubscriber};
    let request_context = better_auth_core::hooks::current_request_hook_context();
    let work = async move {
        match request_context {
            Some(context) => {
                better_auth_core::hooks::with_request_hook_context_value(context, operation).await
            }
            None => operation.await,
        }
    }
    .instrument(tracing::Span::current())
    .with_current_subscriber();
    let mut work: BackgroundTaskCompletion = Box::pin(work);
    // JavaScript calls the async sender before registering its hot promise.
    match std::future::poll_fn(|context| std::task::Poll::Ready(work.as_mut().poll(context))).await
    {
        std::task::Poll::Ready(result) => Ok(Box::pin(async move { result })),
        std::task::Poll::Pending => {
            let executor = tokio::runtime::Handle::try_current().map_err(|error| {
                AuthError::internal(format!(
                    "Background OTP delivery requires a Tokio executor: {error}"
                ))
            })?;
            let running = executor.spawn(work);
            Ok(Box::pin(async move {
                running.await.map_err(|error| {
                    AuthError::internal(format!("Background OTP delivery task failed: {error}"))
                })?
            }))
        }
    }
}
