//! Delivery scheduling for the already persisted one-time password.
use super::SendTwoFactorOtp;
use alibi_core::{AuthResult, BackgroundTaskHandler, start_background_task_for, wire::UserView};
use std::sync::Arc;

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
    let completion = start_background_task_for("Background OTP delivery", operation).await?;
    // runInBackgroundOrAwait also catches the synchronous application observer
    // error, independently of the already running delivery's result.
    if let Err(error) = observer.handle(completion) {
        tracing::warn!(error = %error, "Failed to run two-factor OTP background task");
    }
    Ok(())
}
