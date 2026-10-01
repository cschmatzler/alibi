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
