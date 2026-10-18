//! Instance-local work prepared while session foreign keys still identify dependants.
use crate::{AuthContext, AuthResult, AuthSchema};
use async_trait::async_trait;
use std::sync::Arc;
/// Prepare read-only work before a session mutation. A vetoed deletion never completes it.
/// The instance context provides the undecorated store and installed plugin policy.
#[async_trait]
pub trait SessionDeletionHook<S: AuthSchema>: Send + Sync {
    async fn prepare(
        &self,
        session: &S::Session,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<Box<dyn SessionDeletionWork<S>>>>;
}
/// Work performed after the selected session is deleted or its audit row expires.
/// Implementations may hand owned work to the instance's background-task policy.
#[async_trait]
pub trait SessionDeletionWork<S: AuthSchema>: Send + Sync {
    async fn complete(&self, context: &AuthContext<S>) -> AuthResult<()>;
}
pub(crate) struct SessionDeletionHooks<S: AuthSchema>(
    pub(crate) Vec<Arc<dyn SessionDeletionHook<S>>>,
);
impl<S: AuthSchema> Default for SessionDeletionHooks<S> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<S: AuthSchema> Clone for SessionDeletionHooks<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
