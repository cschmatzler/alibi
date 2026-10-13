//! Instance-local work prepared while session foreign keys still identify dependants.
use crate::{AuthResult, AuthSchema, AuthStore};
use async_trait::async_trait;
use std::sync::Arc;
/// Prepare read-only work before a session mutation. A vetoed deletion never completes it.
#[async_trait]
pub trait SessionDeletionHook<S: AuthSchema>: Send + Sync {
    async fn prepare(
        &self,
        session: &S::Session,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<Option<Box<dyn SessionDeletionWork<S>>>>;
}
/// Work performed after the selected physical session has actually disappeared.
#[async_trait]
pub trait SessionDeletionWork<S: AuthSchema>: Send + Sync {
    async fn complete(&self, database: &dyn AuthStore<S>) -> AuthResult<()>;
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
