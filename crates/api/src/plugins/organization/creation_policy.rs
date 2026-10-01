//! Application-owned organization creation policies, evaluated on the persisted user.
use async_trait::async_trait;
use better_auth_core::{AuthResult, wire::UserView};

/// Optional asynchronous overrides for the fixed creation settings.
///
/// `None` uses the corresponding fixed configuration. A limit override returns
/// `Some(true)` when the user has reached the limit, rather than when creation is allowed.
#[async_trait]
pub trait OrganizationCreationPolicy: std::fmt::Debug + Send + Sync {
    async fn allow_creation(&self, _user: &UserView) -> AuthResult<Option<bool>> {
        Ok(None)
    }
    async fn limit_reached(&self, _user: &UserView) -> AuthResult<Option<bool>> {
        Ok(None)
    }
}
