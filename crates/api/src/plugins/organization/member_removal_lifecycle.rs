//! Awaited member removal callbacks over immutable original adapter snapshots.
use super::types::{OrganizationMemberRemovalSnapshot, OrganizationResponse};
use async_trait::async_trait;
use better_auth_core::{AuthResult, wire::UserView};

/// The original target membership, target user and raw stored organization.
///
/// Email selection includes the adapter's joined user in member; ID selection
/// omits it. These are target snapshots, not invented actor/request arguments.
#[derive(Debug, Clone)]
pub struct OrganizationMemberRemovalContext {
    pub member: OrganizationMemberRemovalSnapshot,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// Trusted callbacks run after authorization and related-row resolution.
///
/// Before errors prevent ordinary deletion; after errors retain committed deletion and
/// current-session selection clearing. Independent callback writes remain real. The lifecycle has
/// no enclosing transaction; the contextual adapter deletion does. Returned patches are not part
/// of the source removal callback contract.
#[async_trait]
pub trait OrganizationMemberRemovalHooks: std::fmt::Debug + Send + Sync {
    async fn before_remove(&self, _context: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        Ok(())
    }
    async fn after_remove(&self, _context: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        Ok(())
    }
}
