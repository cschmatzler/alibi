use crate::plugins::organization::OrganizationMemberCreatePatch;
use crate::plugins::organization::types::OrganizationMemberRemovalSnapshot;
use crate::plugins::organization::types::OrganizationResponse;
use alibi_core::AuthResult;
use alibi_core::Member;
use alibi_core::wire::UserView;
use async_trait::async_trait;

/// The source callback draft has no generated ID or creation timestamp.
#[derive(Debug, Clone)]
pub struct OrganizationMemberAdditionDraft {
    pub user_id: String,
    pub organization_id: String,
    pub role: String,
    pub team_id: Option<String>,
}

/// Target user and raw stored organization after all initial admission checks.
/// There is no invented actor or HTTP request in this server-only callback.
#[derive(Debug, Clone)]
pub struct OrganizationMemberAdditionContext {
    pub member: OrganizationMemberAdditionDraft,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// The persisted member after optional team admission, with original snapshots.
#[derive(Debug, Clone)]
pub struct OrganizationMemberAddedContext {
    pub member: Member,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// Admission phases are awaited separately.
///
/// Before errors prevent the member write; after errors retain successful member/team writes. Team
/// failures clean up the new member and the original user's configured page of team memberships.
/// Supported typed patches are trusted and are not revalidated. Arbitrary custom columns and
/// direct mutation of JavaScript arguments remain adapter boundaries.
#[async_trait]
pub trait OrganizationMemberAdditionHooks: std::fmt::Debug + Send + Sync {
    async fn before_add_member(
        &self,
        _context: &OrganizationMemberAdditionContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        Ok(None)
    }

    async fn after_add_member(&self, _context: &OrganizationMemberAddedContext) -> AuthResult<()> {
        Ok(())
    }
}

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

/// Original target membership, normalized requested role and target user.
/// The organization uses the adapter's raw stored metadata projection.
#[derive(Debug, Clone)]
pub struct OrganizationMemberRoleContext {
    pub member: Member,
    pub new_role: String,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// Updated member and original role, target user and organization snapshots.
#[derive(Debug, Clone)]
pub struct OrganizationMemberRoleUpdatedContext {
    pub member: Member,
    pub previous_role: String,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// A nonempty role overrides the authorized initial role without revalidation.
/// Empty or missing values retain the normalized initial role, as in source.
#[derive(Debug, Clone, Default)]
pub struct OrganizationMemberRolePatch {
    pub role: Option<String>,
}

/// Trusted application callbacks execute after role authorization/validation.
///
/// Before errors prevent the adapter write; after errors retain it. The lifecycle
/// is not wrapped in a transaction. Contexts contain the target user, not actor.
#[async_trait]
pub trait OrganizationMemberRoleHooks: std::fmt::Debug + Send + Sync {
    async fn before_update(
        &self,
        _context: &OrganizationMemberRoleContext,
    ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
        Ok(None)
    }
    async fn after_update(
        &self,
        _context: &OrganizationMemberRoleUpdatedContext,
    ) -> AuthResult<()> {
        Ok(())
    }
}
