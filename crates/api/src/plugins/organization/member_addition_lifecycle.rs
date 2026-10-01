//! Server-only member-admission callbacks over immutable original snapshots.
use async_trait::async_trait;
use better_auth_core::{AuthResult, Member, wire::UserView};

use super::{OrganizationMemberCreatePatch, types::OrganizationResponse};

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

/// Admission phases are awaited separately. Before errors prevent the member
/// write; after errors retain successful member/team writes. Team failures clean
/// up the new member and the original user's configured page of team memberships.
/// Supported typed patches are trusted and are not revalidated. Arbitrary custom
/// columns and direct mutation of JavaScript arguments remain adapter boundaries.
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
