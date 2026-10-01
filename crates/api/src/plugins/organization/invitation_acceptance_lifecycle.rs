//! Awaited invitation acceptance callbacks with original authority snapshots.
use super::types::OrganizationResponse;
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, Member,
    wire::{InvitationView, UserView},
};

#[derive(Debug, Clone)]
pub struct OrganizationInvitationAcceptanceContext {
    pub invitation: InvitationView,
    pub user: UserView,
    /// The originally looked-up organization, including its stored metadata.
    pub organization: OrganizationResponse,
}

#[derive(Debug, Clone)]
pub struct OrganizationInvitationAcceptedContext {
    pub invitation: InvitationView,
    pub member: Member,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// Before errors prevent the conditional claim.
///
/// After errors retain accepted
/// status and committed memberships/session scope. Returned JavaScript callback
/// values do not patch acceptance; immutable snapshots express this contract.
#[async_trait]
pub trait OrganizationInvitationAcceptanceHooks: std::fmt::Debug + Send + Sync {
    async fn before_accept_invitation(
        &self,
        _context: &OrganizationInvitationAcceptanceContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_accept_invitation(
        &self,
        _context: &OrganizationInvitationAcceptedContext,
    ) -> AuthResult<()> {
        Ok(())
    }
}
