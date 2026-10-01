//! Awaited role callbacks over the target member and original related rows.
use super::types::OrganizationResponse;
use async_trait::async_trait;
use better_auth_core::{AuthResult, Member, wire::UserView};

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
