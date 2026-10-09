use crate::{
    AuthError, AuthResult, CreateInvitation, CreateMember, CreateOrganization, Invitation,
    InvitationStatus, Member, Organization, UpdateOrganization,
};
use async_trait::async_trait;
/// Query parameters for listing organization members.
#[derive(Debug, Clone, Default)]
pub struct ListOrganizationMembersParams {
    /// Organization id whose members should be listed.
    pub organization_id: String,
    /// Maximum number of members to return.
    pub limit: Option<usize>,
    /// Number of matching members to skip before returning rows.
    pub offset: Option<usize>,
    /// Client-visible field name used for sorting.
    pub sort_by: Option<String>,
    /// Sort direction (`asc` or `desc`).
    pub sort_direction: Option<String>,
    /// Client-visible field name used for filtering.
    pub filter_field: Option<String>,
    /// Filter value paired with `filter_field`.
    pub filter_value: Option<String>,
    /// Filter operator (`eq`, `ne`, `contains`, `gt`, `gte`, `lt`, `lte`).
    pub filter_operator: Option<String>,
}

/// Adapter page with JavaScript numeric limits retained through SQL binding.
/// Unlike the legacy usize query, an absent sort does not impose an order.
#[derive(Debug, Clone, Default)]
pub struct MemberPageQuery {
    pub organization_id: String,
    pub limit: Option<f64>,
    pub offset: Option<f64>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<String>,
    pub filter_operator: Option<String>,
}

#[async_trait]
pub trait OrganizationStore: Send + Sync {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    /// Fetch multiple organizations by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization>;
    /// Apply exactly the supplied organization columns as a database patch.
    /// Returns absence separately from database errors. Empty patches are sent
    /// to the adapter rather than converted into timestamp-only updates.
    /// Custom stores serving the default HTTP update route must implement this
    /// bounded operation; the default fails closed with `NotImplemented`.
    /// Model callbacks belong to `update_organization_if_present` instead.
    async fn patch_organization_if_present(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        Err(AuthError::NotImplemented(
            "Organization patches are not supported by this store".into(),
        ))
    }
    /// Update a matching organization, retaining adapter model hooks.
    /// `None` means no row was updated; other storage failures remain errors.
    /// Custom stores must implement this optional-row operation explicitly.
    async fn update_organization_if_present(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        Err(AuthError::NotImplemented(
            "Optional organization updates are not supported by this store".into(),
        ))
    }
    /// Delete the organization and its members/invitations atomically.
    /// Extension rows (teams, roles, API keys) and sessions are retained, matching
    /// the pinned default adapter. Custom adapters own their constraint policy.
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    /// Update a matching member while preserving adapter model hooks.
    /// Absence is `None`; other storage failures remain errors.
    async fn update_member_role_if_present(
        &self,
        _member_id: &str,
        _role: &str,
    ) -> AuthResult<Option<Member>> {
        Err(AuthError::NotImplemented(
            "Optional member role updates are not supported by this store".into(),
        ))
    }
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    /// Delete the authorized original member, then optionally release its team
    /// memberships atomically. The original scope/user remains authoritative if
    /// a lifecycle callback independently changes or removes the stored member.
    /// A missing/ignored member deletion is successful; SQL errors are failures.
    async fn delete_member_with_context(
        &self,
        _member_id: &str,
        _organization_id: &str,
        _user_id: &str,
        _remove_team_members: bool,
    ) -> AuthResult<()> {
        Err(AuthError::NotImplemented(
            "Contextual member deletion is not supported by this store".into(),
        ))
    }
    /// Return the adapter's organization-scoped page without imposing a sort.
    /// Used for the source's paged last-owner guard independently of total count.
    async fn list_organization_members_page(
        &self,
        _organization_id: &str,
        _limit: usize,
    ) -> AuthResult<Vec<Member>> {
        Err(AuthError::NotImplemented(
            "Unsorted member pages are not supported by this store".into(),
        ))
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    /// Query organization members with filter, sort, and pagination applied in
    /// the store when possible.
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
    /// Apply raw numeric pagination without converting it into the legacy usize API.
    async fn query_organization_members_page(
        &self,
        _params: &MemberPageQuery,
    ) -> AuthResult<(Vec<Member>, usize)> {
        Err(AuthError::NotImplemented(
            "Raw numeric member pages are not supported by this store".into(),
        ))
    }
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
}

/// Trusted persisted-field overrides returned by an invitation creation hook.
/// They are separate from the stable default `CreateInvitation` constructor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvitationCreateOptions {
    pub id: Option<String>,
    pub status: Option<InvitationStatus>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create_invitation_with_options(
        &self,
        invitation: CreateInvitation,
        options: InvitationCreateOptions,
    ) -> AuthResult<Invitation> {
        if options == InvitationCreateOptions::default() {
            self.create_invitation(invitation).await
        } else {
            Err(AuthError::NotImplemented(
                "Invitation creation overrides are not supported by this store".into(),
            ))
        }
    }

    /// Actual adapter page of pending rows, before expiry filtering.
    async fn pending_invitation_page(
        &self,
        _org_id: &str,
        _email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        Err(AuthError::NotImplemented(
            "Pending invitation pages are not supported by this store".into(),
        ))
    }
    /// Update expiry independently; reissue retains every other invitation field.
    async fn update_invitation_expiry(
        &self,
        _id: &str,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Invitation> {
        Err(AuthError::NotImplemented(
            "Invitation expiry updates are not supported by this store".into(),
        ))
    }

    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation>;
    /// Atomically change only an invitation still at the expected status and return
    /// the actual updated row. A mismatch or missing row returns None. This write
    /// commits independently of a later membership transaction.
    async fn update_invitation_status_if_status(
        &self,
        _id: &str,
        _expected: InvitationStatus,
        _status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        Err(AuthError::NotImplemented(
            "Conditional invitation updates are not supported by this store".into(),
        ))
    }
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    /// Count still-pending, unexpired invitations for an organization.
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
    /// Claim a pending invitation and persist memberships/session scope in one transition.
    async fn accept_invitation_with_teams(
        &self,
        _invitation_id: &str,
        _user_id: &str,
        _session_token: &str,
        _team_limits: &[(String, Option<f64>)],
        _membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, Member)>> {
        Err(AuthError::NotImplemented(
            "Atomic invitation acceptance is not supported by this store".to_owned(),
        ))
    }
    async fn update_invitation_team_ids(
        &self,
        _id: &str,
        _team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        Err(AuthError::NotImplemented(
            "Invitation team updates are not supported by this store".to_owned(),
        ))
    }
}
