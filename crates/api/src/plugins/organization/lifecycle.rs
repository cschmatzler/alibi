//! Typed creation lifecycle callbacks over immutable authority and row snapshots.
use async_trait::async_trait;
use better_auth_core::wire::UserView;
use better_auth_core::{AuthResult, CreateMember, CreateOrganization, Member, Organization};
use serde_json::{Map, Value};

/// The validated draft after creation policies and the initial slug check.
#[derive(Debug, Clone)]
pub struct OrganizationDraftContext {
    pub organization: CreateOrganization,
    pub user: UserView,
}

/// The actual creator-member draft and the organization already persisted.
#[derive(Debug, Clone)]
pub struct OrganizationMemberDraftContext {
    pub organization: Organization,
    pub member: CreateMember,
    pub user: UserView,
}

/// Persisted row snapshots used after adding the creator and after creation.
/// The latter callback runs after default-team callbacks and before selection.
#[derive(Debug, Clone)]
pub struct OrganizationCreatedContext {
    pub organization: Organization,
    pub member: Member,
    pub user: UserView,
}

/// Supported fields merged over the validated draft without revalidation.
#[derive(Debug, Clone, Default)]
pub struct OrganizationCreatePatch {
    pub id: Option<String>,
    pub name: Option<String>,
    pub slug: Option<String>,
    /// `None` retains the draft; `Some(None)` clears its logo.
    pub logo: Option<Option<String>>,
    /// `None` retains metadata; `Some(None)` applies the source's falsy-null
    /// creation policy and omits it. A present empty map stores an empty record.
    /// This differs from the native store's literal JSON-null write.
    pub metadata: Option<Option<Map<String, Value>>>,
}
impl OrganizationCreatePatch {
    pub(crate) fn apply(self, data: &mut CreateOrganization) {
        if let Some(id) = self.id {
            data.id = Some(id);
        }
        if let Some(name) = self.name {
            data.name = name;
        }
        if let Some(slug) = self.slug {
            data.slug = slug;
        }
        if let Some(logo) = self.logo {
            data.logo = logo;
        }
        if let Some(metadata) = self.metadata {
            data.metadata = metadata.map(Value::Object);
        }
    }
}

/// Trusted member-field overrides. The source generates member IDs itself.
#[derive(Debug, Clone, Default)]
pub struct OrganizationMemberCreatePatch {
    pub organization_id: Option<String>,
    pub user_id: Option<String>,
    pub role: Option<String>,
}
impl OrganizationMemberCreatePatch {
    pub(crate) fn apply(self, data: &mut CreateMember) {
        if let Some(id) = self.organization_id {
            data.organization_id = id;
        }
        if let Some(id) = self.user_id {
            data.user_id = id;
        }
        if let Some(role) = self.role {
            data.role = role;
        }
    }
}

/// Creation hooks are awaited at their individual source phases. Errors retain
/// previous writes; the framework does not wrap this lifecycle in a transaction.
/// Authority snapshots cannot be changed by an HTTP body or by mutating context.
/// Typed patches cover bundled model fields, not arbitrary JavaScript columns
/// or direct mutation of callback arguments. Capture an application store when
/// the callback needs independent persistence or additional field access.
#[async_trait]
pub trait OrganizationCreationHooks: std::fmt::Debug + Send + Sync {
    async fn before_create(
        &self,
        _context: &OrganizationDraftContext,
    ) -> AuthResult<Option<OrganizationCreatePatch>> {
        Ok(None)
    }
    async fn before_add_member(
        &self,
        _context: &OrganizationMemberDraftContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        Ok(None)
    }
    async fn after_add_member(&self, _context: &OrganizationCreatedContext) -> AuthResult<()> {
        Ok(())
    }
    async fn after_create(&self, _context: &OrganizationCreatedContext) -> AuthResult<()> {
        Ok(())
    }
}
