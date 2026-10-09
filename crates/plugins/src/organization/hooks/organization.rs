use crate::organization::types::CreatedOrganizationResponse;
use alibi_core::AuthResult;
use alibi_core::CreateMember;
use alibi_core::CreateOrganization;
use alibi_core::Member;
use alibi_core::Organization;
use alibi_core::UpdateOrganization;
use alibi_core::utils::json::JsValue;
use alibi_core::wire::UserView;
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::Map;
use serde_json::Value;

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

/// Creation hooks are awaited at their individual source phases.
///
/// Errors retain previous writes; the framework does not wrap this lifecycle in a transaction.
/// Authority snapshots cannot be changed by an HTTP body or by mutating context. Typed patches
/// cover bundled model fields, not arbitrary JavaScript columns or direct mutation of callback
/// arguments. Capture an application store when the callback needs independent persistence or
/// additional field access.
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

/// The original authenticated user/session and raw stored organization.
///
/// Selection has already been cleared in storage when `before_delete` runs. The same snapshots
/// reach `after_delete`, after scoped deletion has committed.
#[derive(Debug, Clone)]
pub struct OrganizationDeleteContext {
    pub organization: crate::organization::types::OrganizationResponse,
    pub user: UserView,
    pub session: alibi_core::wire::SessionView,
    /// Actual supplied values; a trusted header-only call does not invent headers.
    pub headers: std::collections::HashMap<String, String>,
    /// None for the trusted header-only helper. HTTP snapshots use the native
    /// `AuthRequest`'s canonical route path and independent public request parts.
    pub request: Option<alibi_core::AuthRequest>,
}

pub(crate) struct DeleteInvocation<'a> {
    pub headers: &'a std::collections::HashMap<String, String>,
    pub request: Option<&'a alibi_core::AuthRequest>,
}

/// Awaited deletion phases, without a lifecycle-wide transaction.
///
/// A before-hook error retains rows after selection clearing; an after-hook error retains the
/// committed deletion. Capture an application store for independent operations. Direct JavaScript
/// argument mutation, global server-API dispatch and continuation after HTTP request cancellation
/// are separate framework boundaries.
#[async_trait]
pub trait OrganizationDeletionHooks: std::fmt::Debug + Send + Sync {
    async fn before_delete(&self, _context: &OrganizationDeleteContext) -> AuthResult<()> {
        Ok(())
    }
    async fn after_delete(&self, _context: &OrganizationDeleteContext) -> AuthResult<()> {
        Ok(())
    }
}

/// Original validated patch; the source supplies this instead of a stored row.
#[derive(Debug, Clone)]
pub struct OrganizationUpdateInput {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<Option<String>>,
    /// Original JavaScript numbers remain available until adapter serialization.
    pub metadata: Option<IndexMap<String, JsValue>>,
}

/// Original validated patch and the authenticated actor and membership snapshots.
#[derive(Debug, Clone)]
pub struct OrganizationUpdateContext {
    pub organization: OrganizationUpdateInput,
    pub user: UserView,
    pub member: Member,
}

/// Parsed adapter output, or `None` when the update found no row.
/// Authority snapshots retain their original values even if a callback writes.
#[derive(Debug, Clone)]
pub struct OrganizationUpdatedContext {
    pub organization: Option<CreatedOrganizationResponse>,
    pub user: UserView,
    pub member: Member,
}

/// Supported bundled fields merged over validated input without revalidation.
#[derive(Debug, Clone, Default)]
pub struct OrganizationUpdatePatch {
    pub name: Option<String>,
    pub slug: Option<String>,
    /// `None` retains the supplied patch; `Some(None)` clears the logo.
    pub logo: Option<Option<String>>,
    /// `None` retains input; `Some(None)` stores literal JSON null.
    /// This intentionally differs from the creation hook's falsy-null policy.
    pub metadata: Option<Option<IndexMap<String, JsValue>>>,
}
impl OrganizationUpdatePatch {
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(crate) fn apply(self, data: &mut UpdateOrganization) -> AuthResult<()> {
        if let Some(name) = self.name {
            data.name = Some(name);
        }
        if let Some(slug) = self.slug {
            data.slug = Some(slug);
        }
        if let Some(logo) = self.logo {
            data.logo = Some(logo);
        }
        if let Some(metadata) = self.metadata {
            data.metadata = Some(
                metadata
                    .map_or(JsValue::Null, JsValue::Object)
                    .to_json_value()?,
            );
        }
        Ok(())
    }
}

/// Trusted application callbacks run after validation/authentication/permission and the initial
/// slug lookup.
///
/// Before errors prevent the update; after errors retain prior writes. This lifecycle is not
/// wrapped in a transaction. Typed patches cover bundled columns, not arbitrary JavaScript
/// properties or direct callback-argument mutation. Capture an application store for writes.
#[async_trait]
pub trait OrganizationUpdateHooks: std::fmt::Debug + Send + Sync {
    async fn before_update(
        &self,
        _context: &OrganizationUpdateContext,
    ) -> AuthResult<Option<OrganizationUpdatePatch>> {
        Ok(None)
    }
    async fn after_update(&self, _context: &OrganizationUpdatedContext) -> AuthResult<()> {
        Ok(())
    }
}
