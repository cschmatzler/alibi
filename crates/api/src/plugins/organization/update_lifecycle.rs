//! Awaited update callbacks with immutable validated input and authority snapshots.
use super::types::CreatedOrganizationResponse;
use async_trait::async_trait;
use better_auth_core::utils::json::JsValue;
use better_auth_core::{AuthResult, Member, UpdateOrganization, wire::UserView};
use indexmap::IndexMap;

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
    pub(in crate::plugins) fn apply(self, data: &mut UpdateOrganization) -> AuthResult<()> {
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
