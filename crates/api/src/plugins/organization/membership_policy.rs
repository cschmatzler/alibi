//! Source admission limits are separate from adapter read-page limits.
use super::types::OrganizationResponse;
use async_trait::async_trait;
use better_auth_core::{AuthResult, wire::UserView};
use std::sync::Arc;

/// One immutable membership policy, shared by trusted addition and invitation admission.
#[derive(Debug, Clone)]
pub enum MembershipLimit {
    Fixed(f64),
    Resolver(Arc<dyn OrganizationMembershipLimitResolver>),
}

/// Evaluated after the actual member count and organization lookup, over the
/// target user and raw stored organization. Read pages never invoke this callback.
#[async_trait]
pub trait OrganizationMembershipLimitResolver: std::fmt::Debug + Send + Sync {
    async fn maximum_members(
        &self,
        user: &UserView,
        organization: &OrganizationResponse,
    ) -> AuthResult<f64>;
}

pub(in crate::plugins) fn truthy_number(value: f64) -> bool {
    value != 0.0 && !value.is_nan()
}

pub(in crate::plugins) fn read_page_limit(policy: Option<&MembershipLimit>) -> f64 {
    match policy {
        Some(MembershipLimit::Fixed(value)) if truthy_number(*value) => *value,
        _ => 100.0,
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn admission_limit(
    policy: Option<&MembershipLimit>,
    user: &UserView,
    organization: &OrganizationResponse,
) -> AuthResult<f64> {
    match policy {
        Some(MembershipLimit::Resolver(resolver)) => {
            resolver.maximum_members(user, organization).await
        }
        _ => Ok(read_page_limit(policy)),
    }
}
