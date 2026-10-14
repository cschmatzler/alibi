//! Application mutation admission using the provider's locked transaction.
use alibi_core::{AuthResult, AuthSchema, AuthTransaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{any::Any, sync::Arc};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SsoMutationAction {
    Update,
    Delete,
}
/// Provider identity supplied to an application policy without credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoMutationProvider {
    pub id: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
}
/// The current provider reference and proposed mutation's boundary classification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoProviderMutation {
    pub action: SsoMutationAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_authentication_boundary_change: Option<bool>,
    pub provider: SsoMutationProvider,
    pub provider_reference: Value,
}
#[async_trait::async_trait]
pub trait SsoProviderMutationGuard<S: AuthSchema>: Send + Sync {
    /// Runs inside the provider mutation transaction. An error rejects and rolls back it.
    async fn guard(
        &self,
        mutation: SsoProviderMutation,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<()>;
}
/// A schema-bound application policy retained in non-generic plugin configuration.
#[derive(Clone)]
pub struct SsoMutationGuard {
    callback: Arc<dyn Any + Send + Sync>,
}
impl SsoMutationGuard {
    pub fn new<S: AuthSchema>(callback: Arc<dyn SsoProviderMutationGuard<S>>) -> Self {
        Self {
            callback: Arc::new(callback),
        }
    }
    pub(super) fn resolve<S: AuthSchema>(
        &self,
    ) -> AuthResult<Arc<dyn SsoProviderMutationGuard<S>>> {
        self.callback
            .downcast_ref::<Arc<dyn SsoProviderMutationGuard<S>>>()
            .cloned()
            .ok_or_else(|| {
                alibi_core::AuthError::config(
                    "SSO mutation guard schema does not match the application schema",
                )
            })
    }
}
impl std::fmt::Debug for SsoMutationGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoMutationGuard")
            .finish_non_exhaustive()
    }
}

pub(super) async fn run<S: AuthSchema>(
    guard: &dyn SsoProviderMutationGuard<S>,
    provider: &alibi_core::store::SsoProvider,
    action: SsoMutationAction,
    boundary: Option<bool>,
    verified: bool,
    database: &dyn AuthTransaction<S>,
) -> AuthResult<()> {
    let mutation = SsoProviderMutation {
        action,
        is_authentication_boundary_change: boundary,
        provider: SsoMutationProvider {
            id: provider.id.clone(),
            provider_id: provider.provider_id.clone(),
            organization_id: provider.organization_id.clone(),
        },
        provider_reference: super::sign_in::mutation_provider_reference(provider, verified)?,
    };
    guard.guard(mutation, database).await.map_err(|_| {
        tracing::error!("SSO provider mutation guard rejected the mutation");
        alibi_core::AuthError::Api {
            status: 409,
            code: Some("SSO_PROVIDER_MUTATION_REJECTED".into()),
            message: "SSO provider mutation is not allowed".into(),
        }
    })
}
