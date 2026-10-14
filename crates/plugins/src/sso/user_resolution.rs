//! Application-owned resolution of a cryptographically verified enterprise identity.
use alibi_core::{AuthResult, AuthSchema, AuthTransaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{any::Any, sync::Arc};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    Oidc,
    Saml,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoAccountKey {
    pub issuer: String,
    pub account_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoUserResolutionInput {
    pub protocol: SsoProtocol,
    pub provider_id: String,
    pub account_key: SsoAccountKey,
    pub provider_user: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_claims: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_id_token_claims: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_attributes: Option<Value>,
    pub provider_reference: Value,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoResolvedProfile {
    Preserve,
    Update,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum SsoUserResolution {
    Continue,
    Link {
        #[serde(rename = "userId")]
        user_id: String,
        profile: SsoResolvedProfile,
    },
    Reject {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}
impl SsoUserResolution {
    pub(super) fn valid(&self) -> bool {
        match self {
            Self::Continue => true,
            Self::Link { user_id, .. } => !user_id.trim().is_empty(),
            Self::Reject { code, .. } => !code.trim().is_empty(),
        }
    }
}
#[async_trait::async_trait]
pub trait SsoUserResolver<S: AuthSchema>: Send + Sync {
    async fn resolve(
        &self,
        input: SsoUserResolutionInput,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<SsoUserResolution>;
}
#[derive(Clone)]
pub struct SsoResolver {
    callback: Arc<dyn Any + Send + Sync>,
}
impl SsoResolver {
    pub fn new<S: AuthSchema>(callback: Arc<dyn SsoUserResolver<S>>) -> Self {
        Self {
            callback: Arc::new(callback),
        }
    }
    pub(super) fn resolve<S: AuthSchema>(&self) -> AuthResult<Arc<dyn SsoUserResolver<S>>> {
        self.callback
            .downcast_ref::<Arc<dyn SsoUserResolver<S>>>()
            .cloned()
            .ok_or_else(|| {
                alibi_core::AuthError::config(
                    "SSO user resolver schema does not match the application schema",
                )
            })
    }
}
impl std::fmt::Debug for SsoResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoResolver").finish_non_exhaustive()
    }
}

pub(super) struct Authentication<'a, S: AuthSchema> {
    pub identity: crate::oauth::handlers::transactional_identity::Identity<'a, S>,
    pub input: SsoUserResolutionInput,
    pub provider: &'a alibi_core::store::SsoProvider,
}
fn failure() -> alibi_core::AuthError {
    alibi_core::AuthError::Api {
        status: 500,
        code: Some("SSO_USER_RESOLUTION_FAILED".into()),
        message: "Unable to resolve the SSO user".into(),
    }
}
impl super::SsoPlugin {
    pub(super) async fn resolved_authentication<S: AuthSchema>(
        &self,
        request: Authentication<'_, S>,
    ) -> AuthResult<crate::oauth::handlers::ProcessOAuthUserResult> {
        let resolver = self
            .config
            .resolve_user
            .as_ref()
            .ok_or_else(failure)?
            .resolve::<S>()?;
        let identity = request.identity;
        let ctx = identity.ctx.clone();
        if ctx.config.session.stateless {
            return Err(alibi_core::AuthError::Api {
                status: 501,
                code: Some("SSO_USER_RESOLUTION_REQUIRES_DATABASE_SESSIONS".into()),
                message:
                    "SSO user resolution requires database-backed sessions with database fallback"
                        .into(),
            });
        }
        let provider = request.provider.clone();
        let input = request.input;
        let verified = self.config.domain_verification;
        let name = identity.provider.to_owned();
        let user = identity.user.clone();
        let profile = identity.profile.clone();
        let policy = identity.policy.clone();
        let tokens = identity.tokens.clone();
        let meta = identity.meta.clone();
        let disabled = identity.disable_signup;
        let scoped = ctx.clone();
        let authenticated = alibi_core::store::transaction_with_policy(
            ctx.database.as_ref(),
            alibi_core::store::AfterCommitErrorPolicy::Report,
            move |database| {
                Box::pin(async move {
                    if !provider.id.is_empty() {
                        let current = database
                            .lock_sso_provider(&provider.id, &provider.provider_id)
                            .await?
                            .ok_or_else(|| alibi_core::AuthError::Api {
                                status: 409,
                                code: Some("SSO_PROVIDER_CHANGED".into()),
                                message:
                                    "SSO provider changed while account linking was in progress"
                                        .into(),
                            })?;
                        if super::sign_in::provider_reference(&current, verified)?
                            != input.provider_reference
                        {
                            return Err(alibi_core::AuthError::Api {
                                status: 409,
                                code: Some("SSO_PROVIDER_CHANGED".into()),
                                message:
                                    "SSO provider changed while account linking was in progress"
                                        .into(),
                            });
                        }
                    }
                    let decision = resolver.resolve(input, database).await.map_err(|_| {
                        tracing::error!("SSO user resolution failed");
                        failure()
                    })?;
                    if !decision.valid() {
                        return Err(failure());
                    }
                    if let SsoUserResolution::Reject { code, message } = &decision {
                        return Err(alibi_core::AuthError::Api {
                            status: 403,
                            code: Some(code.clone()),
                            message: message.clone().unwrap_or_default(),
                        });
                    }
                    let identity = crate::oauth::handlers::transactional_identity::Identity {
                        provider: &name,
                        user: &user,
                        profile: &profile,
                        policy: &policy,
                        tokens: &tokens,
                        disable_signup: disabled,
                        meta: &meta,
                        ctx: &scoped,
                    };
                    crate::oauth::handlers::transactional_identity::authenticate(
                        &identity, &decision, database,
                    )
                    .await
                })
            },
        )
        .await?;
        crate::oauth::handlers::transactional_identity::publish(&ctx, authenticated).await
    }
}
