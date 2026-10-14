use super::ScimPlugin;
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse};
use alibi_core::store::AuthTransaction;
pub use alibi_core::store::{
    ScimAuthorizationSource, ScimIdentitySource, ScimProjectedUserState, ScimRoleExistenceInput,
    ScimRoleMappingInput,
};
use alibi_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema,
};
use async_trait::async_trait;
use std::sync::Arc;
/// Application access reconciliation inside the actual provisioning transaction.
#[async_trait]
pub trait ScimProjection<S: AuthSchema>: Send + Sync {
    async fn reconcile_user(
        &self,
        input: &ScimProjectedUserState,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<()>;
}
#[async_trait]
pub trait ScimRoleProjection<S: AuthSchema>: Send + Sync {
    async fn map(
        &self,
        input: &ScimRoleMappingInput,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<Option<Vec<String>>>;
    async fn exists(
        &self,
        input: &ScimRoleExistenceInput,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<bool>;
}
pub(super) struct ScimProjectionHandle<S: AuthSchema>(
    pub Arc<dyn ScimProjection<S>>,
    pub Option<Arc<dyn ScimRoleProjection<S>>>,
);

/// A SCIM plugin carrying application-owned transactional projection callbacks.
pub struct ConfiguredScimPlugin<S: AuthSchema> {
    base: ScimPlugin,
    projection: Arc<dyn ScimProjection<S>>,
    roles: Option<Arc<dyn ScimRoleProjection<S>>>,
}
impl ScimPlugin {
    #[must_use]
    pub fn projection<S: AuthSchema>(
        self,
        projection: Arc<dyn ScimProjection<S>>,
    ) -> ConfiguredScimPlugin<S> {
        ConfiguredScimPlugin {
            base: self,
            projection,
            roles: None,
        }
    }
}
impl<S: AuthSchema> ConfiguredScimPlugin<S> {
    #[must_use]
    pub fn roles(mut self, roles: Arc<dyn ScimRoleProjection<S>>) -> Self {
        self.roles = Some(roles);
        self
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for ConfiguredScimPlugin<S> {
    route_openapi_metadata!(S);
    fn name(&self) -> &'static str {
        "scim"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        <ScimPlugin as AuthPlugin<S>>::routes(&self.base)
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        <ScimPlugin as AuthPlugin<S>>::server_endpoints(&self.base)
    }
    fn validate_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointInput> {
        self.base.validate_endpoint(call, ctx)
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        self.base.on_init(ctx).await?;
        ctx.extensions.insert(ScimProjectionHandle(
            self.projection.clone(),
            self.roles.clone(),
        ));
        Ok(())
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        self.base.on_endpoint(call, ctx).await
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        self.base.on_request(req, ctx).await
    }
}

impl ScimPlugin {
    pub(super) async fn reconcile_projection<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        use alibi_core::{AuthError, store::transaction, utils::json::JsValue};
        let projection=ctx.extensions.get::<ScimProjectionHandle<S>>().ok_or_else(||AuthError::config("SCIM projection reconciliation requires projection.reconcileUser to be configured."))?;
        let domain = call
            .body()
            .and_then(|body| body.get("provisioningDomainId"))
            .and_then(JsValue::as_str)
            .ok_or_else(|| AuthError::internal("Validated domain missing"))?
            .to_owned();
        let mut cursor = None;
        let mut reconciled = 0;
        let mut batches = 0;
        loop {
            let candidates = ctx
                .database
                .scim_projection_candidates(&domain, cursor.as_deref())
                .await?;
            if candidates.is_empty() {
                break;
            }
            let more = candidates.len() > 50;
            let mut by_user = indexmap::IndexMap::new();
            for candidate in candidates.into_iter().take(50) {
                cursor = Some(candidate.user_id.clone());
                _ = by_user.insert(candidate.user_id, candidate.id);
            }
            let count = by_user.len();
            let ids = by_user.into_values().collect::<Vec<_>>();
            let callback = projection.0.clone();
            let roles = projection.1.clone();
            let batch_domain = domain.clone();
            let result = transaction::<S, (), _>(ctx.database.as_ref(), move |database| {
                Box::pin(async move {
                    let states = database
                        .prepare_scim_projection(&batch_domain, &ids, roles.is_some())
                        .await?;
                    for mut prepared in states {
                        if let Some(roles) = &roles {
                            apply_roles(database, roles.as_ref(), &mut prepared).await?;
                        }

                        database
                            .remove_scim_projection_grants(
                                &batch_domain,
                                &prepared.state.user_id,
                                &prepared.removed_grant_ids,
                            )
                            .await?;
                        callback
                            .reconcile_user(&prepared.state, database)
                            .await
                            .map_err(|error| {
                                if alibi_core::endpoint::is_endpoint_api_error(&error) {
                                    error
                                } else {
                                    AuthError::CallbackFailure(Box::new(error))
                                }
                            })?;
                    }
                    Ok(())
                })
            })
            .await;
            match result {
                Ok(()) => {}
                Err(AuthError::CallbackFailure(cause)) => {
                    let detail = match cause.as_ref() {
                        AuthError::Api { message, .. }
                            if matches!(
                                message.as_str(),
                                "SCIM role mapping failed" | "SCIM role validation failed"
                            ) =>
                        {
                            message.as_str()
                        }
                        _ => "SCIM projection reconciliation failed",
                    };
                    return Ok(EndpointResponse::error(AuthError::Api{status:500,code:None,message:detail.into()}).with_error_body(JsValue::from(serde_json::json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":detail}))));
                }
                Err(error) => return Err(error),
            }
            batches += 1;
            reconciled += count;
            if !more {
                break;
            }
        }
        EndpointResponse::json(
            &serde_json::json!({"provisioningDomainId":domain,"reconciledUsers":reconciled,"batches":batches}),
        )
    }
}

async fn apply_roles<S: AuthSchema>(
    database: &dyn AuthTransaction<S>,
    roles: &dyn ScimRoleProjection<S>,
    prepared: &mut alibi_core::store::ScimProjectionPreparedUser,
) -> AuthResult<()> {
    use alibi_core::store::CreateScimProjectionGrant;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::SubsecRound;
    use sha2::{Digest, Sha256};
    let mut desired = indexmap::IndexMap::new();
    let mut existence = std::collections::HashMap::new();
    for input in &prepared.role_sources {
        let mapped = roles
            .map(input, database)
            .await
            .map_err(|error| role_error(error, "SCIM role mapping failed"))?
            .unwrap_or_default();
        let mut unique = std::collections::HashSet::new();
        for candidate in mapped {
            let role = alibi_core::utils::javascript::trim(&candidate);
            if role.is_empty() || !unique.insert(role.to_string()) {
                continue;
            }
            let existence_key = (
                input.connection_id.clone(),
                input.provisioning_domain_id.clone(),
                role.to_string(),
            );
            let exists = if let Some(exists) = existence.get(&existence_key) {
                *exists
            } else {
                let exists = roles
                    .exists(
                        &ScimRoleExistenceInput {
                            connection_id: input.connection_id.clone(),
                            provisioning_domain_id: input.provisioning_domain_id.clone(),
                            role: role.into(),
                        },
                        database,
                    )
                    .await
                    .map_err(|error| role_error(error, "SCIM role validation failed"))?;
                _ = existence.insert(existence_key, exists);
                exists
            };
            if !exists {
                continue;
            }
            let ScimAuthorizationSource::Group {
                id,
                external_id,
                display_name,
            } = &input.source;
            let key = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
                "scim-projection-grant",
                &input.connection_id,
                &input.scim_user_id,
                "group",
                id,
                role,
            ])?));
            _ = desired.insert(
                key.clone(),
                (
                    CreateScimProjectionGrant {
                        connection_id: input.connection_id.clone(),
                        provisioning_domain_id: input.provisioning_domain_id.clone(),
                        scim_user_id: input.scim_user_id.clone(),
                        user_id: input.user_id.clone(),
                        source_id: id.clone(),
                        source_value: external_id.clone().unwrap_or_else(|| display_name.clone()),
                        role: role.into(),
                        grant_key: key,
                        created_at: chrono::Utc::now().trunc_subsecs(3),
                    },
                    serde_json::json!({"source":input.source,"role":role}),
                ),
            );
        }
    }
    prepared.removed_grant_ids = prepared
        .existing_grants
        .iter()
        .filter(|(_, key)| !desired.contains_key(key))
        .map(|(id, _)| id.clone())
        .collect();
    database
        .remove_scim_projection_grants(
            &prepared.state.provisioning_domain_id,
            &prepared.state.user_id,
            &prepared.removed_grant_ids,
        )
        .await?;
    prepared.removed_grant_ids.clear();
    let now = chrono::Utc::now().trunc_subsecs(3);
    for (key, (data, _)) in &desired {
        if !prepared
            .existing_grants
            .iter()
            .any(|(_, existing)| existing == key)
        {
            let mut data = data.clone();
            data.created_at = now;
            database.create_scim_projection_grant(data).await?;
        }
    }
    let mut ordered = desired.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    prepared.state.grants = ordered.into_iter().map(|(_, (_, state))| state).collect();
    Ok(())
}
fn role_error(error: alibi_core::AuthError, detail: &str) -> alibi_core::AuthError {
    if alibi_core::endpoint::is_endpoint_api_error(&error) {
        error
    } else {
        tracing::error!(error=%error,detail,"SCIM role callback failed");
        alibi_core::AuthError::CallbackFailure(Box::new(alibi_core::AuthError::Api {
            status: 500,
            code: None,
            message: detail.into(),
        }))
    }
}
