use super::ScimPlugin;
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse};
use alibi_core::store::AuthTransaction;
pub use alibi_core::store::{ScimIdentitySource, ScimProjectedUserState};
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
pub(super) struct ScimProjectionHandle<S: AuthSchema>(pub Arc<dyn ScimProjection<S>>);
/// A SCIM plugin carrying application-owned transactional projection callbacks.
pub struct ConfiguredScimPlugin<S: AuthSchema> {
    base: ScimPlugin,
    projection: Arc<dyn ScimProjection<S>>,
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
        }
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
        ctx.extensions
            .insert(ScimProjectionHandle(self.projection.clone()));
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
            let batch_domain = domain.clone();
            let result = transaction::<S, (), _>(ctx.database.as_ref(), move |database| {
                Box::pin(async move {
                    let states = database
                        .prepare_scim_projection(&batch_domain, &ids)
                        .await?;
                    for prepared in states {
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
                Err(AuthError::CallbackFailure(_)) => {
                    let detail = "SCIM projection reconciliation failed";
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
