use super::ScimPlugin;
use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse};
use alibi_core::store::AuthTransaction;
pub use alibi_core::store::{
    ScimAuthorizationSource, ScimIdentitySource, ScimIdentityState, ScimProjectedUserState,
    ScimRoleExistenceInput, ScimRoleMappingInput,
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
#[async_trait]
pub trait ScimIdentity<S: AuthSchema>: Send + Sync {
    async fn reconcile_user(
        &self,
        input: &ScimIdentityState,
        database: &dyn AuthTransaction<S>,
    ) -> AuthResult<()>;
}
pub(super) struct ScimIdentityHandle<S: AuthSchema>(pub Arc<dyn ScimIdentity<S>>);
pub(super) struct ScimProjectionHandle<S: AuthSchema>(
    pub Arc<dyn ScimProjection<S>>,
    pub Option<Arc<dyn ScimRoleProjection<S>>>,
);

/// A SCIM plugin carrying application-owned transactional projection callbacks.
pub struct ConfiguredScimPlugin<S: AuthSchema> {
    base: ScimPlugin,
    projection: Option<Arc<dyn ScimProjection<S>>>,
    identity: Option<Arc<dyn ScimIdentity<S>>>,
    roles: Option<Arc<dyn ScimRoleProjection<S>>>,
    verifier: Option<Arc<dyn super::ScimBearerTokenVerifier<S>>>,
}
impl ScimPlugin {
    #[must_use]
    pub fn projection<S: AuthSchema>(
        self,
        projection: Arc<dyn ScimProjection<S>>,
    ) -> ConfiguredScimPlugin<S> {
        ConfiguredScimPlugin {
            base: self,
            projection: Some(projection),
            identity: None,
            roles: None,
            verifier: None,
        }
    }
}
impl ScimPlugin {
    #[must_use]
    pub fn identity<S: AuthSchema>(
        self,
        identity: Arc<dyn ScimIdentity<S>>,
    ) -> ConfiguredScimPlugin<S> {
        ConfiguredScimPlugin {
            base: self,
            projection: None,
            identity: Some(identity),
            roles: None,
            verifier: None,
        }
    }
}
impl ScimPlugin {
    #[must_use]
    pub fn authentication<S: AuthSchema>(
        mut self,
        verifier: Arc<dyn super::ScimBearerTokenVerifier<S>>,
    ) -> ConfiguredScimPlugin<S> {
        self.has_token_verifier = true;
        ConfiguredScimPlugin {
            base: self,
            projection: None,
            identity: None,
            roles: None,
            verifier: Some(verifier),
        }
    }
}
impl<S: AuthSchema> ConfiguredScimPlugin<S> {
    #[must_use]
    pub fn authentication(mut self, verifier: Arc<dyn super::ScimBearerTokenVerifier<S>>) -> Self {
        self.base.has_token_verifier = true;
        self.verifier = Some(verifier);
        self
    }
    #[must_use]
    pub fn identity(mut self, identity: Arc<dyn ScimIdentity<S>>) -> Self {
        self.identity = Some(identity);
        self
    }

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
    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        <ScimPlugin as AuthPlugin<S>>::allowed_media_types(&self.base, route)
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
        if let Some(verifier) = &self.verifier {
            ctx.extensions
                .insert(super::authentication::ScimBearerVerifierHandle(
                    verifier.clone(),
                ));
        }
        if let Some(projection) = &self.projection {
            ctx.extensions
                .insert(ScimProjectionHandle(projection.clone(), self.roles.clone()));
        }
        if let Some(identity) = &self.identity {
            ctx.extensions.insert(ScimIdentityHandle(identity.clone()));
        }
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
                                "SCIM role mapping failed"
                                    | "SCIM role validation failed"
                                    | "SCIM identity reconciliation failed"
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

pub(super) async fn apply_roles<S: AuthSchema>(
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
            .map_err(|error| application_callback_error(error, "SCIM role mapping failed"))?
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
                    .map_err(|error| {
                        application_callback_error(error, "SCIM role validation failed")
                    })?;
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
    // The reference orders base64url grant keys with String.localeCompare,
    // whose default collation puts lowercase letters before later uppercase
    // letters by alphabetic weight rather than by their ASCII byte values.
    let collator = icu_collator::Collator::try_new(
        icu_collator::CollatorPreferences::default(),
        icu_collator::options::CollatorOptions::default(),
    )
    .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?;
    ordered.sort_by(|left, right| collator.compare(&left.0, &right.0));
    prepared.state.grants = ordered.into_iter().map(|(_, (_, state))| state).collect();
    Ok(())
}
pub(super) fn application_callback_error(
    error: alibi_core::AuthError,
    detail: &str,
) -> alibi_core::AuthError {
    if alibi_core::endpoint::is_endpoint_api_error(&error) {
        error
    } else {
        tracing::error!(error=%error,detail,"SCIM application callback failed");
        alibi_core::AuthError::CallbackFailure(Box::new(alibi_core::AuthError::Api {
            status: 500,
            code: None,
            message: detail.into(),
        }))
    }
}
impl ScimPlugin {
    pub(super) async fn decommission_binding<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        mut binding: alibi_core::store::ScimConnectionBinding,
    ) -> AuthResult<alibi_core::store::ScimConnectionBinding> {
        use alibi_core::{AuthError, store::transaction};
        use chrono::SubsecRound;
        let active_lease = |binding: &alibi_core::store::ScimConnectionBinding| {
            binding.decommission_status == "reconciling"
                && binding
                    .decommission_lease_id
                    .as_ref()
                    .is_some_and(|lease| !lease.is_empty())
                && binding
                    .decommission_lease_expires_at
                    .is_some_and(|expiry| expiry > chrono::Utc::now().trunc_subsecs(3))
        };
        if binding.decommission_status == "complete" || active_lease(&binding) {
            return Ok(binding);
        }
        let mut acquired = None;
        for _ in 0..10 {
            if let Some(leased) = ctx
                .database
                .acquire_scim_decommission_lease(binding.clone())
                .await?
            {
                acquired = Some(leased);
                break;
            }
            binding = ctx
                .database
                .terminal_scim_connection_binding(
                    &binding.connection_id,
                    Some(&binding.provisioning_domain_id),
                    &binding.connection_key,
                )
                .await?;
            if binding.decommission_status == "complete" || active_lease(&binding) {
                return Ok(binding);
            }
        }
        let binding=acquired.ok_or_else(||AuthError::internal(format!("SCIM connection \"{}\" changed repeatedly while decommissioning; retry the operation.",binding.connection_id)))?;
        let lease = binding
            .decommission_lease_id
            .clone()
            .ok_or_else(|| AuthError::internal("Acquired SCIM lease missing"))?;
        let projection = ctx.extensions.get::<ScimProjectionHandle<S>>();
        let identity = ctx.extensions.get::<ScimIdentityHandle<S>>();
        let result=async {
            loop {
                let binding_id=binding.id.clone();let connection_id=binding.connection_id.clone();let lease=lease.clone();let projection=projection.clone();let identity=identity.clone();
                let checkpoint=transaction::<S,alibi_core::store::ScimConnectionBinding,_>(ctx.database.as_ref(),move|database|Box::pin(async move{
                    let stored=database.get_scim_connection_binding(&binding_id).await?.ok_or_else(||AuthError::internal(format!("SCIM connection \"{connection_id}\" binding disappeared during decommissioning.")))?;
                    if stored.decommission_status=="complete"{return Ok(stored);}
                    if stored.decommission_lease_id.as_deref()!=Some(&lease){return Err(AuthError::internal(format!("SCIM connection \"{connection_id}\" decommission lease was taken over by another worker.")));}
                    let candidates=database.scim_projection_candidates(&stored.provisioning_domain_id,stored.decommission_cursor_user_id.as_deref()).await?;
                    let more=candidates.len()>50;let mut cursor=None;let mut by_user=indexmap::IndexMap::new();for candidate in candidates.into_iter().take(50){cursor=Some(candidate.user_id.clone());_=by_user.insert(candidate.user_id,candidate.id);}
                    let user_ids=by_user.keys().cloned().collect::<Vec<_>>();let ids=by_user.into_values().collect::<Vec<_>>();
                    let roles=projection.as_ref().and_then(|projection|projection.1.clone());
                    let states=database.prepare_scim_projection(&stored.provisioning_domain_id,&ids,roles.is_some()).await?;
                    if !database.renew_scim_decommission_lease(&stored,&lease).await?{return Err(AuthError::internal(format!("SCIM connection \"{connection_id}\" decommission lease changed before reconciliation.")));}
                    for mut prepared in states {
                        if let Some(roles)=&roles{apply_roles(database,roles.as_ref(),&mut prepared).await?;}
                        database.remove_scim_projection_grants(&stored.provisioning_domain_id,&prepared.state.user_id,&prepared.removed_grant_ids).await?;
                        if let Some(projection)=&projection{projection.0.reconcile_user(&prepared.state,database).await.map_err(|error|if alibi_core::endpoint::is_endpoint_api_error(&error){error}else{AuthError::CallbackFailure(Box::new(error))})?;}
                    }
                    for user_id in &user_ids{
                        let state=database.reconcile_scim_identity(user_id).await?;
                        if let Some(identity)=&identity{identity.0.reconcile_user(&state,database).await.map_err(|error|application_callback_error(error,"SCIM identity reconciliation failed"))?;}
                        if !state.active{database.delete_user_sessions(user_id).await?;}
                    }
                    database.advance_scim_decommission(&stored,&lease,cursor.as_deref(),user_ids.len(),more).await?.ok_or_else(||AuthError::internal(format!("SCIM connection \"{connection_id}\" decommission checkpoint changed concurrently.")))
                })).await?;
                if checkpoint.decommission_status=="complete"{return Ok(checkpoint);}
            }
        }.await;
        if result.is_err() {
            let _ignored = ctx
                .database
                .release_scim_decommission_lease(&binding.id, &lease)
                .await;
        }
        result
    }
    pub(super) fn scim_callback_response(cause: &alibi_core::AuthError) -> EndpointResponse {
        use alibi_core::{AuthError, utils::json::JsValue};
        let detail = match cause {
            AuthError::Api { message, .. }
                if matches!(
                    message.as_str(),
                    "SCIM role mapping failed"
                        | "SCIM role validation failed"
                        | "SCIM identity reconciliation failed"
                ) =>
            {
                message.as_str()
            }
            _ => "SCIM projection reconciliation failed",
        };
        EndpointResponse::error(AuthError::Api{status:500,code:None,message:detail.into()}).with_error_body(JsValue::from(serde_json::json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":detail})))
    }
}
