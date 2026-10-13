//! Enumerate only configurations the authenticated caller can manage.
use super::{
    AuthContext, AuthResult, AuthSchema, AuthUser, EndpointResponse, SessionRequest, SsoPlugin,
    Value, json,
};
impl SsoPlugin {
    #[must_use]
    pub fn list_sso_providers_endpoint() -> super::ServerEndpoint<Value> {
        super::ServerEndpoint::new("sso", "listSSOProviders")
    }
    pub(super) async fn list<S: AuthSchema>(
        &self,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = super::super::helpers::ordinary_session(request, ctx).await?;
        let rows = ctx.database.list_sso_providers().await?;
        let org_enabled = ctx
            .get_metadata(super::super::organization::METADATA_ENABLED)
            .is_some();
        let mut accessible = Vec::new();
        for row in rows.iter().filter(|row| {
            row.organization_id.is_none() && row.user_id.as_deref() == Some(user.id().as_ref())
        }) {
            accessible.push(super::provider_read::sanitize(row, ctx)?);
        }
        for row in rows.iter().filter(|row| row.organization_id.is_some()) {
            let allowed = if org_enabled {
                if let Some(id) = row.organization_id.as_deref().filter(|id| !id.is_empty()) {
                    ctx.database
                        .get_member(id, user.id().as_ref())
                        .await?
                        .is_some_and(|member| {
                            member
                                .role
                                .split(',')
                                .any(|role| matches!(role.trim(), "owner" | "admin"))
                        })
                } else {
                    false
                }
            } else {
                row.user_id.as_deref() == Some(user.id().as_ref())
            };
            if allowed {
                accessible.push(super::provider_read::sanitize(row, ctx)?);
            }
        }
        EndpointResponse::json(&json!({"providers":accessible}))
    }
}
