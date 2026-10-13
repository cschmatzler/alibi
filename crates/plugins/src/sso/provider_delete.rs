//! Retire a provider's identity namespace under the caller's real authority.
use super::{
    AuthContext, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint, SessionRequest,
    SsoPlugin, Value, api, json,
};
impl SsoPlugin {
    pub fn delete_sso_provider_endpoint(provider_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "deleteSSOProvider")
            .with_body(&json!({"providerId":provider_id}))
    }
    pub(super) async fn delete<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let provider = self.authorized_provider(input, request, ctx).await?;
        if !ctx
            .database
            .delete_sso_provider_and_accounts(&provider.id, &provider.provider_id)
            .await?
        {
            return Err(api(404, "Provider not found"));
        }
        EndpointResponse::json(&json!({"success":true}))
    }
    pub(super) fn validate_delete(input: Option<&JsValue>) -> AuthResult<JsValue> {
        super::super::endpoint::validate_fields(
            input,
            "body",
            &[super::super::authentication_helpers::JsonField::string(
                "providerId",
                true,
            )],
        )
    }
}
