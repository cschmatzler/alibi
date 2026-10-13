//! Durable ownership proofs, reused until the reference's seven-day deadline.
use super::{
    AuthContext, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint, SessionRequest,
    SsoPlugin, Value, json,
};
impl SsoPlugin {
    pub fn request_domain_verification_endpoint(
        provider_id: &str,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "requestDomainVerification")
            .with_body(&json!({"providerId":provider_id}))
    }
    fn domain_identifier(&self, provider_id: &str) -> String {
        let prefix = if self.config.domain_verification_token_prefix.is_empty() {
            "better-auth-token"
        } else {
            &self.config.domain_verification_token_prefix
        };
        format!("_{prefix}-{provider_id}")
    }
    pub(super) async fn issue_domain_proof<S: AuthSchema>(
        &self,
        provider_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        use base64::Engine as _;
        let bytes = rand::random::<[u8; 18]>();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let now = chrono::Utc::now();
        _ = ctx
            .verifications()
            .create(alibi_core::CreateVerification {
                identifier: self.domain_identifier(provider_id),
                value: token.clone(),
                expires_at: now + chrono::Duration::days(7),
            })
            .await?;
        Ok(token)
    }
    pub(super) async fn request_domain<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let provider = self.authorized_provider(input, request, ctx).await?;
        if provider.domain_verified == Some(true) {
            return Err(alibi_core::AuthError::Api {
                status: 409,
                code: Some("DOMAIN_VERIFIED".into()),
                message: "Domain has already been verified".into(),
            });
        }
        let proof = ctx
            .verifications()
            .find(&self.domain_identifier(&provider.provider_id))
            .await?;
        let token = if let Some(proof) = proof.filter(|proof| {
            proof
                .expires_at()
                .is_ok_and(|expiry| expiry > chrono::Utc::now())
        }) {
            proof.value()?.to_owned()
        } else {
            self.issue_domain_proof(&provider.provider_id, ctx).await?
        };
        Ok(EndpointResponse::json(&json!({"domainVerificationToken":token}))?.with_status(201))
    }
}
