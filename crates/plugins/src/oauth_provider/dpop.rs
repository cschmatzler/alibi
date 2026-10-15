//! Sender binding is resolved before any token mint or refresh claim.
use super::{OAuthProviderPlugin, OAuthTokenIssueParams};
use alibi_core::endpoint::EndpointError;
use alibi_core::session::SessionRequest;
use alibi_core::{AuthContext, AuthError, AuthSchema};
use serde_json::{Value, json};

impl OAuthProviderPlugin {
    pub(super) async fn resolve_dpop_binding<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl SessionRequest,
        params: &OAuthTokenIssueParams,
        policy: &super::resource_policy::ResourceAdmission,
    ) -> Result<Option<Value>, EndpointError> {
        let metadata = params
            .client
            .metadata
            .get("metadata")
            .and_then(|value| match value {
                Value::String(text) => serde_json::from_str::<Value>(text).ok(),
                value => Some(value.clone()),
            });
        let client_required = params.client.metadata.get("dpop_bound_access_tokens")
            == Some(&Value::Bool(true))
            || params.client.metadata.get("dpopBoundAccessTokens") == Some(&Value::Bool(true))
            || metadata
                .as_ref()
                .and_then(|v| v.get("dpop_bound_access_tokens"))
                == Some(&Value::Bool(true));
        let code_jkt = params
            .verification_value
            .as_ref()
            .and_then(|v| v.get("query"))
            .and_then(|v| v.get("dpop_jkt"))
            .and_then(Value::as_str);
        let refresh_jkt = params
            .refresh_token
            .as_ref()
            .and_then(|v| v.metadata.get("confirmation"))
            .and_then(crate::oauth2::get_confirmation_jkt);
        let proof = req
            .session_headers()
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("dpop"))
            .map(|(_, value)| value.trim_matches([' ', '\t', '\r', '\n']))
            .filter(|v| !v.is_empty());
        let Some(proof) = proof else {
            if client_required
                || policy.dpop_required
                || refresh_jkt.is_some()
                || code_jkt.is_some_and(|v| !v.is_empty())
            {
                return Err(super::resource_policy::failure(
                    "invalid_dpop_proof",
                    "DPoP proof header is required",
                ));
            }
            return Ok(None);
        };
        let url = req.physical_request().and_then(|v| v.url()).map_or_else(
            || {
                format!(
                    "{}{}/oauth2/token",
                    ctx.config.base_url.trim_end_matches('/'),
                    ctx.config.base_path
                )
            },
            ToString::to_string,
        );
        let replay = crate::oauth2::create_dpop_replay_store(ctx);
        // The reference deliberately fixes htm to POST, even for a supplied
        // physical request whose method differs from the token endpoint.
        let mut options = crate::oauth2::VerifyDpopProofOptions::new(proof, "POST", &url);
        options.expected_jkt = refresh_jkt.or(code_jkt);
        options.replay_store = Some(&replay);
        options.proof_max_age_seconds = self.config.dpop_proof_max_age_seconds;
        options.signing_algorithms = self.config.dpop_signing_algorithms.clone();
        match crate::oauth2::verify_dpop_proof(&options).await {
            Ok(proof) => Ok(Some(json!({"jkt":proof.jkt}))),
            Err(error) if crate::oauth2::is_dpop_proof_error(&error) => Err(
                super::resource_policy::failure("invalid_dpop_proof", &error.message),
            ),
            Err(error) => Err(AuthError::internal(error.message).into()),
        }
    }
}
