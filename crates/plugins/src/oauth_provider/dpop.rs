//! Sender binding is resolved before any token mint or refresh claim.
use super::{OAuthProviderPlugin, OAuthTokenIssueParams};
use alibi_core::endpoint::EndpointError;
use alibi_core::session::SessionRequest;
use alibi_core::{AuthContext, AuthError, AuthSchema};
use serde_json::{Value, json};

pub(super) fn proof_header(req: &impl SessionRequest) -> Option<&str> {
    req.session_headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("dpop"))
        .map(|(_, value)| value.trim_matches([' ', '\t', '\r', '\n']))
        .filter(|value| !value.is_empty())
}
/// The endpoint's public URL, which clients use as the `DPoP` `htu`: the origin
/// and base path of the configured base URL (not the request URL, whose host
/// proxies and dev servers can rewrite) plus the request's own path below the
/// base path, so route parameters and a trailing slash match what the client
/// called. `path` is used when there is no HTTP request.
pub(super) fn endpoint_url<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &impl SessionRequest,
    path: &str,
) -> String {
    let configured = format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    );
    let base = configured.trim_end_matches('/');
    let Some(request_path) = req
        .physical_request()
        .and_then(|request| request.url())
        .map(url::Url::path)
        .filter(|_| !base.is_empty())
    else {
        return format!("{base}{path}");
    };
    let base_path = url::Url::parse(base)
        .map(|url| {
            let path = url.path();
            path.strip_suffix('/').unwrap_or(path).to_owned()
        })
        .unwrap_or_default();
    let endpoint_path = request_path
        .strip_prefix(base_path.as_str())
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(path);
    format!("{base}{endpoint_path}")
}
/// Captures a proof's replay reservation without recording it, so a one-time
/// code can be checked before it is consumed and the `jti` recorded after.
#[derive(Default)]
pub(super) struct DeferredReplay(std::sync::Mutex<Option<crate::oauth2::DpopReplayReservation>>);
#[async_trait::async_trait]
impl crate::oauth2::DpopReplayStore for DeferredReplay {
    async fn reserve(
        &self,
        reservation: &crate::oauth2::DpopReplayReservation,
    ) -> Result<bool, crate::oauth2::DpopError> {
        if let Ok(mut pending) = self.0.lock() {
            *pending = Some(reservation.clone());
        }
        Ok(true)
    }
}
impl DeferredReplay {
    /// Record the captured reservation; a `jti` already used fails the request.
    pub(super) async fn record<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
    ) -> Result<(), EndpointError> {
        let pending = self.0.lock().ok().and_then(|mut pending| pending.take());
        let Some(mut reservation) = pending else {
            return Ok(());
        };
        reservation.now = Some(chrono::Utc::now());
        let store = crate::oauth2::create_dpop_replay_store(ctx);
        match crate::oauth2::DpopReplayStore::reserve(&store, &reservation).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(super::resource_policy::failure(
                "invalid_dpop_proof",
                "DPoP proof jti has already been used",
            )),
            Err(error) => Err(AuthError::internal(error.message).into()),
        }
    }
}
impl OAuthProviderPlugin {
    pub(super) async fn resolve_dpop_binding<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl SessionRequest,
        params: &OAuthTokenIssueParams,
        policy: &super::resource_policy::ResourceAdmission,
    ) -> Result<Option<Value>, EndpointError> {
        self.resolve_dpop_binding_with(ctx, req, params, policy, None)
            .await
    }
    pub(super) async fn resolve_dpop_binding_with<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl SessionRequest,
        params: &OAuthTokenIssueParams,
        policy: &super::resource_policy::ResourceAdmission,
        deferred: Option<&DeferredReplay>,
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
        let proof = proof_header(req);
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
        let url = endpoint_url(ctx, req, "/oauth2/token");
        let replay = crate::oauth2::create_dpop_replay_store(ctx);
        // The reference deliberately fixes htm to POST, even for a supplied
        // physical request whose method differs from the token endpoint.
        let mut options = crate::oauth2::VerifyDpopProofOptions::new(proof, "POST", &url);
        options.expected_jkt = refresh_jkt.or(code_jkt);
        options.replay_store = Some(match deferred {
            Some(deferred) => deferred,
            None => &replay,
        });
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
