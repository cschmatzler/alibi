use super::OAuthProviderPlugin;
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

impl OAuthProviderPlugin {
    pub(super) fn resolve_subject(
        &self,
        user_id: &str,
        client: &OAuthClient,
    ) -> AuthResult<String> {
        let Some(secret) = self
            .config
            .pairwise_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .filter(|_| {
                client.metadata.get("subject_type").and_then(Value::as_str) == Some("pairwise")
            })
        else {
            return Ok(user_id.into());
        };
        let redirect = client
            .metadata
            .get("redirect_uris")
            .and_then(Value::as_array)
            .and_then(|uris| uris.first())
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AuthError::config("Client has no redirect URIs for sector identifier")
            })?;
        let url =
            url::Url::parse(redirect).map_err(|error| AuthError::internal(error.to_string()))?;
        let sector = &url[url::Position::BeforeHost..url::Position::AfterPort];
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        mac.update(format!("{sector}.{user_id}").as_bytes());
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }

    pub(super) async fn resolve_introspection_subject<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        mut payload: Value,
        introspecting_client: &OAuthClient,
    ) -> AuthResult<Value> {
        if payload.get("active") != Some(&Value::Bool(true)) {
            return Ok(payload);
        }
        let Some(subject) = payload
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| !sub.is_empty())
        else {
            return Ok(payload);
        };
        let Some(client_id) = payload
            .get("client_id")
            .or_else(|| payload.get("azp"))
            .and_then(Value::as_str)
        else {
            return Ok(payload);
        };
        let client = if client_id == introspecting_client.client_id {
            Some(introspecting_client.clone())
        } else {
            self.get_client(ctx, client_id).await?
        };
        if let Some(client) = client {
            let resolved = self.resolve_subject(subject, &client)?;
            if let Some(subject) = payload.get_mut("sub") {
                *subject = Value::String(resolved);
            }
        }
        Ok(payload)
    }
}
