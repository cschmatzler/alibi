//! Client credential extraction and registration-bound authentication shared by protocol endpoints.
use alibi_core::endpoint::EndpointResponse;
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
pub(super) struct Credentials {
    pub(super) client_id: String,
    pub(super) secret: String,
    pub(super) method: &'static str,
}
pub(super) fn extract(body: &Value, req: &impl SessionRequest) -> Credentials {
    let mut client_id = body
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut secret = body
        .get("client_secret")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let method = if let Some(header) = req
        .physical_request()
        .and_then(|r| r.header("authorization"))
        && let Some(encoded) = header.strip_prefix("Basic ")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
        && let Ok(decoded) = String::from_utf8(decoded)
        && let Some((id, value)) = decoded.split_once(':')
    {
        client_id = urlencoding::decode(id)
            .unwrap_or_else(|_| id.into())
            .into_owned();
        secret = urlencoding::decode(value)
            .unwrap_or_else(|_| value.into())
            .into_owned();
        "client_secret_basic"
    } else if secret.is_empty() {
        "none"
    } else {
        "client_secret_post"
    };
    Credentials {
        client_id,
        secret,
        method,
    }
}
impl Credentials {
    fn denied(&self, description: &str) -> AuthResult<EndpointResponse> {
        let response = super::clients::status_protocol_error(
            if self.method == "client_secret_basic" {
                401
            } else {
                400
            },
            "invalid_client",
            description,
        )?;
        Ok(if self.method == "client_secret_basic" {
            response.with_header("WWW-Authenticate", "Basic")
        } else {
            response
        })
    }
    pub(super) async fn authenticate<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Result<OAuthClient, EndpointResponse>> {
        let Some(client) = ctx.database.get_oauth_client(&self.client_id).await? else {
            return Ok(Err(self.denied("missing client")?));
        };
        if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
            return Ok(Err(self.denied("client is disabled")?));
        }
        let registered = client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic");
        if registered != self.method {
            return Ok(Err(self.denied(&format!(
                "client registered for {registered} cannot use {}",
                self.method
            ))?));
        }
        if registered != "none" && self.secret.is_empty() {
            return Ok(Err(self.denied("client secret must be provided")?));
        }
        if !self.secret.is_empty() && client.client_secret.is_none() {
            return Ok(Err(
                self.denied("public client, client secret should not be received")?
            ));
        }
        if !self.secret.is_empty()
            && client.client_secret.as_deref()
                != Some(&URL_SAFE_NO_PAD.encode(Sha256::digest(&self.secret)))
        {
            return Ok(Err(self.denied("invalid client_secret")?));
        }
        Ok(Ok(client))
    }
}
