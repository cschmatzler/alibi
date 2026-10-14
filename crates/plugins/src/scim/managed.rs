use super::{AuthResult, ScimPlugin, Value};
use alibi_core::endpoint::{EndpointCall, EndpointInput, EndpointResponse, ServerEndpoint};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthSchema};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SubsecRound, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rand::seq::IndexedRandom;
use serde::Serialize;
use sha2::Sha256;
/// Trusted creation arguments; the expiry is a Date rather than JSON text.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnectionInput {
    pub creation_request_id: String,
    pub provisioning_domain_id: String,
    pub actor_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}
fn body_string(body: &JsValue, name: &str, min: usize) -> AuthResult<String> {
    let value = body.get(name);
    let Some(text) = value.and_then(JsValue::as_str) else {
        return Err(crate::endpoint::validation(format!(
            "[body.{name}] Invalid input: expected string, received {}",
            crate::authentication_helpers::json_type(value)
        )));
    };
    let text = alibi_core::utils::javascript::trim(text);
    let length = text.encode_utf16().count();
    if length < min {
        return Err(crate::endpoint::validation(format!(
            "[body.{name}] Too small: expected string to have >={min} characters"
        )));
    }
    if length > 255 {
        return Err(crate::endpoint::validation(format!(
            "[body.{name}] Too big: expected string to have <=255 characters"
        )));
    }
    Ok(text.into())
}
pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = call.body().ok_or_else(|| {
        crate::endpoint::validation("[body] Invalid input: expected object, received undefined")
    })?;
    let mut output = indexmap::IndexMap::new();
    for (name, min) in [
        ("creationRequestId", 16),
        ("provisioningDomainId", 1),
        ("actorId", 1),
    ] {
        _ = output.insert(name.into(), JsValue::String(body_string(body, name, min)?));
    }
    let scopes = body.get("scopes");
    let Some(values) = scopes.and_then(JsValue::as_array) else {
        return Err(crate::endpoint::validation(format!(
            "[body.scopes] Invalid input: expected array, received {}",
            crate::authentication_helpers::json_type(scopes)
        )));
    };
    if values.is_empty() {
        return Err(crate::endpoint::validation(
            "[body.scopes] Too small: expected array to have >=1 items",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        if !value.as_str().is_some_and(|scope| {
            matches!(
                scope,
                "scim.users.read" | "scim.users.write" | "scim.groups.read" | "scim.groups.write"
            )
        }) {
            return Err(crate::endpoint::validation(format!(
                r#"[body.scopes.{index}] Invalid option: expected one of "scim.users.read"|"scim.users.write"|"scim.groups.read"|"scim.groups.write""#
            )));
        }
    }
    _ = output.insert("scopes".into(), JsValue::Array(values.to_vec()));
    let expiry = body.get("expiresAt");
    let Some(date) = expiry.and_then(JsValue::as_date) else {
        return Err(crate::endpoint::validation(format!(
            "[body.expiresAt] Invalid input: expected date, received {}",
            crate::authentication_helpers::json_type(expiry)
        )));
    };
    _ = output.insert("expiresAt".into(), JsValue::Date(date.trunc_subsecs(3)));
    Ok(EndpointInput {
        body: Some(JsValue::Object(output)),
        query: call.query().cloned(),
    })
}
fn random_string(length: usize) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from(*alphabet.choose(&mut rng).unwrap_or(&b'a')))
        .collect()
}
impl ScimPlugin {
    /// Create a managed connection and one independently hashed bearer credential.
    /// # Errors
    /// Returns an error if the arguments cannot be represented as logical input.
    pub fn create_managed_connection_endpoint(
        input: &ScimManagedConnectionInput,
    ) -> AuthResult<ServerEndpoint<Value>> {
        let mut body = JsValue::from(serde_json::to_value(input)?);
        if let JsValue::Object(values) = &mut body {
            _ = values.insert("expiresAt".into(), JsValue::Date(input.expires_at));
        }
        Ok(ServerEndpoint::new("scim", "createSCIMManagedConnection").with_body_value(body))
    }
    pub(super) async fn create_managed_connection<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        call.queue_response_header("cache-control", "no-store");
        call.queue_response_header("pragma", "no-cache");
        let options = self
            .managed_connections
            .as_ref()
            .ok_or_else(|| AuthError::Api {
                status: 400,
                code: None,
                message: "SCIM managed connections are not configured".into(),
            })?;
        let body = call
            .body()
            .ok_or_else(|| AuthError::internal("Validated body missing"))?;
        let expires = *body
            .get("expiresAt")
            .and_then(JsValue::as_date)
            .ok_or_else(|| AuthError::internal("Validated expiry missing"))?;
        if expires <= Utc::now().trunc_subsecs(3) {
            return Err(AuthError::Api {
                status: 400,
                code: None,
                message: "Managed SCIM credential expiry must be in the future".into(),
            });
        }
        let scopes = body
            .get("scopes")
            .and_then(JsValue::as_array)
            .ok_or_else(|| AuthError::internal("Validated scopes missing"))?
            .iter()
            .filter_map(JsValue::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if scopes
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != scopes.len()
        {
            return Err(AuthError::Api {
                status: 400,
                code: None,
                message: "Managed SCIM credential scopes must be unique".into(),
            });
        }
        let connection_id = format!("ba_scim_connection_{}", random_string(32));
        let credential_id = format!("ba_scim_credential_{}", random_string(32));
        let token = format!("{credential_id}.{}", random_string(48));
        let mut mac = Hmac::<Sha256>::new_from_slice(options.credential_hash_secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        mac.update(token.as_bytes());
        let digest = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let created = ctx
            .database
            .create_scim_managed_connection(alibi_core::store::CreateScimManagedConnection {
                creation_request_id: body_string(body, "creationRequestId", 16)?,
                connection_id,
                provisioning_domain_id: body_string(body, "provisioningDomainId", 1)?,
                actor_id: body_string(body, "actorId", 1)?,
                credential_id,
                token_digest: digest,
                serialized_scopes: serde_json::to_string(&scopes)?,
                expires_at: expires,
                created_at: Utc::now().trunc_subsecs(3),
            })
            .await?;
        let mut connection = serde_json::to_value(created.connection)?;
        if let Value::Object(fields) = &mut connection {
            _ = fields.remove("id");
            _ = fields.remove("revision");
        }
        let credential = created.credential;
        EndpointResponse::json(
            &serde_json::json!({"connection":connection,"credential":{"credentialId":credential.credential_id,"status":credential.status,"scopes":scopes,"expiresAt":credential.expires_at,"createdAt":credential.created_at,"createdBy":credential.created_by,"lastUsedAt":credential.last_used_at,"revokedAt":credential.revoked_at,"revokedBy":credential.revoked_by},"token":token}),
        )
    }
}
