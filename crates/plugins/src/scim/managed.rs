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
    if call.operation_id() == "getSCIMManagedConnection" {
        let id = body.get("connectionId");
        let Some(id) = id.and_then(JsValue::as_str) else {
            return Err(crate::endpoint::validation(format!(
                "[body.connectionId] Invalid input: expected string, received {}",
                crate::authentication_helpers::json_type(id)
            )));
        };
        if !id.starts_with("ba_scim_connection_") {
            return Err(crate::endpoint::validation(
                r#"[body.connectionId] Invalid string: must start with "ba_scim_connection_""#,
            ));
        }
        if id.encode_utf16().count() > 255 {
            return Err(crate::endpoint::validation(
                "[body.connectionId] Too big: expected string to have <=255 characters",
            ));
        }
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [
                    ("connectionId".into(), JsValue::String(id.into())),
                    (
                        "provisioningDomainId".into(),
                        JsValue::String(body_string(body, "provisioningDomainId", 1)?),
                    ),
                ]
                .into_iter()
                .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    if call.operation_id() == "listSCIMManagedConnections" {
        return Ok(EndpointInput {
            body: Some(JsValue::Object(
                [(
                    "provisioningDomainId".into(),
                    JsValue::String(body_string(body, "provisioningDomainId", 1)?),
                )]
                .into_iter()
                .collect(),
            )),
            query: call.query().cloned(),
        });
    }
    let rotating = call.operation_id() == "rotateSCIMManagedCredential";
    let mut output = indexmap::IndexMap::new();
    if rotating {
        let id = body.get("connectionId");
        let Some(id) = id.and_then(JsValue::as_str) else {
            return Err(crate::endpoint::validation(format!(
                "[body.connectionId] Invalid input: expected string, received {}",
                crate::authentication_helpers::json_type(id)
            )));
        };
        if !id.starts_with("ba_scim_connection_") {
            return Err(crate::endpoint::validation(
                r#"[body.connectionId] Invalid string: must start with "ba_scim_connection_""#,
            ));
        }
        if id.encode_utf16().count() > 255 {
            return Err(crate::endpoint::validation(
                "[body.connectionId] Too big: expected string to have <=255 characters",
            ));
        }
        _ = output.insert("connectionId".into(), JsValue::String(id.into()));
    }

    for (name, min) in [
        ("creationRequestId", 16),
        ("provisioningDomainId", 1),
        ("actorId", 1),
    ] {
        if rotating && name == "creationRequestId" {
            continue;
        }
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
    /// Trusted rotation arguments with an actual Date expiry.
    /// # Errors
    /// Returns an error if the arguments cannot be serialized.
    pub fn rotate_managed_credential_endpoint(
        input: &ScimManagedCredentialRotationInput,
    ) -> AuthResult<ServerEndpoint<Value>> {
        let mut body = JsValue::from(serde_json::to_value(input)?);
        if let JsValue::Object(values) = &mut body {
            _ = values.insert("expiresAt".into(), JsValue::Date(input.expires_at));
        }
        Ok(ServerEndpoint::new("scim", "rotateSCIMManagedCredential").with_body_value(body))
    }
    pub(super) async fn rotate_managed_credential<S: AuthSchema>(
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
        let credential_id = format!("ba_scim_credential_{}", random_string(32));
        let token = format!("{credential_id}.{}", random_string(48));
        let mut mac = Hmac::<Sha256>::new_from_slice(options.credential_hash_secret.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))?;
        mac.update(token.as_bytes());
        let digest = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let data = alibi_core::store::RotateScimManagedCredential {
            connection_id: body
                .get("connectionId")
                .and_then(JsValue::as_str)
                .ok_or_else(|| AuthError::internal("Validated ID missing"))?
                .into(),
            provisioning_domain_id: body_string(body, "provisioningDomainId", 1)?,
            actor_id: body_string(body, "actorId", 1)?,
            credential_id,
            token_digest: digest,
            serialized_scopes: serde_json::to_string(&scopes)?,
            expires_at: expires,
            created_at: Utc::now().trunc_subsecs(3),
            max_active_credentials: options.max_active_credentials,
        };
        for _ in 0..5 {
            if let Some(created) = ctx
                .database
                .rotate_scim_managed_credential(data.clone())
                .await?
            {
                let mut connection = serde_json::to_value(created.connection)?;
                if let Value::Object(values) = &mut connection {
                    _ = values.remove("id");
                    _ = values.remove("revision");
                }
                let credential = created.credential;
                return EndpointResponse::json(
                    &serde_json::json!({"connection":connection,"credential":{"credentialId":credential.credential_id,"status":credential.status,"scopes":scopes,"expiresAt":credential.expires_at,"createdAt":credential.created_at,"createdBy":credential.created_by,"lastUsedAt":credential.last_used_at,"revokedAt":credential.revoked_at,"revokedBy":credential.revoked_by},"token":token}),
                );
            }
        }
        Err(alibi_core::store::scim::scim_managed_conflict(
            "Managed SCIM connection changed repeatedly during credential rotation",
        ))
    }

    /// Read domain-owned connection metadata and its current credential policy.
    /// # Errors
    /// Returns an error if the arguments cannot be serialized.
    pub fn get_managed_connection_endpoint(
        id: &str,
        domain: &str,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "getSCIMManagedConnection")
            .with_body(&serde_json::json!({"connectionId":id,"provisioningDomainId":domain}))
    }
    pub(super) async fn get_managed_connection<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        _ = self
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
        let id = body
            .get("connectionId")
            .and_then(JsValue::as_str)
            .ok_or_else(|| AuthError::internal("Validated ID missing"))?;
        let state = ctx
            .database
            .get_scim_managed_connection(id, &body_string(body, "provisioningDomainId", 1)?)
            .await?
            .ok_or_else(|| AuthError::Api {
                status: 404,
                code: None,
                message: "Managed SCIM connection not found".into(),
            })?;
        let mut connection = serde_json::to_value(state.connection)?;
        if let Value::Object(values) = &mut connection {
            _ = values.remove("id");
            _ = values.remove("revision");
        }
        let mut credentials = Vec::new();
        for credential in state.credentials {
            let scopes: Vec<String> = serde_json::from_str(&credential.serialized_scopes)
                .map_err(|_| invalid_scope_policy())?;
            if scopes.is_empty()
                || scopes.iter().any(|scope| {
                    !matches!(
                        scope.as_str(),
                        "scim.users.read"
                            | "scim.users.write"
                            | "scim.groups.read"
                            | "scim.groups.write"
                    )
                })
                || scopes
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    != scopes.len()
            {
                return Err(invalid_scope_policy());
            }
            let status = if credential.status == "active"
                && credential.expires_at <= Utc::now().trunc_subsecs(3)
            {
                "expired"
            } else {
                &credential.status
            };
            credentials.push(serde_json::json!({"credentialId":credential.credential_id,"status":status,"scopes":scopes,"expiresAt":credential.expires_at,"createdAt":credential.created_at,"createdBy":credential.created_by,"lastUsedAt":credential.last_used_at,"revokedAt":credential.revoked_at,"revokedBy":credential.revoked_by}));
        }
        EndpointResponse::json(
            &serde_json::json!({"connection":connection,"credentials":credentials}),
        )
    }

    /// List durable connection metadata belonging to one provisioning domain.
    /// # Errors
    /// Returns an error if the input cannot be serialized.
    pub fn list_managed_connections_endpoint(domain: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("scim", "listSCIMManagedConnections")
            .with_body(&serde_json::json!({"provisioningDomainId":domain}))
    }
    pub(super) async fn list_managed_connections<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        _ = self
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
        let rows = ctx
            .database
            .list_scim_managed_connections(&body_string(body, "provisioningDomainId", 1)?)
            .await?;
        let connections = rows
            .into_iter()
            .map(|row| {
                let mut row = serde_json::to_value(row)?;
                if let Value::Object(values) = &mut row {
                    _ = values.remove("id");
                    _ = values.remove("revision");
                }
                Ok(row)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        EndpointResponse::json(&serde_json::json!({"connections":connections}))
    }

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

fn invalid_scope_policy() -> AuthError {
    AuthError::Api {
        status: 500,
        code: None,
        message: "Managed SCIM credential scope policy is invalid".into(),
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedCredentialRotationInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub actor_id: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
}
