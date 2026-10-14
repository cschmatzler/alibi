//! Connection-authenticated canonical SCIM reads.
use super::{ScimPlugin, Value};
use alibi_core::endpoint::{EndpointCall, EndpointResponse};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{SecondsFormat, SubsecRound};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const MARKER: &str = "x-better-auth-scim-response";
fn error(status: u16, detail: &str, scim_type: Option<&str>) -> EndpointResponse {
    let mut body = serde_json::json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":status.to_string(),"detail":detail});
    if let Some(scim_type) = scim_type {
        _ = body
            .as_object_mut()
            .map(|body| body.insert("scimType".into(), Value::String(scim_type.into())));
    }
    EndpointResponse::error(AuthError::Api {
        status,
        code: None,
        message: detail.into(),
    })
    .with_error_body(JsValue::from(body))
    .with_header(MARKER, "1")
}
fn unauthorized(detail: &str) -> EndpointResponse {
    error(401, detail, None).with_header("www-authenticate", "Bearer realm=\"SCIM\"")
}
fn identifier(value: &str) -> bool {
    let length = value.encode_utf16().count();
    (1..=255).contains(&length) && alibi_core::utils::javascript::trim(value) == value
}
fn valid_scopes(scopes: &[String]) -> bool {
    !scopes.is_empty()
        && scopes.iter().enumerate().all(|(index, scope)| {
            matches!(
                scope.as_str(),
                "scim.users.read" | "scim.users.write" | "scim.groups.read" | "scim.groups.write"
            ) && !scopes.iter().take(index).any(|previous| previous == scope)
        })
}
struct ResolvedConnection {
    id: String,
    domain: String,
    scopes: Option<Vec<String>>,
}
impl ScimPlugin {
    async fn verify_managed_bearer<S: AuthSchema>(
        &self,
        token: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<ResolvedConnection>> {
        let Some(options) = &self.managed_connections else {
            return Ok(None);
        };
        let Some((id, secret)) = token.split_once('.') else {
            return Ok(None);
        };
        let Some(suffix) = id.strip_prefix("ba_scim_credential_") else {
            return Ok(None);
        };
        let valid = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        };
        if !valid(suffix) || !valid(secret) {
            return Ok(None);
        }
        let Some(credential) = ctx.database.find_scim_managed_credential(id).await? else {
            return Ok(None);
        };
        if credential.hash_version != "v1"
            || credential.status != "active"
            || credential.expires_at.timestamp_millis() <= chrono::Utc::now().timestamp_millis()
        {
            return Ok(None);
        }
        let Ok(digest) = URL_SAFE_NO_PAD.decode(&credential.token_digest) else {
            return Ok(None);
        };
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(options.credential_hash_secret.as_bytes())
                .map_err(|error| AuthError::internal(error.to_string()))?;
        mac.update(token.as_bytes());
        if mac.verify_slice(&digest).is_err() {
            return Ok(None);
        }
        let Some(connection) = ctx
            .database
            .find_scim_active_managed_connection(&credential.connection_record_id)
            .await?
        else {
            return Ok(None);
        };
        let now = chrono::Utc::now().trunc_subsecs(3);
        let due = credential.last_used_at.is_none_or(|previous| {
            i128::from(previous.timestamp_millis())
                + i128::from(options.last_used_write_interval_seconds) * 1000
                <= i128::from(now.timestamp_millis())
        });
        if due {
            let _accounting = ctx
                .database
                .record_scim_credential_use(&credential.id, credential.last_used_at, now)
                .await;
        }
        // The reference accounts for use before parsing the persisted scope policy.
        let scopes: Vec<String> =
            serde_json::from_str(&credential.serialized_scopes).map_err(|_| AuthError::Api {
                status: 500,
                code: None,
                message: "Managed SCIM credential scope policy is invalid".into(),
            })?;
        if !valid_scopes(&scopes) {
            return Err(AuthError::Api {
                status: 500,
                code: None,
                message: "Managed SCIM credential scope policy is invalid".into(),
            });
        }
        Ok(Some(ResolvedConnection {
            id: connection.connection_id,
            domain: connection.provisioning_domain_id,
            scopes: Some(scopes),
        }))
    }
    pub(super) fn validate_connections(&self) -> AuthResult<()> {
        let mut ids = std::collections::HashSet::new();
        let mut tokens = std::collections::HashSet::new();
        for connection in &self.connections {
            if !identifier(&connection.id) {
                return Err(AuthError::config(
                    "SCIM connection ids must be trimmed and contain between 1 and 255 characters.",
                ));
            }
            if connection.id.starts_with("ba_scim_connection_") {
                return Err(AuthError::config(
                    "Static SCIM connection ids cannot use the reserved \"ba_scim_connection_\" prefix.",
                ));
            }
            if connection.credentials.is_empty() {
                return Err(AuthError::config(
                    "SCIM connections require a static credential or bearer token verifier.",
                ));
            }
            if connection
                .provisioning_domain_id
                .as_deref()
                .is_some_and(|domain| !identifier(domain))
            {
                return Err(AuthError::config(
                    "SCIM provisioning domain ids must be trimmed and contain between 1 and 255 characters.",
                ));
            }
            if !ids.insert(&connection.id) {
                return Err(AuthError::config("SCIM connection ids must be unique."));
            }
            let mut credentials = std::collections::HashSet::new();
            for credential in &connection.credentials {
                if !identifier(&credential.id) {
                    return Err(AuthError::config(
                        "SCIM credential ids must be trimmed and contain between 1 and 255 characters.",
                    ));
                }
                if !credentials.insert(&credential.id) {
                    return Err(AuthError::config(
                        "SCIM credential ids must be unique within a connection.",
                    ));
                }
                if credential.token.is_empty()
                    || credential
                        .token
                        .chars()
                        .any(alibi_core::utils::javascript::is_whitespace)
                {
                    return Err(AuthError::config(
                        "SCIM bearer tokens cannot be empty or contain whitespace.",
                    ));
                }
                if credential
                    .scopes
                    .as_ref()
                    .is_some_and(|scopes| !valid_scopes(scopes))
                {
                    return Err(AuthError::config(
                        "SCIM credential scopes must be non-empty, unique, and supported.",
                    ));
                }
                if !tokens.insert(&credential.token) {
                    return Err(AuthError::config("SCIM bearer tokens must be unique."));
                }
            }
        }
        Ok(())
    }
    pub(super) async fn get_group<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        // Query shape validation precedes authentication in the TS endpoint.
        if let Some(detail) = query_shape_error(call.query()) {
            return Ok(error(400, &detail, Some("invalidValue")));
        }
        let authorization = call
            .headers()
            .and_then(|headers| headers.get("authorization"));
        let bearer = authorization.and_then(|header| bearer_token(header));
        let Some(bearer) = bearer else {
            return Ok(unauthorized("SCIM bearer token is required"));
        };
        let mut principal = None;
        // Continue comparing all configured credentials after finding a principal.
        for connection in &self.connections {
            for credential in &connection.credentials {
                let matches = bool::from(credential.token.as_bytes().ct_eq(bearer.as_bytes()));
                let active = credential.expires_at.is_none_or(|expiry| {
                    expiry.timestamp_millis() > chrono::Utc::now().timestamp_millis()
                });
                if principal.is_none() && matches && active {
                    principal = Some((connection, credential));
                }
            }
        }
        let mut principal = principal.map(|(connection, credential)| ResolvedConnection {
            id: connection.id.clone(),
            domain: connection
                .provisioning_domain_id
                .clone()
                .unwrap_or_else(|| connection.id.clone()),
            scopes: credential.scopes.clone(),
        });
        if principal.is_none() && bearer.starts_with("ba_scim_credential_") {
            principal = match self.verify_managed_bearer(bearer, ctx).await {
                Ok(principal) => principal,
                Err(AuthError::Api {
                    status, message, ..
                }) => return Ok(error(status, &message, None)),
                Err(error) => return Err(error),
            };
        }
        let Some(connection) = principal else {
            return Ok(unauthorized("Invalid SCIM bearer token"));
        };
        let resource = if call.path().is_some_and(|path| path.contains("/Groups")) {
            "groups"
        } else {
            "users"
        };
        let operation = if call
            .method()
            .is_none_or(|method| matches!(method, HttpMethod::Get | HttpMethod::Head))
        {
            "read"
        } else {
            "write"
        };
        let required = format!("scim.{resource}.{operation}");
        if connection
            .scopes
            .as_ref()
            .is_some_and(|scopes| !scopes.contains(&required))
        {
            return Ok(error(
                403,
                &format!("The SCIM bearer token is missing the {required} scope"),
                None,
            ));
        }
        let domain = connection.domain.as_str();
        let key = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
            "scim-connection",
            &connection.id,
        ])?));
        let binding = ctx
            .database
            .active_scim_connection_binding(&connection.id, domain, &key)
            .await?;
        if binding.connection_id != connection.id || binding.provisioning_domain_id != domain {
            return Ok(error(
                409,
                "The connection provisioningDomainId changed after the connection was first used",
                None,
            ));
        }
        if binding.decommission_status != "active" {
            return Ok(unauthorized("SCIM connection is decommissioned"));
        }
        let id = call
            .params()
            .and_then(|params| params.get("groupId"))
            .and_then(JsValue::as_str)
            .unwrap_or("");
        let group = ctx.database.get_scim_group(id, &connection.id).await?;
        let Some(group) = group else {
            return Ok(error(404, "SCIM Group not found", None));
        };
        if group.provisioning_domain_id != domain {
            return Ok(error(
                409,
                "The connection provisioningDomainId changed after resources were created",
                None,
            ));
        }
        // Semantic projection errors intentionally follow resource lookup.
        let projection = match Projection::parse(call.query()) {
            Ok(value) => value,
            Err(detail) => return Ok(error(400, &detail, Some("invalidValue"))),
        };
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let mut output = serde_json::json!({"schemas":[GROUP_SCHEMA],"id":group.id,"displayName":group.display_name,
            "meta":{"resourceType":"Group","created":group.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),"lastModified":group.updated_at.to_rfc3339_opts(SecondsFormat::Millis,true),"location":resource_url(&base,"Groups",&group.id)?}});
        if let Some(external_id) = group.external_id.filter(|value| !value.is_empty()) {
            _ = output
                .as_object_mut()
                .map(|object| object.insert("externalId".into(), Value::String(external_id)));
        }
        if projection.members_requested() {
            let memberships = ctx
                .database
                .scim_group_members(&group.id, &connection.id)
                .await?;
            if memberships.persisted_count > 1000 {
                return Ok(error(
                    500,
                    "Persisted SCIM Group membership exceeds the server limit",
                    None,
                ));
            }
            let mut members = Vec::new();
            for member in memberships.members {
                members.push(serde_json::json!({"value":member.id,"$ref":resource_url(&base,"Users",&member.id)?,"display":member.display_name,"type":"User"}));
            }
            _ = output
                .as_object_mut()
                .map(|object| object.insert("members".into(), Value::Array(members)));
        }
        Ok(EndpointResponse::json(&projection.apply(output))?.with_header(MARKER, "1"))
    }
}
fn bearer_token(header: &str) -> Option<&str> {
    // JS RegExp uses its own whitespace set and excludes line terminators from '.'.
    let header = header.trim_matches(|character| matches!(character, ' ' | '\t'));
    let prefix = header.get(..6)?;
    if !prefix.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let tail = header.get(6..)?;
    if !tail
        .chars()
        .next()
        .is_some_and(alibi_core::utils::javascript::is_whitespace)
    {
        return None;
    }
    let token = tail.trim_start_matches(alibi_core::utils::javascript::is_whitespace);
    if token.is_empty()
        || token
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    Some(token)
}
fn resource_url(base: &str, kind: &str, id: &str) -> AuthResult<String> {
    // encodeURIComponent leaves these ASCII characters unescaped.
    let encoded = urlencoding::encode(id)
        .into_owned()
        .replace("%21", "!")
        .replace("%27", "'")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%2A", "*");
    let base = url::Url::parse(&format!("{base}/"))
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(base
        .join(&format!("scim/v2/{kind}/{encoded}"))
        .map_err(|error| AuthError::internal(error.to_string()))?
        .to_string())
}
fn query_shape_error(query: Option<&JsValue>) -> Option<String> {
    let query = query?;
    let JsValue::Object(_) = query else {
        return Some(format!(
            "[query] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(Some(query))
        ));
    };
    let mut errors = Vec::new();
    for name in ["attributes", "excludedAttributes"] {
        if let Some(value) = query.get(name) {
            let valid = matches!(value, JsValue::String(_))
                || matches!(value,JsValue::Array(values) if values.iter().all(|value| matches!(value,JsValue::String(_))));
            if !valid {
                errors.push(format!("[query.{name}] Invalid input"));
            }
        }
    }
    (!errors.is_empty()).then(|| errors.join("; "))
}
struct Projection {
    include: bool,
    paths: Vec<Vec<String>>,
}
impl Projection {
    fn parse(query: Option<&JsValue>) -> Result<Self, String> {
        let attributes = attribute_paths(
            query.and_then(|query| query.get("attributes")),
            "attributes",
        )?;
        let excluded = attribute_paths(
            query.and_then(|query| query.get("excludedAttributes")),
            "excludedAttributes",
        )?;
        if !attributes.is_empty() && !excluded.is_empty() {
            return Err("attributes and excludedAttributes cannot be used together".into());
        }
        Ok(Self {
            include: !attributes.is_empty(),
            paths: if attributes.is_empty() {
                excluded
            } else {
                attributes
            },
        })
    }
    fn members_requested(&self) -> bool {
        if self.include {
            self.paths
                .iter()
                .any(|path| path.first().is_some_and(|name| name == "members"))
        } else {
            !self
                .paths
                .iter()
                .any(|path| path.len() == 1 && path.first().is_some_and(|name| name == "members"))
        }
    }
    fn apply(&self, mut value: Value) -> Value {
        if self.paths.is_empty() {
            return value;
        }
        // The reference traverses a Date as an object with no enumerable keys.
        // Excluding a subattribute consequently turns that metadata Date into {}.
        if !self.include {
            for path in &self.paths {
                if path.len() > 2
                    && path.first().is_some_and(|name| name == "meta")
                    && let Some(name) = path.get(1)
                    && matches!(name.as_str(), "created" | "lastmodified")
                    && let Some(meta) = value.get_mut("meta").and_then(Value::as_object_mut)
                {
                    let name = if name == "lastmodified" {
                        "lastModified"
                    } else {
                        "created"
                    };
                    _ = meta.insert(name.into(), serde_json::json!({}));
                }
            }
        }
        let schemas = value.get("schemas").cloned();
        let id = value.get("id").cloned();
        let mut selected = select_value(&value, &self.paths, self.include)
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(object) = selected.as_object_mut() {
            if let Some(schemas) = schemas {
                _ = object.insert("schemas".into(), schemas);
            }
            if let Some(id) = id {
                _ = object.insert("id".into(), id);
            }
        }
        selected
    }
}
fn attribute_paths(input: Option<&JsValue>, parameter: &str) -> Result<Vec<Vec<String>>, String> {
    let values = match input {
        Some(JsValue::String(value)) => vec![value.as_str()],
        Some(JsValue::Array(values)) => values.iter().filter_map(JsValue::as_str).collect(),
        _ => Vec::new(),
    };
    let mut paths = Vec::new();
    for value in values {
        if alibi_core::utils::javascript::trim(value).is_empty() {
            continue;
        }
        for part in value.split(',') {
            let path = alibi_core::utils::javascript::trim(part);
            if path.is_empty()
                || path
                    .chars()
                    .any(alibi_core::utils::javascript::is_whitespace)
            {
                return Err(format!(
                    "{parameter} must be a comma-separated list of attribute paths"
                ));
            }
            let lower = path.to_lowercase();
            let normalized = lower
                .strip_prefix(&format!("{}:", GROUP_SCHEMA.to_lowercase()))
                .unwrap_or(&lower);
            let segments = normalized.split('.').map(str::to_owned).collect::<Vec<_>>();
            if !paths.contains(&segments) {
                paths.push(segments);
            }
        }
    }
    Ok(paths)
}
fn select_value(value: &Value, paths: &[Vec<String>], include: bool) -> Option<Value> {
    if paths.iter().any(Vec::is_empty) {
        return include.then(|| value.clone());
    }
    match value {
        Value::Array(values) => {
            let values = values
                .iter()
                .filter_map(|value| select_value(value, paths, include))
                .collect::<Vec<_>>();
            (!include || !values.is_empty()).then_some(Value::Array(values))
        }
        Value::Object(object) => {
            let mut selected = serde_json::Map::new();
            for (key, value) in object {
                let children = paths
                    .iter()
                    .filter(|path| path.first().is_some_and(|name| name == &key.to_lowercase()))
                    .map(|path| path.iter().skip(1).cloned().collect())
                    .collect::<Vec<_>>();
                let value = if children.is_empty() {
                    (!include).then(|| value.clone())
                } else {
                    select_value(value, &children, include)
                };
                if let Some(value) = value {
                    _ = selected.insert(key.clone(), value);
                }
            }
            (!include || !selected.is_empty()).then_some(Value::Object(selected))
        }
        _ => (!include).then(|| value.clone()),
    }
}
