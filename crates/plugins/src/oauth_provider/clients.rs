use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngExt as _, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Metadata accepted when an authenticated owner registers a managed client.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateOAuthClientInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens: Option<bool>,
}
impl OAuthProviderPlugin {
    pub fn create_oauth_client_endpoint(
        input: &CreateOAuthClientInput,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "createOAuthClient").with_body(input)
    }
    pub(super) async fn create_client<S: AuthSchema>(
        &self,
        input: CreateOAuthClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        if req
            .endpoint_call()
            .is_some_and(|call| call.headers().is_none())
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 400,
                code: None,
                message: String::new(),
            })
            .without_error_body());
        }
        req.queue_response_header("Cache-Control", "no-store");
        req.queue_response_header("Pragma", "no-cache");
        let mut metadata: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::to_value(input)?)?;
        let auth = metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic")
            .to_owned();
        if ![
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ]
        .contains(&auth.as_str())
        {
            return protocol_error(
                "invalid_client_metadata",
                format!("unsupported token_endpoint_auth_method {auth}"),
            );
        }
        let grants = metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![json!("authorization_code")]);
        for grant in &grants {
            if !grant.as_str().is_some_and(|grant| {
                self.config
                    .grant_types
                    .iter()
                    .any(|supported| supported == grant)
            }) {
                return protocol_error(
                    "invalid_client_metadata",
                    format!(
                        "unsupported grant_type {}",
                        grant.as_str().unwrap_or_default()
                    ),
                );
            }
        }
        let code_grant = grants.contains(&json!("authorization_code"));
        let redirects = metadata
            .get("redirect_uris")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if code_grant && redirects.is_empty() {
            return protocol_error(
                "invalid_redirect_uri",
                "Redirect URIs are required for authorization_code and implicit grant types",
            );
        }
        let application = metadata
            .get("application_type")
            .and_then(Value::as_str)
            .unwrap_or("web");
        for redirect in &redirects {
            if let Some(error) = redirect_error(redirect.as_str().unwrap_or_default(), application)
            {
                return protocol_error("invalid_redirect_uri", error);
            }
        }
        let responses = metadata
            .get("response_types")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| code_grant.then(|| vec![json!("code")]));
        if code_grant
            && !responses
                .as_ref()
                .is_some_and(|responses| responses.contains(&json!("code")))
        {
            return protocol_error(
                "invalid_client_metadata",
                "When 'authorization_code' grant type is used, 'code' response type must be included",
            );
        }
        if !code_grant
            && responses
                .as_ref()
                .is_some_and(|responses| responses.contains(&json!("code")))
        {
            return protocol_error(
                "invalid_client_metadata",
                "When 'code' response type is used, 'authorization_code' grant type must be included",
            );
        }
        if let Some(scope) = metadata.get("scope").and_then(Value::as_str) {
            for scope in scope.split(' ').filter(|scope| !scope.is_empty()) {
                if !self.config.scopes.iter().any(|allowed| allowed == scope) {
                    return protocol_error(
                        "invalid_scope",
                        format!("cannot request scope {scope}"),
                    );
                }
            }
        }
        if metadata.contains_key("jwks") && metadata.contains_key("jwks_uri") {
            return protocol_error(
                "invalid_client_metadata",
                "jwks and jwks_uri are mutually exclusive",
            );
        }
        if let Some(uri) = metadata.get("jwks_uri").and_then(Value::as_str)
            && let Some(error) = remote_key_uri_error(uri, ctx)
        {
            return protocol_error("invalid_client_metadata", error);
        }
        if let Some(jwks) = metadata.get("jwks")
            && let Some(error) = public_jwks_error(jwks)
        {
            return protocol_error("invalid_client_metadata", error);
        }
        if auth == "private_key_jwt"
            && !metadata.contains_key("jwks")
            && !metadata.contains_key("jwks_uri")
        {
            return protocol_error(
                "invalid_client_metadata",
                "private_key_jwt requires either jwks or jwks_uri",
            );
        }
        if let Some(uri) = metadata
            .get("backchannel_logout_uri")
            .and_then(Value::as_str)
        {
            if self.config.disable_jwt_plugin {
                return protocol_error(
                    "invalid_client_metadata",
                    "backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)",
                );
            }
            if let Some(error) = backchannel_uri_error(uri) {
                return protocol_error("invalid_client_metadata", error);
            }
        }
        _ = metadata.insert("token_endpoint_auth_method".into(), json!(auth));
        _ = metadata
            .entry("application_type")
            .or_insert_with(|| json!("web"));
        _ = metadata.insert("grant_types".into(), json!(grants));
        if let Some(responses) = responses {
            _ = metadata.insert("response_types".into(), json!(responses));
        }
        _ = metadata.insert("redirect_uris".into(), json!(redirects));
        _ = metadata.insert("disabled".into(), json!(false));
        _ = metadata
            .entry("dpop_bound_access_tokens")
            .or_insert_with(|| json!(false));
        let client_id = random_credential();
        let plaintext =
            (!["none", "private_key_jwt"].contains(&auth.as_str())).then(random_credential);
        let stored = plaintext
            .as_deref()
            .map(|secret| {
                if self.config.disable_jwt_plugin {
                    crate::token_crypto::encrypt_with_config(secret, &ctx.config)
                } else {
                    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes())))
                }
            })
            .transpose()?;
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid client creation timestamp"))?;
        let user_id = user.id().as_ref().to_owned();
        let client = ctx
            .database
            .create_oauth_client(alibi_core::store::CreateOAuthClient {
                client_id,
                user_id: Some(user_id),
                client_secret: stored,
                metadata: Value::Object(metadata),
                created_at: now,
            })
            .await?;
        let mut output: serde_json::Map<String, Value> = serde_json::from_value(client.metadata)?;
        _ = output.insert("client_id".into(), json!(client.client_id));
        _ = output.insert("user_id".into(), json!(client.user_id));
        _ = output.insert(
            "client_id_issued_at".into(),
            json!(client.created_at.timestamp()),
        );
        if let Some(secret) = plaintext {
            _ = output.insert("client_secret".into(), json!(secret));
            _ = output.insert("client_secret_expires_at".into(), json!(0));
        }
        Ok(EndpointResponse::json(&Value::Object(output))?.with_status(201))
    }
}
fn random_credential() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .map(char::from)
        .filter(char::is_ascii_alphabetic)
        .take(32)
        .collect()
}
fn protocol_error(error: &str, description: impl Into<String>) -> AuthResult<EndpointResponse> {
    Ok(EndpointResponse::error(AuthError::Api {
        status: 400,
        code: None,
        message: String::new(),
    })
    .with_error_body(alibi_core::utils::json::parse_value(
        &serde_json::to_string(&json!({"error":error,"error_description":description.into()}))?,
    )?))
}
fn redirect_error(uri: &str, application: &str) -> Option<String> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some(format!("redirect URI must be an absolute URI: {uri}"));
    };
    if uri.contains('#')
        || !url.username().is_empty()
        || url.password().is_some_and(|value| !value.is_empty())
    {
        return Some(format!(
            "redirect URI must not include credentials or a fragment: {uri}"
        ));
    }
    let host = url.host_str().unwrap_or_default();
    if host.trim_end_matches('.') == "localhost" && host.ends_with('.') {
        return Some(format!(
            "redirect URI localhost must not include trailing dots: {uri}"
        ));
    }
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
        || host == "[::1]";
    if application == "web" {
        return (url.scheme() != "https" || loopback).then(|| {
            format!("web clients require https redirect URIs on non-loopback hosts: {uri}")
        });
    }
    if url.scheme() == "https" {
        return loopback
            .then(|| format!("native clients must not use https loopback redirect URIs: {uri}"));
    }
    if url.scheme() == "http" {
        return (!["localhost","127.0.0.1","[::1]"].contains(&host)).then(||format!("native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: {uri}"));
    }
    let scheme = url.scheme();
    let labels = scheme.split('.').collect::<Vec<_>>();
    let reverse = labels.len() > 1
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    let private = uri
        .strip_prefix(&format!("{scheme}:"))
        .is_some_and(|path| path.starts_with('/') && !path.starts_with("//"));
    (!reverse||!private||["file","ftp","mailto","javascript","data","vbscript"].contains(&scheme)).then(||format!("native private-use redirect URI schemes must be well-formed reverse-domain names, omit the naming authority, and must not use a reserved scheme: {uri}"))
}
fn private_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || !host.contains('.')
    {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    })
}
fn remote_key_uri_error<S: AuthSchema>(uri: &str, ctx: &AuthContext<S>) -> Option<String> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some("jwks_uri must be a valid URL".into());
    };
    if url.scheme() != "https" {
        return Some("jwks_uri must use HTTPS".into());
    }
    if !url.username().is_empty() || url.password().is_some_and(|value| !value.is_empty()) {
        return Some("jwks_uri must not contain credentials".into());
    }
    if uri.contains('#') {
        return Some("jwks_uri must not include a fragment component".into());
    }
    if private_host(url.host_str().unwrap_or_default()) {
        return Some("jwks_uri must not point to a private or reserved address".into());
    }
    (!ctx.config.is_redirect_target_trusted(uri)).then(|| {
        "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin".into()
    })
}
fn backchannel_uri_error(uri: &str) -> Option<String> {
    let Ok(url) = url::Url::parse(uri) else {
        return Some("backchannel_logout_uri must be an absolute URL".into());
    };
    if uri.contains('#') {
        return Some("backchannel_logout_uri must not include a fragment component".into());
    }
    if url.scheme() != "https" {
        return Some("backchannel_logout_uri must use https".into());
    }
    if !url.username().is_empty() || url.password().is_some_and(|value| !value.is_empty()) {
        return Some("backchannel_logout_uri must not contain credentials".into());
    }
    private_host(url.host_str().unwrap_or_default())
        .then(|| "backchannel_logout_uri must not point to a private or reserved address".into())
}
fn public_jwks_error(value: &Value) -> Option<&'static str> {
    let keys = value.get("keys").and_then(Value::as_array)?;
    for key in keys {
        if ["k", "d", "p", "q", "dp", "dq", "qi", "oth"]
            .iter()
            .any(|name| key.get(name).is_some())
            || key.get("kty").and_then(Value::as_str) == Some("oct")
        {
            return Some("jwks must contain only public asymmetric keys");
        }
        let string = |name| {
            key.get(name)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        };
        let curve = key.get("crv").and_then(Value::as_str).unwrap_or_default();
        let kind = key.get("kty").and_then(Value::as_str).unwrap_or_default();
        let valid = match kind {
            "RSA" => string("n") && string("e"),
            "EC" => ["P-256", "P-384", "P-521"].contains(&curve) && string("x") && string("y"),
            "OKP" => curve == "Ed25519" && string("x"),
            _ => false,
        };
        if !valid {
            return Some("jwks keys must be supported public JWKs with required key parameters");
        }
        if let Some(algorithm) = key.get("alg") {
            let valid = algorithm.as_str().is_some_and(|alg| match kind {
                "RSA" => ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"].contains(&alg),
                "EC" => matches!(
                    (curve, alg),
                    ("P-256", "ES256") | ("P-384", "ES384") | ("P-521", "ES512")
                ),
                "OKP" => alg == "EdDSA",
                _ => false,
            });
            if !valid {
                return Some(
                    "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve",
                );
            }
        }
    }
    None
}
#[derive(Clone, Copy)]
enum FieldKind {
    String,
    Boolean,
    Uris,
    Uri,
    Contacts,
    Method,
    Application,
    Jwks,
    Grants,
    Responses,
}
const FIELDS: &[(&str, FieldKind)] = &[
    ("redirect_uris", FieldKind::Uris),
    ("scope", FieldKind::String),
    ("client_name", FieldKind::String),
    ("client_uri", FieldKind::String),
    ("logo_uri", FieldKind::String),
    ("contacts", FieldKind::Contacts),
    ("tos_uri", FieldKind::String),
    ("policy_uri", FieldKind::String),
    ("software_id", FieldKind::String),
    ("software_version", FieldKind::String),
    ("software_statement", FieldKind::String),
    ("post_logout_redirect_uris", FieldKind::Uris),
    ("backchannel_logout_uri", FieldKind::Uri),
    ("backchannel_logout_session_required", FieldKind::Boolean),
    ("token_endpoint_auth_method", FieldKind::Method),
    ("application_type", FieldKind::Application),
    ("jwks", FieldKind::Jwks),
    ("jwks_uri", FieldKind::String),
    ("grant_types", FieldKind::Grants),
    ("response_types", FieldKind::Responses),
    ("dpop_bound_access_tokens", FieldKind::Boolean),
];
pub(super) fn validate(body: Option<&JsValue>) -> AuthResult<JsValue> {
    let Some(object) = body.and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[body] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(body)
        )));
    };
    let mut issues = Vec::new();
    let mut output = indexmap::IndexMap::new();
    for (name, kind) in FIELDS {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let path = format!("body.{name}");
        validate_field(*kind, value, &path, &mut issues);
        let normalized = match (kind, value) {
            (FieldKind::Method, JsValue::String(value)) => JsValue::String(value.trim().into()),
            (FieldKind::Grants, JsValue::Array(values)) => JsValue::Array(
                values
                    .iter()
                    .map(|value| {
                        value.as_str().map_or_else(
                            || value.clone(),
                            |text| JsValue::String(text.trim().into()),
                        )
                    })
                    .collect(),
            ),
            (FieldKind::Jwks, JsValue::Object(object)) => JsValue::Object(
                object
                    .iter()
                    .filter(|(name, _)| name.as_str() == "keys")
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            ),
            _ => value.clone(),
        };
        _ = output.insert((*name).into(), normalized);
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    Ok(JsValue::Object(output))
}
fn validate_field(kind: FieldKind, value: &JsValue, path: &str, issues: &mut Vec<String>) {
    use crate::authentication_helpers::{JsonFieldKind, field_issue, json_type};
    let mut add = |issue: String| issues.push(format!("[{path}] {issue}"));
    match kind {
        FieldKind::String | FieldKind::Method | FieldKind::Uri => {
            if let Some(issue) =
                field_issue(JsonFieldKind::String, Some(value), json_type(Some(value)))
            {
                add(issue);
                return;
            }
            if let Some(text) = value.as_str() {
                if matches!(kind, FieldKind::Method) && text.trim().is_empty() {
                    add("Too small: expected string to have >=1 characters".into());
                }
                if matches!(kind, FieldKind::Uri) {
                    for issue in safe_uri_issues(text) {
                        add(issue.into());
                    }
                }
            }
        }
        FieldKind::Boolean => {
            if let Some(issue) =
                field_issue(JsonFieldKind::Boolean, Some(value), json_type(Some(value)))
            {
                add(issue);
            }
        }
        FieldKind::Application => {
            if ![Some("web"), Some("native")].contains(&value.as_str()) {
                add("Invalid option: expected one of \"web\"|\"native\"".into());
            }
        }
        FieldKind::Uris | FieldKind::Contacts | FieldKind::Grants | FieldKind::Responses => {
            let JsValue::Array(values) = value else {
                add(format!(
                    "Invalid input: expected array, received {}",
                    json_type(Some(value))
                ));
                return;
            };
            if values.is_empty() && !matches!(kind, FieldKind::Responses) {
                add("Too small: expected array to have >=1 items".into());
            }
            for (index, value) in values.iter().enumerate() {
                let item_path = format!("{path}.{index}");
                if matches!(kind, FieldKind::Responses) {
                    if value.as_str() != Some("code") {
                        issues.push(format!("[{item_path}] Invalid input: expected \"code\""));
                    }
                    continue;
                }
                if let Some(issue) =
                    field_issue(JsonFieldKind::String, Some(value), json_type(Some(value)))
                {
                    issues.push(format!("[{item_path}] {issue}"));
                    continue;
                }
                if let Some(text) = value.as_str() {
                    if matches!(kind, FieldKind::Contacts) && text.is_empty()
                        || matches!(kind, FieldKind::Grants) && text.trim().is_empty()
                    {
                        issues.push(format!(
                            "[{item_path}] Too small: expected string to have >=1 characters"
                        ));
                    }
                    if matches!(kind, FieldKind::Uris) {
                        for issue in safe_uri_issues(text) {
                            issues.push(format!("[{item_path}] {issue}"));
                        }
                    }
                }
            }
        }
        FieldKind::Jwks => {
            let Some(object) = value.as_object() else {
                add(format!(
                    "Invalid input: expected object, received {}",
                    json_type(Some(value))
                ));
                return;
            };
            let keys = object.get("keys");
            let Some(JsValue::Array(values)) = keys else {
                issues.push(format!(
                    "[{path}.keys] Invalid input: expected array, received {}",
                    json_type(keys)
                ));
                return;
            };
            if values.is_empty() {
                issues.push(format!(
                    "[{path}.keys] Too small: expected array to have >=1 items"
                ));
            }
            for (index, value) in values.iter().enumerate() {
                if !matches!(value, JsValue::Object(_)) {
                    issues.push(format!(
                        "[{path}.keys.{index}] Invalid input: expected record, received {}",
                        json_type(Some(value))
                    ));
                }
            }
        }
    }
}
fn safe_uri_issues(uri: &str) -> Vec<&'static str> {
    let Ok(url) = url::Url::parse(uri) else {
        return vec!["Invalid URL"];
    };
    if ["javascript", "data", "vbscript"].contains(&url.scheme()) {
        return vec!["URL cannot use javascript:, data:, or vbscript: scheme"];
    }
    let mut issues = Vec::new();
    if uri.contains('#') {
        issues.push("Redirect URI must not contain a fragment component");
    }
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() == "http" && !loopback {
        issues.push("Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)");
    }
    issues
}
