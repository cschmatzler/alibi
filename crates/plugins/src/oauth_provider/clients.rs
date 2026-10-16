use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::javascript::trim as js_trim;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use rand::{RngExt as _, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
        let metadata: serde_json::Map<String, Value> =
            serde_json::from_value(serde_json::to_value(input)?)?;
        let metadata = match self.admit_metadata(metadata, ctx)? {
            Ok(metadata) => metadata,
            Err(response) => return Ok(response),
        };
        self.persist_client(metadata, Some(user.id().as_ref().to_owned()), ctx)
            .await
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
        let raw_host = raw_http_host(uri);
        return (!raw_host.as_deref().is_some_and(|host|["localhost","127.0.0.1","[::1]"].contains(&host))).then(||format!("native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: {uri}"));
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
fn raw_http_host(uri: &str) -> Option<String> {
    if !uri
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        return None;
    }
    let authority = uri.get(7..)?.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    if host.starts_with('[') {
        host.find(']')
            .and_then(|end| host.get(..=end))
            .map(str::to_ascii_lowercase)
    } else {
        host.split(':').next().map(str::to_ascii_lowercase)
    }
}
fn private_host(host: &str) -> bool {
    !crate::sso::endpoint_host::public(host)
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
pub(super) fn public_jwks_error(value: &Value) -> Option<&'static str> {
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
    Scopes,
    Subject,
    Expiration,
    Record,
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
    validate_metadata(body, "body", FIELDS)
}
fn validate_metadata(
    body: Option<&JsValue>,
    location: &str,
    fields: &[(&str, FieldKind)],
) -> AuthResult<JsValue> {
    let Some(object) = body.and_then(JsValue::as_object) else {
        return Err(crate::endpoint::validation(format!(
            "[{location}] Invalid input: expected object, received {}",
            crate::authentication_helpers::json_type(body)
        )));
    };
    let mut issues = Vec::new();
    let mut output = indexmap::IndexMap::new();
    for (name, kind) in fields {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let path = format!("{location}.{name}");
        let normalized = match (kind, value) {
            // SafeUrlSchema's z.url() trims JS whitespace without reserializing the URL.
            (FieldKind::Uri, JsValue::String(value)) => JsValue::String(js_trim(value).into()),
            (FieldKind::Uris, JsValue::Array(values)) => JsValue::Array(
                values
                    .iter()
                    .map(|value| {
                        value.as_str().map_or_else(
                            || value.clone(),
                            |text| JsValue::String(js_trim(text).into()),
                        )
                    })
                    .collect(),
            ),
            (FieldKind::Method, JsValue::String(value)) => JsValue::String(value.trim().into()),
            (FieldKind::Grants | FieldKind::Scopes, JsValue::Array(values)) => JsValue::Array(
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
        validate_field(*kind, &normalized, &path, &mut issues);
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
        FieldKind::Uris
        | FieldKind::Contacts
        | FieldKind::Grants
        | FieldKind::Responses
        | FieldKind::Scopes => {
            let JsValue::Array(values) = value else {
                add(format!(
                    "Invalid input: expected array, received {}",
                    json_type(Some(value))
                ));
                return;
            };
            if values.is_empty() && !matches!(kind, FieldKind::Responses | FieldKind::Scopes) {
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
                        || matches!(kind, FieldKind::Grants | FieldKind::Scopes)
                            && text.trim().is_empty()
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
        FieldKind::Subject => {
            if ![Some("public"), Some("pairwise")].contains(&value.as_str()) {
                add("Invalid option: expected one of \"public\"|\"pairwise\"".into());
            }
        }
        FieldKind::Expiration => {
            if !matches!(value, JsValue::String(_) | JsValue::Number(_)) {
                add("Invalid input".into());
            }
        }
        FieldKind::Record => {
            if value.as_object().is_none() {
                add(format!(
                    "Invalid input: expected record, received {}",
                    json_type(Some(value))
                ));
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

#[derive(Debug, Deserialize)]
pub(super) struct ReadClientInput {
    pub client_id: String,
}
pub(super) fn validate_read(query: Option<&JsValue>) -> AuthResult<JsValue> {
    crate::endpoint::validate_fields(
        query,
        "query",
        &[crate::authentication_helpers::JsonField::string(
            "client_id",
            true,
        )],
    )
}
impl OAuthProviderPlugin {
    /// Read an owned client without exposing its stored credential.
    pub fn get_oauth_client_endpoint(client_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "getOAuthClient")
            .with_query(&json!({"client_id":client_id}))
    }
    pub(super) async fn read_client<S: AuthSchema>(
        &self,
        input: ReadClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        let Some(client) = super::discovery::resolve(ctx, &input.client_id).await? else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"not_found","error_description":"client not found"}"#,
            )?));
        };
        if client.user_id.as_deref() != Some(user.id().as_ref()) {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        EndpointResponse::json(&client_read_metadata(client)?)
    }
}

impl OAuthProviderPlugin {
    /// Read public display fields for any authenticated user.
    pub fn get_oauth_client_public_endpoint(client_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "getOAuthClientPublic")
            .with_query(&json!({"client_id":client_id}))
    }
    pub(super) async fn read_public_client<S: AuthSchema>(
        &self,
        input: ReadClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        _ = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        Box::pin(self.public_client_projection(&input.client_id, ctx)).await
    }
    async fn public_client_projection<S: AuthSchema>(
        &self,
        client_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let client = super::discovery::resolve(ctx, client_id).await?;

        let Some(client) =
            client.filter(|client| client.metadata.get("disabled") != Some(&json!(true)))
        else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"not_found","error_description":"client not found"}"#,
            )?));
        };
        let mut display = serde_json::Map::new();
        for name in [
            "client_name",
            "client_uri",
            "logo_uri",
            "contacts",
            "tos_uri",
            "policy_uri",
        ] {
            if let Some(value) = client.metadata.get(name) {
                _ = display.insert(name.into(), value.clone());
            }
        }
        _ = display.insert("client_id".into(), json!(client.client_id));
        _ = display.insert("redirect_uris".into(), json!([]));
        EndpointResponse::json(&Value::Object(display))
    }
}

fn client_read_metadata(client: alibi_core::store::OAuthClient) -> AuthResult<Value> {
    let mut output: serde_json::Map<String, Value> = serde_json::from_value(client.metadata)?;
    _ = output.insert("client_id".into(), json!(client.client_id));
    _ = output.insert("user_id".into(), json!(client.user_id));
    _ = output.insert(
        "client_id_issued_at".into(),
        json!(client.created_at.map(|time| time.timestamp())),
    );
    if client.client_secret.is_some() {
        _ = output
            .entry("client_secret_expires_at")
            .or_insert_with(|| json!(0));
    }
    _ = output.remove("client_secret");
    _ = output.remove("client_credentials_scopes");
    Ok(Value::Object(output))
}
impl OAuthProviderPlugin {
    /// List durable clients belonging to the authenticated user.
    #[must_use]
    pub fn get_oauth_clients_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "getOAuthClients")
    }
    pub(super) async fn list_clients<S: AuthSchema>(
        &self,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        let clients = ctx
            .database
            .list_oauth_clients_by_user(user.id().as_ref())
            .await?;
        let output: Vec<Value> = clients
            .into_iter()
            .map(client_read_metadata)
            .collect::<AuthResult<_>>()?;
        EndpointResponse::json(&output)
    }
}

impl OAuthProviderPlugin {
    /// Delete a durable client owned by the authenticated user.
    pub fn delete_oauth_client_endpoint(client_id: &str) -> AuthResult<ServerEndpoint<()>> {
        ServerEndpoint::new("oauth-provider", "deleteOAuthClient")
            .with_body(&json!({"client_id":client_id}))
    }
    pub(super) async fn delete_client<S: AuthSchema>(
        &self,
        input: ReadClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        if self
            .config
            .cached_trusted_clients
            .contains(&input.client_id)
        {
            return status_protocol_error(
                500,
                "invalid_client",
                "trusted clients must be updated manually",
            );
        }
        let Some(client) = super::discovery::resolve(ctx, &input.client_id).await? else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"not_found","error_description":"client not found"}"#,
            )?));
        };
        if client.user_id.as_deref() != Some(user.id().as_ref()) {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        ctx.database.delete_oauth_client(&input.client_id).await?;
        Ok(EndpointResponse::empty().with_header("Content-Type", "application/json"))
    }
}
pub(super) fn validate_delete(body: Option<&JsValue>) -> AuthResult<JsValue> {
    crate::endpoint::validate_fields(
        body,
        "body",
        &[crate::authentication_helpers::JsonField::string(
            "client_id",
            true,
        )],
    )
}

impl OAuthProviderPlugin {
    /// Rotate an owned confidential client secret and reveal its replacement once.
    pub fn rotate_client_secret_endpoint(client_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "rotateClientSecret")
            .with_body(&json!({"client_id":client_id}))
    }
    pub(super) async fn rotate_client_secret<S: AuthSchema>(
        &self,
        input: ReadClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = Box::pin(crate::helpers::ordinary_session(req, ctx)).await?;
        req.queue_response_header("Cache-Control", "no-store");
        req.queue_response_header("Pragma", "no-cache");
        if self
            .config
            .cached_trusted_clients
            .contains(&input.client_id)
        {
            return status_protocol_error(
                500,
                "invalid_client",
                "trusted clients must be updated manually",
            );
        }
        let Some(client) = super::discovery::resolve(ctx, &input.client_id).await? else {
            return status_protocol_error(404, "not_found", "client not found");
        };
        if client.user_id.as_deref() != Some(user.id().as_ref()) {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        if client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            == Some("none")
            || client.client_secret.is_none()
        {
            return status_protocol_error(
                400,
                "invalid_client",
                "secret rotation is only available for clients using client_secret authentication",
            );
        }
        let plaintext = self.generate_client_secret()?;
        let protected = super::client_secret::store(ctx, &self.config, &plaintext).await?;
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid client update timestamp"))?;
        let Some(client) = ctx
            .database
            .update_oauth_client_secret(&input.client_id, protected, now)
            .await?
        else {
            return status_protocol_error(500, "invalid_client", "unable to update client");
        };
        let mut output = client_read_metadata(client)?;
        _ = output
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("OAuth client metadata must be an object"))?
            .insert(
                "client_secret".into(),
                Value::String(self.prefixed_client_secret(plaintext)),
            );
        EndpointResponse::json(&output)
    }
}
pub(super) fn status_protocol_error(
    status: u16,
    error: &str,
    description: &str,
) -> AuthResult<EndpointResponse> {
    Ok(EndpointResponse::error(AuthError::Api {
        status,
        code: None,
        message: String::new(),
    })
    .with_error_body(alibi_core::utils::json::parse_value(
        &serde_json::to_string(&json!({"error":error,"error_description":description}))?,
    )?))
}

impl OAuthProviderPlugin {
    fn admit_metadata<S: AuthSchema>(
        &self,
        mut metadata: serde_json::Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Result<serde_json::Map<String, Value>, EndpointResponse>> {
        let auth = metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic")
            .to_owned();
        if !self.supported_auth_methods(true).contains(&auth) {
            return protocol_error(
                "invalid_client_metadata",
                format!("unsupported token_endpoint_auth_method {auth}"),
            )
            .map(Err);
        }
        let grants = metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![json!("authorization_code")]);
        for grant in &grants {
            if !grant.as_str().is_some_and(|grant| {
                self.supported_grant_types()
                    .iter()
                    .any(|supported| supported == grant)
            }) {
                return protocol_error(
                    "invalid_client_metadata",
                    format!(
                        "unsupported grant_type {}",
                        grant.as_str().unwrap_or_default()
                    ),
                )
                .map(Err);
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
            )
            .map(Err);
        }
        let application = metadata
            .get("application_type")
            .and_then(Value::as_str)
            .unwrap_or("web");
        for redirect in &redirects {
            if let Some(error) = redirect_error(redirect.as_str().unwrap_or_default(), application)
            {
                return protocol_error("invalid_redirect_uri", error).map(Err);
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
            ).map(Err);
        }
        if !code_grant
            && responses
                .as_ref()
                .is_some_and(|responses| responses.contains(&json!("code")))
        {
            return protocol_error(
                "invalid_client_metadata",
                "When 'code' response type is used, 'authorization_code' grant type must be included",
            ).map(Err);
        }
        if metadata.get("subject_type").and_then(Value::as_str) == Some("pairwise") {
            if self
                .config
                .pairwise_secret
                .as_ref()
                .is_none_or(String::is_empty)
            {
                return protocol_error(
                    "invalid_client_metadata",
                    "pairwise subject_type requires server pairwiseSecret configuration",
                )
                .map(Err);
            }
            let mut hosts = Vec::new();
            for redirect in &redirects {
                if let Some(uri) = redirect.as_str()
                    && let Ok(url) = url::Url::parse(uri)
                {
                    let host = format!(
                        "{}:{}",
                        url.host_str().unwrap_or_default(),
                        url.port().map_or_else(String::new, |port| port.to_string())
                    );
                    if !hosts.contains(&host) {
                        hosts.push(host);
                    }
                }
            }
            if hosts.len() > 1 {
                return protocol_error("invalid_client_metadata","pairwise clients with redirect_uris on different hosts require a sector_identifier_uri, which is not yet supported. All redirect_uris must share the same host.").map(Err);
            }
        }
        if let Some(scope) = metadata.get("scope").and_then(Value::as_str) {
            for scope in scope.split(' ').filter(|scope| !scope.is_empty()) {
                if !self.config.scopes.iter().any(|allowed| allowed == scope) {
                    return protocol_error(
                        "invalid_scope",
                        format!("cannot request scope {scope}"),
                    )
                    .map(Err);
                }
            }
        }
        if metadata.contains_key("jwks") && metadata.contains_key("jwks_uri") {
            return protocol_error(
                "invalid_client_metadata",
                "jwks and jwks_uri are mutually exclusive",
            )
            .map(Err);
        }
        if let Some(uri) = metadata.get("jwks_uri").and_then(Value::as_str)
            && let Some(error) = remote_key_uri_error(uri, ctx)
        {
            return protocol_error("invalid_client_metadata", error).map(Err);
        }
        if let Some(jwks) = metadata.get("jwks")
            && let Some(error) = public_jwks_error(jwks)
        {
            return protocol_error("invalid_client_metadata", error).map(Err);
        }
        if auth == "private_key_jwt"
            && !metadata.contains_key("jwks")
            && !metadata.contains_key("jwks_uri")
        {
            return protocol_error(
                "invalid_client_metadata",
                "private_key_jwt requires either jwks or jwks_uri",
            )
            .map(Err);
        }
        if let Some(uri) = metadata
            .get("backchannel_logout_uri")
            .and_then(Value::as_str)
        {
            if self.config.disable_jwt_plugin {
                return protocol_error(
                    "invalid_client_metadata",
                    "backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)",
                ).map(Err);
            }
            if let Some(error) = backchannel_uri_error(uri) {
                return protocol_error("invalid_client_metadata", error).map(Err);
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
        _ = metadata.entry("disabled").or_insert_with(|| json!(false));
        _ = metadata
            .entry("dpop_bound_access_tokens")
            .or_insert_with(|| json!(false));
        Ok(Ok(metadata))
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateClientInput {
    client_id: String,
    update: Value,
}
pub(super) fn validate_update(body: Option<&JsValue>) -> AuthResult<JsValue> {
    let mut output = crate::endpoint::validate_fields(
        body,
        "body",
        &[crate::authentication_helpers::JsonField::string(
            "client_id",
            true,
        )],
    )?;
    let fields = FIELDS
        .iter()
        .copied()
        .filter(|(name, _)| {
            ![
                "token_endpoint_auth_method",
                "jwks",
                "jwks_uri",
                "dpop_bound_access_tokens",
            ]
            .contains(name)
        })
        .collect::<Vec<_>>();
    let update = validate_metadata(
        body.and_then(|value| value.get("update")),
        "body.update",
        &fields,
    )?;
    if let JsValue::Object(object) = &mut output {
        _ = object.insert("update".into(), update);
    }
    Ok(output)
}
impl OAuthProviderPlugin {
    /// Patch metadata of a durable client owned by the authenticated user.
    pub fn update_oauth_client_endpoint(
        client_id: &str,
        update: &impl Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "updateOAuthClient")
            .with_body(&json!({"client_id":client_id,"update":update}))
    }

    pub(super) async fn update_client<S: AuthSchema>(
        &self,
        input: UpdateClientInput,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        admin: bool,
    ) -> AuthResult<EndpointResponse> {
        let user = if admin {
            let Some((user, _)) = Box::pin(ctx.require_cached_session(req)).await.ok() else {
                return Ok(EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body()
                .with_header("Content-Type", "application/json"));
            };
            user
        } else {
            Box::pin(crate::helpers::ordinary_session(req, ctx))
                .await?
                .0
        };
        if self
            .config
            .cached_trusted_clients
            .contains(&input.client_id)
        {
            return status_protocol_error(
                500,
                "invalid_client",
                "trusted clients must be updated manually",
            );
        }
        let Some(client) = super::discovery::resolve(ctx, &input.client_id).await? else {
            return status_protocol_error(404, "not_found", "client not found");
        };
        if client.user_id.as_deref() != Some(user.id().as_ref()) {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        let mut updates: serde_json::Map<String, Value> = serde_json::from_value(input.update)?;
        if updates.is_empty() {
            return client_update_response(client, admin);
        }
        let mut merged: serde_json::Map<String, Value> = serde_json::from_value(client.metadata)?;
        let scopes = updates.remove("client_credentials_scopes");
        let extensions = updates
            .remove("metadata")
            .and_then(|value| value.as_object().cloned());
        // The pinned TS adapter strips expiresAt because it is absent from the client schema.
        _ = updates.remove("client_secret_expires_at");
        merged.extend(updates);
        if let Some(scopes) = scopes.and_then(|value| value.as_array().cloned()) {
            if let Some(response) = self
                .admit_credential_scopes(&scopes, &merged, req, ctx)
                .await?
            {
                return Ok(response);
            }
            _ = merged.insert("client_credentials_scopes".into(), json!(scopes));
        }
        if let Some(extensions) = extensions {
            let extensions = extensions
                .into_iter()
                .filter(|(name, _)| !RESERVED_METADATA_FIELDS.contains(&name.as_str()))
                .collect::<serde_json::Map<_, _>>();
            if !extensions.is_empty() {
                merged.retain(|name, _| RESERVED_METADATA_FIELDS.contains(&name.as_str()));
                merged.extend(extensions);
            }
        }
        if !merged
            .get("grant_types")
            .and_then(Value::as_array)
            .is_some_and(|grants| grants.contains(&json!("client_credentials")))
            || merged
                .get("token_endpoint_auth_method")
                .and_then(Value::as_str)
                == Some("none")
        {
            _ = merged.insert("client_credentials_scopes".into(), json!([]));
        }
        // Update admission may infer defaults, but the reference persists only the requested patch.
        let metadata = match self.admit_metadata(merged.clone(), ctx)? {
            Ok(_) => Value::Object(merged),
            Err(response) => return Ok(response),
        };
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid client update timestamp"))?;
        let Some(client) = ctx
            .database
            .update_oauth_client_metadata(&input.client_id, metadata, now)
            .await?
        else {
            return status_protocol_error(500, "invalid_client", "unable to update client");
        };
        client_update_response(client, admin)
    }
}

impl OAuthProviderPlugin {
    fn generate_client_secret(&self) -> AuthResult<String> {
        let generated = self
            .config
            .client_secret_generator
            .as_ref()
            .map(|generator| generator.generate())
            .transpose()?;
        Ok(generated
            .filter(|secret| !secret.is_empty())
            .unwrap_or_else(random_credential))
    }
    fn prefixed_client_secret(&self, secret: String) -> String {
        match self.config.client_secret_prefix.as_deref() {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}{secret}"),
            _ => secret,
        }
    }
    async fn persist_client<S: AuthSchema>(
        &self,
        metadata: serde_json::Map<String, Value>,
        user_id: Option<String>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let auth = metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic");
        let client_id = match &self.config.client_id_generator {
            Some(generator) => generator.generate()?,
            None => random_credential(),
        };
        let plaintext =
            if ["none", "private_key_jwt"].contains(&auth) || self.is_extension_auth_method(auth) {
                None
            } else {
                Some(self.generate_client_secret()?)
            };
        let stored = if let Some(secret) = plaintext.as_deref() {
            Some(super::client_secret::store(ctx, &self.config, secret).await?)
        } else {
            None
        };
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid client creation timestamp"))?;
        let client = ctx
            .database
            .create_oauth_client(alibi_core::store::CreateOAuthClient {
                client_id,
                user_id,
                client_secret: stored,
                metadata: Value::Object(metadata),
                created_at: now,
            })
            .await?;
        let mut output: serde_json::Map<String, Value> = serde_json::from_value(client.metadata)?;
        _ = output.insert("client_id".into(), json!(client.client_id));
        if let Some(user_id) = client.user_id {
            _ = output.insert("user_id".into(), json!(user_id));
        }
        _ = output.insert(
            "client_id_issued_at".into(),
            json!(client.created_at.map(|time| time.timestamp())),
        );
        if let Some(secret) = plaintext {
            _ = output.insert(
                "client_secret".into(),
                Value::String(self.prefixed_client_secret(secret)),
            );
            _ = output.insert("client_secret_expires_at".into(), json!(0));
        }
        Ok(EndpointResponse::json(&Value::Object(output))?.with_status(201))
    }
    /// Register a client under the provider's dynamic-registration policy.
    pub fn register_oauth_client_endpoint(
        input: &CreateOAuthClientInput,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "registerOAuthClient").with_body(input)
    }
    pub(super) async fn register_client<S: AuthSchema>(
        &self,
        body: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let mut metadata = match registration_metadata(body)? {
            Ok(metadata) => metadata,
            Err(response) => return Ok(response),
        };
        req.queue_response_header("Cache-Control", "no-store");
        req.queue_response_header("Pragma", "no-cache");
        if !self.config.allow_dynamic_client_registration {
            return status_protocol_error(403, "access_denied", "Client registration is disabled");
        }
        let session = Box::pin(ctx.require_cached_session(req)).await.ok();
        if session.is_none() && !self.config.allow_unauthenticated_client_registration {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error_description":"Authentication required for client registration"}"#,
            )?)
            .with_header("WWW-Authenticate", "Bearer"));
        }
        if session.is_none()
            && metadata
                .get("grant_types")
                .and_then(Value::as_array)
                .is_some_and(|grants| grants.contains(&json!("client_credentials")))
        {
            return status_protocol_error(
                400,
                "invalid_client_metadata",
                "client_credentials grant requires authenticated registration",
            );
        }
        if metadata
            .get("scope")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            _ = metadata.insert("scope".into(), json!(self.config.scopes.join(" ")));
        }
        let mut metadata = match self.admit_metadata(metadata, ctx)? {
            Ok(metadata) => metadata,
            Err(response) => return Ok(response),
        };
        if let Some(resources) = body
            .and_then(|body| body.get("resources"))
            .and_then(JsValue::as_array)
            && let Some(resource) = resources.first().and_then(JsValue::as_str)
        {
            return status_protocol_error(
                400,
                "invalid_target",
                &format!("requested resource {resource} is not allowed for client registration"),
            );
        }
        _ = metadata.insert("scope".into(), json!(self.config.scopes.join(" ")));
        let user_id = session.map(|(user, _)| user.id().as_ref().to_owned());
        self.persist_client(metadata, user_id, ctx).await
    }
}
fn registration_metadata(
    body: Option<&JsValue>,
) -> AuthResult<Result<serde_json::Map<String, Value>, EndpointResponse>> {
    let validated = match validate(body) {
        Ok(value) => value,
        Err(error) => {
            let message = error.error_payload().2;
            let first = message.split("; ").next().unwrap_or(&message);
            let (path, issue) = first
                .strip_prefix("[body.")
                .and_then(|text| text.split_once("] "))
                .unwrap_or_else(|| ("", first.trim_start_matches("[body] ")));
            let error = if path.starts_with("redirect_uris")
                || path.starts_with("post_logout_redirect_uris")
            {
                "invalid_redirect_uri"
            } else if path == "software_statement" {
                "invalid_software_statement"
            } else {
                "invalid_client_metadata"
            };
            let description = if path.is_empty() {
                issue.to_owned()
            } else if let Some(expected) = issue
                .strip_prefix("Invalid input: expected ")
                .and_then(|text| text.split_once(','))
            {
                format!("{path} must be a {}", expected.0)
            } else {
                format!("{path}: {issue}")
            };
            return status_protocol_error(400, error, &description).map(Err);
        }
    };
    let mut metadata: serde_json::Map<String, Value> =
        alibi_core::utils::json::from_value(validated)?;
    if metadata
        .get("client_name")
        .and_then(Value::as_str)
        .is_some_and(|name| name.trim().is_empty())
    {
        return status_protocol_error(
            400,
            "invalid_client_metadata",
            "client_name: client_name cannot be empty",
        )
        .map(Err);
    }
    if let Some(subject) = body.and_then(|body| body.get("subject_type")) {
        if !subject
            .as_str()
            .is_some_and(|value| ["public", "pairwise"].contains(&value))
        {
            return status_protocol_error(
                400,
                "invalid_client_metadata",
                "subject_type must be one of: public, pairwise",
            )
            .map(Err);
        }
        _ = metadata.insert("subject_type".into(), json!(subject.as_str()));
    }
    if let Some(value) = body.and_then(|body| body.get("resources")) {
        let Some(resources) = value.as_array() else {
            return status_protocol_error(400, "invalid_target", "resources must be a array")
                .map(Err);
        };
        for (index, value) in resources.iter().enumerate() {
            let Some(uri) = value.as_str() else {
                return status_protocol_error(
                    400,
                    "invalid_target",
                    &format!("resources[{index}] must be a string"),
                )
                .map(Err);
            };
            let error = match url::Url::parse(uri) {
                Err(_) => Some("resource must be an absolute URI"),
                Ok(url) => {
                    if uri.contains('#') {
                        Some("resource must not contain a fragment")
                    } else if ["javascript", "data", "vbscript"].contains(&url.scheme()) {
                        Some("resource cannot use javascript:, data:, or vbscript: scheme")
                    } else {
                        None
                    }
                }
            };
            if let Some(error) = error {
                return status_protocol_error(
                    400,
                    "invalid_target",
                    &format!("resources[{index}]: {error}"),
                )
                .map(Err);
            }
        }
    }
    if body.and_then(|body| body.get("skip_consent")).is_some() {
        return status_protocol_error(
            400,
            "invalid_client_metadata",
            "skip_consent must be a never",
        )
        .map(Err);
    }
    Ok(Ok(metadata))
}

pub(super) fn validate_admin_create(body: Option<&JsValue>) -> AuthResult<JsValue> {
    let mut fields = Vec::new();
    for &(name, kind) in FIELDS {
        if name == "dpop_bound_access_tokens" {
            continue;
        }
        if name == "response_types" {
            fields.push(("client_credentials_scopes", FieldKind::Scopes));
        }
        fields.push((name, kind));
    }
    fields.extend([
        ("client_secret_expires_at", FieldKind::Expiration),
        ("skip_consent", FieldKind::Boolean),
        ("enable_end_session", FieldKind::Boolean),
        ("require_pkce", FieldKind::Boolean),
        ("dpop_bound_access_tokens", FieldKind::Boolean),
        ("subject_type", FieldKind::Subject),
        ("metadata", FieldKind::Record),
    ]);
    validate_metadata(body, "body", &fields)
}
impl OAuthProviderPlugin {
    /// Create a managed client with operator fields through the trusted server API.
    pub fn admin_create_oauth_client_endpoint(
        input: &impl Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminCreateOAuthClient").with_body(input)
    }
    pub(super) async fn admin_create_client<S: AuthSchema>(
        &self,
        mut metadata: serde_json::Map<String, Value>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        req.queue_response_header("Cache-Control", "no-store");
        req.queue_response_header("Pragma", "no-cache");
        let Some((user, _)) = Box::pin(ctx.require_cached_session(req)).await.ok() else {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        };
        let scopes = metadata
            .remove("client_credentials_scopes")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        if let Some(response) = self
            .admit_credential_scopes(&scopes, &metadata, req, ctx)
            .await?
        {
            return Ok(response);
        }
        _ = metadata.remove("client_secret_expires_at");
        let extensions = metadata
            .remove("metadata")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let mut metadata = match self.admit_metadata(metadata, ctx)? {
            Ok(metadata) => metadata,
            Err(response) => return Ok(response),
        };
        for (name, value) in extensions {
            if !RESERVED_METADATA_FIELDS.contains(&name.as_str()) {
                _ = metadata.insert(name, value);
            }
        }
        _ = metadata.insert("client_credentials_scopes".into(), json!(scopes));
        self.persist_client(metadata, Some(user.id().as_ref().to_owned()), ctx)
            .await
    }
}

const RESERVED_METADATA_FIELDS: &[&str] = &[
    "clientId",
    "clientSecret",
    "clientDiscoveryId",
    "disabled",
    "scopes",
    "clientCredentialsScopes",
    "userId",
    "createdAt",
    "updatedAt",
    "expiresAt",
    "name",
    "uri",
    "icon",
    "contacts",
    "tos",
    "policy",
    "softwareId",
    "softwareVersion",
    "softwareStatement",
    "redirectUris",
    "postLogoutRedirectUris",
    "backchannelLogoutUri",
    "backchannelLogoutSessionRequired",
    "tokenEndpointAuthMethod",
    "grantTypes",
    "responseTypes",
    "applicationType",
    "jwks",
    "jwksUri",
    "requirePKCE",
    "dpopBoundAccessTokens",
    "skipConsent",
    "enableEndSession",
    "subjectType",
    "referenceId",
    "metadata",
    "client_id",
    "client_secret",
    "client_secret_expires_at",
    "scope",
    "user_id",
    "client_id_issued_at",
    "client_name",
    "client_uri",
    "logo_uri",
    "tos_uri",
    "policy_uri",
    "jwks_uri",
    "software_id",
    "software_version",
    "software_statement",
    "redirect_uris",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
    "application_type",
    "skip_consent",
    "enable_end_session",
    "require_pkce",
    "dpop_bound_access_tokens",
    "subject_type",
    "reference_id",
    "public",
    "type",
    "resources",
    "client_credentials_scopes",
];

impl OAuthProviderPlugin {
    async fn admit_credential_scopes<S: AuthSchema>(
        &self,
        scopes: &[Value],
        metadata: &serde_json::Map<String, Value>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<EndpointResponse>> {
        if !scopes.is_empty() {
            if !metadata
                .get("grant_types")
                .and_then(Value::as_array)
                .is_some_and(|grants| grants.contains(&json!("client_credentials")))
            {
                return status_protocol_error(
                    400,
                    "invalid_client_metadata",
                    "client_credentials_scopes requires the client_credentials grant",
                )
                .map(Some);
            }
            if metadata
                .get("token_endpoint_auth_method")
                .and_then(Value::as_str)
                == Some("none")
            {
                return status_protocol_error(
                    400,
                    "invalid_client_metadata",
                    "public clients cannot be assigned client_credentials scopes",
                )
                .map(Some);
            }
            let invalid = scopes
                .iter()
                .filter_map(Value::as_str)
                .filter(|scope| {
                    !self.config.scopes.iter().any(|allowed| allowed == scope)
                        || ["openid", "profile", "email", "offline_access"].contains(scope)
                })
                .collect::<Vec<_>>();
            if !invalid.is_empty() {
                return status_protocol_error(
                    400,
                    "invalid_scope",
                    &format!(
                        "The following client_credentials scopes are invalid: {}",
                        invalid.join(", ")
                    ),
                )
                .map(Some);
            }
            if let Some(privileges) = &self.config.client_credentials_scope_privileges
                && let Ok((user, session)) = Box::pin(ctx.require_cached_session(req)).await
            {
                let mut headers = alibi_core::Headers::new();
                for (name, value) in req.session_headers() {
                    _ = headers.insert(name.clone(), value.clone());
                }
                if privileges
                    .allowed(&super::OAuthClientPrivilegeContext {
                        action: "configure-client-credentials-scopes",
                        headers,
                        user: serde_json::to_value(user)?,
                        session: serde_json::to_value(session)?,
                    })
                    .await?
                {
                    return Ok(None);
                }
            }
            return Ok(Some(
                EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body()
                .with_header("Content-Type", "application/json"),
            ));
        }
        Ok(None)
    }
}

fn client_update_response(
    client: alibi_core::store::OAuthClient,
    admin: bool,
) -> AuthResult<EndpointResponse> {
    let scopes = client
        .metadata
        .get("client_credentials_scopes")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut output = client_read_metadata(client)?;
    if admin {
        let object = output
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("OAuth client metadata must be an object"))?;
        _ = object.insert("client_credentials_scopes".into(), scopes);
    }
    EndpointResponse::json(&output)
}
pub(super) fn validate_admin_update(body: Option<&JsValue>) -> AuthResult<JsValue> {
    let mut output = crate::endpoint::validate_fields(
        body,
        "body",
        &[crate::authentication_helpers::JsonField::string(
            "client_id",
            true,
        )],
    )?;
    let mut fields = FIELDS
        .iter()
        .copied()
        .filter(|(name, _)| {
            ![
                "token_endpoint_auth_method",
                "jwks",
                "jwks_uri",
                "dpop_bound_access_tokens",
            ]
            .contains(name)
        })
        .collect::<Vec<_>>();
    let position = fields
        .iter()
        .position(|(name, _)| *name == "response_types")
        .unwrap_or(fields.len());
    fields.insert(position, ("client_credentials_scopes", FieldKind::Scopes));
    fields.extend([
        ("client_secret_expires_at", FieldKind::Expiration),
        ("skip_consent", FieldKind::Boolean),
        ("enable_end_session", FieldKind::Boolean),
        ("dpop_bound_access_tokens", FieldKind::Boolean),
        ("metadata", FieldKind::Record),
    ]);
    let update = validate_metadata(
        body.and_then(|body| body.get("update")),
        "body.update",
        &fields,
    )?;
    if let JsValue::Object(object) = &mut output {
        _ = object.insert("update".into(), update);
    }
    Ok(output)
}
impl OAuthProviderPlugin {
    /// Patch operator-controlled fields of an owned client through the server-only API.
    pub fn admin_update_oauth_client_endpoint(
        client_id: &str,
        update: &impl Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminUpdateOAuthClient")
            .with_body(&json!({"client_id":client_id,"update":update}))
    }
}

#[derive(serde::Deserialize)]
pub(super) struct PreloginClientInput {
    client_id: String,
    oauth_query: Option<String>,
}
pub(super) fn validate_prelogin(body: Option<&JsValue>) -> AuthResult<JsValue> {
    crate::endpoint::validate_fields(
        body,
        "body",
        &[
            crate::authentication_helpers::JsonField::string("client_id", true),
            crate::authentication_helpers::JsonField::string("oauth_query", false),
        ],
    )
}
impl OAuthProviderPlugin {
    /// Read public client display metadata before login using a provider-issued authorization query.
    pub fn get_oauth_client_public_prelogin_endpoint(
        client_id: &str,
        oauth_query: Option<&str>,
    ) -> AuthResult<ServerEndpoint<Value>> {
        let mut input = serde_json::Map::from_iter([("client_id".into(), json!(client_id))]);
        if let Some(query) = oauth_query {
            _ = input.insert("oauth_query".into(), json!(query));
        }
        ServerEndpoint::new("oauth-provider", "getOAuthClientPublicPrelogin").with_body(&input)
    }
    pub(super) async fn read_prelogin_client<S: AuthSchema>(
        &self,
        input: PreloginClientInput,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let valid = super::authorization::verify_authorization_query(
            input.oauth_query.as_deref().unwrap_or(""),
            ctx.config.current_secret(),
        )?;
        // The provider's before hook rejects a supplied invalid query before endpoint middleware.
        if input
            .oauth_query
            .as_deref()
            .is_some_and(|query| !query.is_empty())
            && !valid
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 400,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"invalid_signature"}"#,
            )?));
        }
        if !self.config.allow_public_client_prelogin {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 400,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        if !valid {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 401,
                code: None,
                message: String::new(),
            })
            .with_error_body(alibi_core::utils::json::parse_value(
                r#"{"error":"invalid_signature"}"#,
            )?));
        }
        Box::pin(self.public_client_projection(&input.client_id, ctx)).await
    }
}
