//! Client credential extraction and registration-bound authentication shared by protocol endpoints.
use alibi_core::endpoint::EndpointResponse;
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
pub(super) struct Credentials {
    pub(super) client_id: String,
    pub(super) secret: String,
    pub(super) pre_verified: bool,
    pub(super) method: &'static str,
}
const AUTH_FIELDS: [&str; 3] = ["client_secret", "client_assertion", "client_assertion_type"];

pub(super) async fn extract<S: AuthSchema>(
    body: &Value,
    req: &impl SessionRequest,
    ctx: &AuthContext<S>,
    provider: &super::OAuthProviderPlugin,
    endpoint: &str,
) -> AuthResult<Result<Credentials, EndpointResponse>> {
    let body = match normalize(body, req) {
        Ok(body) => body,
        Err(description) => {
            return Ok(Err(super::clients::status_protocol_error(
                400,
                "invalid_request",
                &description,
            )?));
        }
    };
    if body.get("client_assertion").is_some() || body.get("client_assertion_type").is_some() {
        return super::assertion::verify(&body, ctx, provider, endpoint).await;
    }
    from_normalized(&body, req)
}

fn normalize(body: &Value, req: &impl SessionRequest) -> Result<Value, String> {
    let mut fields = serde_json::Map::new();
    for field in std::iter::once("client_id").chain(AUTH_FIELDS) {
        if let Some(value) = body.get(field) {
            if value == "" {
                continue;
            }
            if !value.is_string() {
                return Err(format!("{field} must be a string"));
            }
            _ = fields.insert(field.into(), value.clone());
        }
    }
    let request = req.physical_request();
    if let Some(request) = request
        && request.header("content-type").is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
        })
    {
        let params = url::form_urlencoded::parse(request.body.as_deref().unwrap_or_default())
            .into_owned()
            .collect::<Vec<_>>();
        for field in std::iter::once("client_id").chain(AUTH_FIELDS) {
            let values = params
                .iter()
                .filter(|(key, value)| key == field && !value.is_empty())
                .map(|(_, value)| value)
                .collect::<Vec<_>>();
            if values.len() > 1 {
                return Err(format!("{field} must not be repeated"));
            }
            if field == "client_id" {
                _ = fields.remove(field);
            }
            if let Some(value) = values.first() {
                _ = fields.insert(field.into(), Value::String((*value).clone()));
            }
        }
    }
    let header = request
        .and_then(|request| request.header("authorization"))
        .is_some_and(|value| !value.is_empty());
    let secret = fields.contains_key("client_secret");
    let assertion =
        fields.contains_key("client_assertion") || fields.contains_key("client_assertion_type");
    if (header && (secret || assertion)) || (secret && assertion) {
        return Err("A request must use only one client authentication method".into());
    }
    let mut normalized = body.as_object().cloned().unwrap_or_default();
    for field in std::iter::once("client_id").chain(AUTH_FIELDS) {
        _ = normalized.remove(field);
    }
    normalized.extend(fields);
    Ok(Value::Object(normalized))
}

fn from_normalized(
    body: &Value,
    req: &impl SessionRequest,
) -> AuthResult<Result<Credentials, EndpointResponse>> {
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
        .and_then(|request| request.header("authorization"))
        .filter(|header| !header.is_empty())
    {
        if header
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Basic"))
            && header.as_bytes().get(5) == Some(&b' ')
        {
            let Some((id, value)) =
                decode_basic(header.get(6..).unwrap_or_default().trim_start_matches(' '))
            else {
                return header_denial(
                    401,
                    "invalid_client",
                    "invalid authorization header format",
                    Some("Basic"),
                );
            };
            client_id = id;
            secret = value;
            "client_secret_basic"
        } else {
            let Some(scheme) = authorization_scheme(header) else {
                return header_denial(
                    400,
                    "invalid_request",
                    "Invalid authorization header format",
                    None,
                );
            };
            return header_denial(
                401,
                "invalid_client",
                "unsupported authorization scheme",
                Some(scheme),
            );
        }
    } else if secret.is_empty() {
        "none"
    } else {
        "client_secret_post"
    };
    Ok(Ok(Credentials {
        client_id,
        secret,
        pre_verified: false,
        method,
    }))
}
fn header_denial(
    status: u16,
    code: &str,
    description: &str,
    scheme: Option<&str>,
) -> AuthResult<Result<Credentials, EndpointResponse>> {
    let response = super::clients::status_protocol_error(status, code, description)?;
    Ok(Err(if let Some(scheme) = scheme {
        response.with_header("WWW-Authenticate", scheme)
    } else {
        response
    }))
}
fn authorization_scheme(header: &str) -> Option<&str> {
    let end = header
        .find(|c: char| !c.is_ascii_alphanumeric() && !"!#$%&'*+-.^_`|~".contains(c))
        .unwrap_or(header.len());
    let scheme = header.get(..end).filter(|scheme| !scheme.is_empty())?;
    if header
        .get(end..)?
        .chars()
        .next()
        .is_some_and(|c| !c.is_whitespace() && c != '\u{feff}')
    {
        return None;
    }
    Some(scheme)
}
fn decode_basic(encoded: &str) -> Option<(String, String)> {
    // Match @better-auth/utils: select the alphabet from the whole input, stop
    // at the first padding character, and discard leftover bits without checks.
    let alphabet = if encoded.contains('-') || encoded.contains('_') {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut bytes = Vec::new();
    for byte in encoded.bytes().take_while(|byte| *byte != b'=') {
        let value = alphabet.iter().position(|candidate| *candidate == byte)?;
        buffer = (buffer << 6) | u32::try_from(value).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 255).ok()?);
        }
    }
    let decoded = String::from_utf8_lossy(&bytes);
    let decoded = decoded.strip_prefix('\u{feff}').unwrap_or(&decoded);
    let (id, secret) = decoded.split_once(':')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((decode_form_value(id)?, decode_form_value(secret)?))
}
fn decode_form_value(raw: &str) -> Option<String> {
    url::form_urlencoded::parse(format!("v={raw}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
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
        config: &super::OAuthProviderConfig,
    ) -> AuthResult<Result<OAuthClient, EndpointResponse>> {
        let Some(client) = super::discovery::resolve(ctx, &self.client_id).await? else {
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
        if !self.pre_verified && registered != "none" && self.secret.is_empty() {
            return Ok(Err(self.denied("client secret must be provided")?));
        }
        if !self.secret.is_empty() && client.client_secret.is_none() {
            return Ok(Err(
                self.denied("public client, client secret should not be received")?
            ));
        }
        if !self.secret.is_empty() {
            let secret = if let Some(prefix) = config
                .client_secret_prefix
                .as_deref()
                .filter(|prefix| !prefix.is_empty())
            {
                let Some(secret) = self.secret.strip_prefix(prefix) else {
                    return Ok(Err(super::clients::status_protocol_error(
                        401,
                        "invalid_client",
                        "invalid client_secret",
                    )?));
                };
                secret
            } else {
                self.secret.as_str()
            };
            let valid = !secret.is_empty()
                && client.client_secret.as_deref().is_some_and(|stored| {
                    if config.disable_jwt_plugin {
                        crate::token_crypto::decrypt_with_config(stored, &ctx.config).is_ok_and(
                            |plaintext| bool::from(plaintext.as_bytes().ct_eq(secret.as_bytes())),
                        )
                    } else {
                        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret));
                        bool::from(hash.as_bytes().ct_eq(stored.as_bytes()))
                    }
                });
            if !valid {
                return Ok(Err(self.denied("invalid client_secret")?));
            }
        }
        Ok(Ok(client))
    }
}
