//! Bearer authentication through the ordinary signed session-cookie lifecycle.

use async_trait::async_trait;
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use better_auth_core::utils::cookie_utils::sign_cookie_value;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    BeforeRequestAction,
};
use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use sha2::Sha256;

/// Configuration of the bearer-to-cookie adapter.
#[derive(Clone, Debug, Default)]
pub struct BearerConfig {
    /// Ignore unsigned bearer tokens. Invalid headers leave ordinary cookies intact.
    pub require_signature: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BearerPlugin {
    config: BearerConfig,
}

impl BearerPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: BearerConfig) -> Self {
        Self { config }
    }

    fn signed_token(&self, authorization: &str, secret: &str) -> Option<String> {
        let (scheme, token) = authorization.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        let token = token
            .trim_matches(|ch: char| (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}');
        if token.is_empty() {
            return None;
        }
        let decoded = if token.contains('.') {
            try_decode(token)
        } else {
            if self.config.require_signature {
                return None;
            }
            try_decode(&sign_cookie_value(token, secret))
        };
        let mut components = decoded.split('.');
        let payload = components.next()?;
        let signature = components.next()?;
        // The pinned HMAC decoder accepts either alphabet, stops at padding,
        // and ignores unused trailing bits. The downstream cookie verifier
        // still owns the complete signed-cookie syntax and session lookup.
        let selected = if signature.contains(['-', '_']) {
            &alphabet::URL_SAFE
        } else {
            &alphabet::STANDARD
        };
        let engine = GeneralPurpose::new(
            selected,
            GeneralPurposeConfig::new()
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
                .with_decode_allow_trailing_bits(true),
        );
        let signature = engine.decode(signature.split('=').next()?).ok()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature).ok()?;
        Some(decoded)
    }
}

fn try_decode(value: &str) -> String {
    // decodeURIComponent fails the entire value on any malformed escape;
    // urlencoding alone would partially decode it before that escape.
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                && bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return value.to_owned();
        }
    }
    urlencoding::decode(value).map_or_else(|_| value.to_owned(), |decoded| decoded.into_owned())
}

fn encode_component(value: &str) -> String {
    // encodeURIComponent preserves these characters in addition to RFC3986's
    // unreserved set. Values are encoded once after cookie-map replacement.
    urlencoding::encode(value)
        .replace("%21", "!")
        .replace("%27", "'")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%2A", "*")
}

fn replace_cookie(header: &str, name: &str, value: &str) -> String {
    let mut cookies = IndexMap::<String, String>::new();
    for item in header.split(';') {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        let key = key.trim_matches([' ', '\t']);
        let value = value.trim_matches([' ', '\t']);
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value
                .bytes()
                .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
        {
            continue;
        }
        drop(cookies.insert(key.to_owned(), try_decode(value)));
    }
    drop(cookies.insert(name.to_owned(), value.to_owned()));
    cookies
        .into_iter()
        .map(|(key, value)| format!("{key}={}", encode_component(&value)))
        .collect::<Vec<_>>()
        .join("; ")
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for BearerPlugin {
    fn name(&self) -> &'static str {
        "bearer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let Some(authorization) = req
            .headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case("authorization").then_some(value))
        else {
            return Ok(None);
        };
        let Some(token) = self.signed_token(authorization, ctx.config.current_secret()) else {
            return Ok(None);
        };
        let existing = req
            .headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case("cookie").then_some(value.as_str()))
            .unwrap_or("");
        let cookie = replace_cookie(existing, &ctx.config.session.cookie_name, &token);
        let mut headers = req.headers.clone();
        headers.retain(|key, _| !key.eq_ignore_ascii_case("cookie"));
        drop(headers.insert("cookie".to_owned(), cookie));
        Ok(Some(BeforeRequestAction::ReplaceHeaders { headers }))
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn after_request(
        &self,
        _req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let token = response
            .headers
            .get_all("set-cookie")
            .filter_map(|header| cookie::Cookie::parse(header.as_str()).ok())
            .filter(|cookie| cookie.name() == ctx.config.session.cookie_name)
            .last();
        if let Some(cookie) = token.filter(|cookie| {
            !cookie.value().is_empty()
                && cookie.max_age().is_none_or(|age| age.whole_seconds() != 0)
        }) {
            let token = try_decode(cookie.value());
            let mut exposed = Vec::new();
            for name in response
                .headers
                .get("access-control-expose-headers")
                .map_or("", String::as_str)
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                if !exposed.contains(&name) {
                    exposed.push(name);
                }
            }
            if !exposed.contains(&"set-auth-token") {
                exposed.push("set-auth-token");
            }
            let exposed = exposed.join(", ");
            drop(response.headers.insert("set-auth-token", token));
            drop(
                response
                    .headers
                    .insert("access-control-expose-headers", exposed),
            );
        }
        Ok(response)
    }
}
