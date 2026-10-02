//! Asymmetric session JWTs, public JWKS, and trusted server-side signing.

mod crypto;
mod endpoint;
pub use endpoint::{JwtTokenOutput, JwtVerifyOutput};

#[cfg(test)]
mod tests;

use super::token_crypto::{decrypt, encrypt};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateJwk, HttpMethod, Jwk,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{str::FromStr, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES512")]
    Es512,
    #[serde(rename = "PS256")]
    Ps256,
    #[serde(rename = "RS256")]
    Rs256,
}

impl JwtAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es512 => "ES512",
            Self::Ps256 => "PS256",
            Self::Rs256 => "RS256",
        }
    }
    #[must_use]
    pub const fn curve(self) -> Option<&'static str> {
        match self {
            Self::EdDsa => Some("Ed25519"),
            Self::Es256 => Some("P-256"),
            Self::Es512 => Some("P-521"),
            Self::Ps256 | Self::Rs256 => None,
        }
    }
}

impl FromStr for JwtAlgorithm {
    type Err = AuthError;
    fn from_str(value: &str) -> AuthResult<Self> {
        match value {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            "ES512" => Ok(Self::Es512),
            "PS256" => Ok(Self::Ps256),
            "RS256" => Ok(Self::Rs256),
            _ => Err(AuthError::config(format!(
                "Unsupported JWT algorithm: {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct JwtKeyPairConfig {
    pub algorithm: JwtAlgorithm,
    pub modulus_length: Option<usize>,
}

impl Default for JwtKeyPairConfig {
    fn default() -> Self {
        Self {
            algorithm: JwtAlgorithm::EdDsa,
            modulus_length: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum JwtExpiration {
    After(Duration),
    /// Relative lifetime retaining the Source floating-point seconds.
    AfterSeconds(f64),
    At(DateTime<Utc>),
    Numeric(f64),
}

impl Default for JwtExpiration {
    fn default() -> Self {
        Self::After(Duration::minutes(15))
    }
}

impl JwtExpiration {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "Remote callbacks observe JavaScript IEEE754 arithmetic"
    )]
    fn timestamp_raw(
        &self,
        issued_at: Option<&better_auth_core::utils::json::JsValue>,
    ) -> better_auth_core::utils::json::JsValue {
        use better_auth_core::utils::json::JsValue;
        let timestamp = match self {
            Self::After(duration) => {
                let seconds = (duration.num_milliseconds() as f64 / 1000.0 + 0.5).floor();
                let base = match issued_at {
                    None | Some(JsValue::Null) => Utc::now().timestamp() as f64,
                    Some(JsValue::Bool(value)) => f64::from(u8::from(*value)),
                    Some(JsValue::Number(value)) => *value,
                    Some(value) => {
                        return JsValue::String(format!(
                            "{}{seconds}",
                            js_raw_primitive_string(value)
                        ));
                    }
                };
                base + seconds
            }
            Self::AfterSeconds(seconds) => {
                let base = match issued_at {
                    None | Some(JsValue::Null) => Utc::now().timestamp() as f64,
                    Some(JsValue::Bool(value)) => f64::from(u8::from(*value)),
                    Some(JsValue::Number(value)) => *value,
                    Some(value) => {
                        return JsValue::String(format!(
                            "{}{}",
                            js_raw_primitive_string(value),
                            ryu_js::Buffer::new().format(*seconds)
                        ));
                    }
                };
                base + seconds
            }
            Self::At(date) => date.timestamp() as f64,
            Self::Numeric(value) => *value,
        };
        JsValue::Number(timestamp)
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn timestamp(&self, issued_at: Option<&Value>) -> Value {
        let timestamp = match self {
            Self::After(duration) => {
                let seconds = (duration.num_milliseconds() as f64 / 1000.0 + 0.5).floor();
                let base = match issued_at {
                    None | Some(Value::Null) => Utc::now().timestamp() as f64,
                    Some(Value::Bool(value)) => f64::from(u8::from(*value)),
                    Some(Value::Number(value)) => value.as_f64().unwrap_or_default(),
                    Some(value) => {
                        // toExpJWT uses JavaScript addition before JOSE parses a
                        // relative NumericDate. Preserve string concatenation,
                        // including arrays' and objects' primitive conversion.
                        return json!(format!(
                            "{}{}",
                            js_primitive_string(value),
                            ryu_js::Buffer::new().format(seconds)
                        ));
                    }
                };
                base + seconds
            }
            Self::AfterSeconds(seconds) => {
                let base = match issued_at {
                    None | Some(Value::Null) => Utc::now().timestamp() as f64,
                    Some(Value::Bool(value)) => f64::from(u8::from(*value)),
                    Some(Value::Number(value)) => value.as_f64().unwrap_or_default(),
                    Some(value) => {
                        return json!(format!(
                            "{}{}",
                            js_primitive_string(value),
                            ryu_js::Buffer::new().format(*seconds)
                        ));
                    }
                };
                base + seconds
            }
            Self::At(date) => date.timestamp() as f64,
            Self::Numeric(value) => *value,
        };
        if timestamp.fract() == 0.0 && timestamp >= i64::MIN as f64 && timestamp < i64::MAX as f64 {
            json!(timestamp as i64)
        } else {
            json!(timestamp)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwtAudience {
    One(String),
    Many(Vec<String>),
}

impl JwtAudience {
    fn matches(&self, value: &Value) -> bool {
        let expected: Vec<&str> = match self {
            Self::One(value_2) => vec![value_2],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        };
        match value {
            Value::String(value) => expected.contains(&value.as_str()),
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .any(|value_3| expected.contains(&value_3)),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct JwtClaimsConfig {
    pub issuer: Option<String>,
    pub audience: Option<JwtAudience>,
    pub expiration: JwtExpiration,
}

#[derive(Clone, Debug, Serialize)]
pub struct JwtSession {
    pub user: UserView,
    pub session: SessionView,
    /// The nested deferred-session response field. Direct completed-response
    /// hooks observe the original stored snapshot and omit this field.
    #[serde(rename = "needsRefresh", skip_serializing_if = "Option::is_none")]
    pub needs_refresh: Option<bool>,
    /// The verified cache clock seen by a direct get-session response hook.
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[async_trait]
pub trait DefineJwtPayload: Send + Sync {
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>>;
}

#[async_trait]
pub trait DefineJwtSubject: Send + Sync {
    async fn subject(&self, session: &JwtSession) -> AuthResult<Option<String>>;
}

#[async_trait]
pub trait JwtKeyring: Send + Sync {
    async fn keys(&self, context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>>;
    async fn create_key(&self, key: CreateJwk, context: &JwtKeyringContext<'_>) -> AuthResult<Jwk>;
}

/// The real endpoint context supplied to application key storage. Server-only
/// operations have a virtual endpoint path and may have no HTTP request.
#[derive(Clone, Copy, Debug)]
pub struct JwtKeyringContext<'a> {
    pub path: &'a str,
    pub request: Option<&'a AuthRequest>,
    pub endpoint: Option<&'a better_auth_core::endpoint::EndpointCall>,
}

/// One property in an application-owned remote signing payload.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RemoteJwtClaim<'a> {
    Absent,
    Undefined,
    Value(&'a better_auth_core::utils::json::JsValue),
}

/// Claims passed to a configured remote signer, before managed JOSE validation.
///
/// `raw_claims` preserves IEEE754 numbers and all supplied JSON values. The
/// added `iat` and `nbf` properties can be own properties with an undefined
/// value; use `claim` to distinguish these from absent or null properties.
/// Undefined properties are omitted from `raw_claims`, matching JSON.stringify.
#[derive(Clone, Debug)]
pub struct RemoteJwtPayload {
    raw_claims: better_auth_core::utils::json::JsValue,
    own_keys: Vec<String>,
    undefined_claims: Vec<String>,
}

impl RemoteJwtPayload {
    #[must_use]
    pub const fn raw_claims(&self) -> &better_auth_core::utils::json::JsValue {
        &self.raw_claims
    }

    /// Property names in the order observed by the application signer.
    #[must_use]
    pub fn own_keys(&self) -> &[String] {
        &self.own_keys
    }

    #[must_use]
    pub fn claim(&self, name: &str) -> RemoteJwtClaim<'_> {
        if self.undefined_claims.iter().any(|key| key == name) {
            RemoteJwtClaim::Undefined
        } else if let Some(value) = self.raw_claims.get(name) {
            RemoteJwtClaim::Value(value)
        } else {
            RemoteJwtClaim::Absent
        }
    }
}

/// An application-owned signer controls serialization, claim validation and
/// its returned token. Managed local signing rules are not applied beforehand.
#[async_trait]
pub trait SignRemoteJwt: Send + Sync {
    async fn sign(
        &self,
        payload: &RemoteJwtPayload,
        options: &JwtSignOptions,
    ) -> AuthResult<String>;
}

#[derive(Clone)]
pub struct JwtPluginConfig {
    pub jwks_path: String,
    pub remote_url: Option<String>,
    pub key_pair: JwtKeyPairConfig,
    pub additional_key_pairs: Vec<JwtKeyPairConfig>,
    pub rotation_interval: Option<Duration>,
    pub grace_period: Duration,
    pub disable_private_key_encryption: bool,
    pub disable_setting_jwt_header: bool,
    pub claims: JwtClaimsConfig,
    pub define_payload: Option<Arc<dyn DefineJwtPayload>>,
    pub define_subject: Option<Arc<dyn DefineJwtSubject>>,
    pub keyring: Option<Arc<dyn JwtKeyring>>,
    pub remote_signer: Option<Arc<dyn SignRemoteJwt>>,
}

impl std::fmt::Debug for JwtPluginConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtPluginConfig").finish_non_exhaustive()
    }
}

impl Default for JwtPluginConfig {
    fn default() -> Self {
        Self {
            jwks_path: "/jwks".to_owned(),
            remote_url: None,
            key_pair: JwtKeyPairConfig::default(),
            additional_key_pairs: vec![],
            rotation_interval: None,
            grace_period: Duration::days(30),
            disable_private_key_encryption: false,
            disable_setting_jwt_header: false,
            claims: JwtClaimsConfig::default(),
            define_payload: None,
            define_subject: None,
            keyring: None,
            remote_signer: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct JwtSignOptions {
    /// None omits the header argument; Some(empty) supplies an empty object.
    pub header: Option<Map<String, Value>>,
    pub signing_key_id: Option<String>,
    pub signing_algorithm: Option<JwtAlgorithm>,
    pub claims: Option<JwtClaimsConfig>,
    /// Reuse a key selected before constructing the payload, for example when
    /// its algorithm determines an OIDC token hash. This avoids another
    /// storage read. Remote signers continue to own key selection.
    pub resolved_key: Option<Arc<ResolvedJwtSigningKey>>,
}

/// A selected server signing key. Private material stays inside the plugin.
#[expect(
    clippy::partial_pub_fields,
    reason = "Public signing metadata keeps private key material encapsulated"
)]
pub struct ResolvedJwtSigningKey {
    pub algorithm: JwtAlgorithm,
    pub key_id: String,
    private_key: Value,
}

impl std::fmt::Debug for ResolvedJwtSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedJwtSigningKey")
            .finish_non_exhaustive()
    }
}

struct JwtVerifyPolicy<'a> {
    issuer: &'a str,
    audience: &'a JwtAudience,
    tolerance: i64,
    require_nonempty_subject: bool,
}

#[derive(Clone, Default)]
pub struct JwtPlugin {
    config: JwtPluginConfig,
}

impl std::fmt::Debug for JwtPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtPlugin").finish_non_exhaustive()
    }
}

impl JwtPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: JwtPluginConfig) -> Self {
        Self { config }
    }

    async fn keys(
        &self,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Vec<Jwk>> {
        let endpoint = better_auth_core::endpoint::current_endpoint_call_context();
        let path = endpoint
            .as_ref()
            .and_then(better_auth_core::endpoint::EndpointCall::path)
            .unwrap_or_else(|| request.map_or("virtual:", AuthRequest::path));
        self.keys_at_path(request, path, ctx).await
    }

    async fn keys_at_path(
        &self,
        request: Option<&AuthRequest>,
        path: &str,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Vec<Jwk>> {
        let endpoint = better_auth_core::endpoint::current_endpoint_call_context();
        match &self.config.keyring {
            Some(keyring) => {
                keyring
                    .keys(&JwtKeyringContext {
                        path,
                        request,
                        endpoint: endpoint.as_ref(),
                    })
                    .await
            }
            None => ctx.database.list_jwks().await,
        }
    }

    /// Provision a private signing key and its public JWK in persistent storage.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation, key serialization, or JWK storage fails.
    pub async fn create_jwk(
        &self,
        config: Option<&JwtKeyPairConfig>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Jwk> {
        let config = config.unwrap_or(&self.config.key_pair);
        let (public, private) = crypto::generate(config)?;
        let private = serde_json::to_string(&private)?;
        let private_key = if self.config.disable_private_key_encryption {
            private
        } else {
            serde_json::to_string(&encrypt(&private, &ctx.config.secret)?)?
        };
        let now = Utc::now();
        let data = CreateJwk {
            id: None,
            public_key: serde_json::to_string(&public)?,
            private_key,
            created_at: now,
            expires_at: self
                .config
                .rotation_interval
                .filter(|duration| !duration.is_zero())
                .map(|duration| now + duration),
            alg: Some(config.algorithm.as_str().to_owned()),
            crv: config.algorithm.curve().map(str::to_owned),
        };
        let endpoint = better_auth_core::endpoint::current_endpoint_call_context();
        match &self.config.keyring {
            Some(keyring) => {
                keyring
                    .create_key(
                        data,
                        &JwtKeyringContext {
                            path: endpoint
                                .as_ref()
                                .and_then(better_auth_core::endpoint::EndpointCall::path)
                                .unwrap_or_else(|| request.map_or("virtual:", AuthRequest::path)),
                            request,
                            endpoint: endpoint.as_ref(),
                        },
                    )
                    .await
            }
            None => ctx.database.create_jwk(data).await,
        }
    }

    /// Select a live key, with explicit key or algorithm pinning when requested.
    ///
    /// # Errors
    ///
    /// Returns an error if a usable signing key cannot be loaded or generated.
    pub async fn resolve_signing_key(
        &self,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Option<ResolvedJwtSigningKey>> {
        if self.config.remote_signer.is_some() {
            return Ok(None);
        }
        // Pinned IDs use findOne independently of the adapter's findMany
        // limit. Custom keyrings supply the raw full set once for this lookup.
        let mut keys = if options.signing_key_id.is_some() {
            Vec::new()
        } else {
            self.keys(request, ctx).await?
        };
        keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
        let primary = self.config.key_pair.algorithm;
        let key_alg = |key: &Jwk| {
            key.alg
                .as_deref()
                .map_or(Ok(primary), JwtAlgorithm::from_str)
        };
        let now = Utc::now();
        let live = |key: &&Jwk| key.expires_at.is_none_or(|expiry| expiry > now);
        let mut minted_unpinned_key = false;
        let mut key = if let Some(id) = &options.signing_key_id {
            let key = match &self.config.keyring {
                Some(_) => self.keys(request, ctx).await?.into_iter().find(|key| &key.id == id),
                None => ctx.database.get_jwk_by_id(id).await?,
            }.ok_or_else(|| AuthError::config(format!("signJWT: signingKeyId \"{id}\" not found in JWKS. The key must be provisioned before it can be referenced.")))?;
            if let Some(algorithm) = options.signing_algorithm
                && key_alg(&key)? != algorithm
            {
                return Err(AuthError::config(format!(
                    "signJWT: signingKeyId \"{id}\" has a different algorithm than {}",
                    algorithm.as_str()
                )));
            }
            key
        } else if let Some(algorithm) = options.signing_algorithm {
            if let Some(key) = keys
                .iter()
                .filter(live)
                .find(|key| key_alg(key).is_ok_and(|alg| alg == algorithm))
                .cloned()
            {
                key
            } else {
                let config = self
                    .config
                    .additional_key_pairs
                    .iter()
                    .find(|config| config.algorithm == algorithm)
                    .or_else(|| (primary == algorithm).then_some(&self.config.key_pair))
                    .ok_or_else(|| {
                        AuthError::config(format!(
                            "No signing key configured for {}",
                            algorithm.as_str()
                        ))
                    })?;
                self.create_jwk(Some(config), request, ctx).await?
            }
        } else {
            if let Some(key) = keys
                .iter()
                .filter(live)
                .find(|key| key_alg(key).is_ok_and(|alg| alg == primary))
                .cloned()
            {
                key
            } else {
                // Source performs a separate fallback lookup. An application
                // keyring can observe it or return a changed key set.
                let mut fallback = self.keys(request, ctx).await?;
                fallback.sort_by_key(|key| std::cmp::Reverse(key.created_at));
                if let Some(key) = fallback
                    .into_iter()
                    .find(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()))
                {
                    key
                } else {
                    minted_unpinned_key = true;
                    self.create_jwk(None, request, ctx).await?
                }
            }
        };
        if !minted_unpinned_key && key.expires_at.is_some_and(|expiry| expiry < Utc::now()) {
            if options.signing_key_id.is_some() || options.signing_algorithm.is_some() {
                return Err(AuthError::config(
                    "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.",
                ));
            }
            key = self.create_jwk(None, request, ctx).await?;
        }
        let private = if self.config.disable_private_key_encryption {
            key.private_key
        } else {
            let encrypted: String = serde_json::from_str(&key.private_key)?;
            decrypt(&encrypted, &ctx.config.secret).map_err(|_error| AuthError::config("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?
        };
        Ok(Some(ResolvedJwtSigningKey {
            algorithm: key
                .alg
                .as_deref()
                .map(JwtAlgorithm::from_str)
                .unwrap_or(Ok(primary))?,
            key_id: key.id,
            private_key: serde_json::from_str(&private)?,
        }))
    }

    /// Sign an application-owned payload through the trusted server API.
    ///
    /// # Errors
    ///
    /// Returns an error if signing-key resolution or JWT encoding fails.
    pub async fn sign_jwt(
        &self,
        payload: Map<String, Value>,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        if self.config.remote_signer.is_some() {
            return self
                .sign_remote_jwt(Value::Object(payload).into(), options, ctx)
                .await;
        }
        self.sign_jwt_checked(payload, options, request, ctx, Ok(()))
            .await
    }

    /// Sign decoded JavaScript JSON through the trusted server API.
    ///
    /// The decoded representation retains nonfinite numbers until claim
    /// validation in managed local signing. Remote signers instead receive
    /// the raw values and own-property metadata without JOSE claim validation.
    /// Local ordinary claims follow JSON.stringify, including rounding and
    /// null for nonfinite values.
    ///
    /// # Errors
    ///
    /// Returns an error if signing-key resolution, payload serialization, or JWT encoding fails.
    pub async fn sign_jwt_json(
        &self,
        payload: &better_auth_core::utils::json::JsValue,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let object = payload
            .as_object()
            .ok_or_else(|| AuthError::bad_request("JWT payload must be an object"))?;
        if self.config.remote_signer.is_some() {
            return self.sign_remote_jwt(payload.clone(), options, ctx).await;
        }
        let validation = (|| {
            for field in ["exp", "iat", "nbf"] {
                validate_numeric_date(
                    field,
                    object
                        .get(field)
                        .and_then(better_auth_core::utils::json::JsValue::as_f64),
                )?;
            }
            for field in ["iss", "sub", "jti"] {
                if object
                    .get(field)
                    .and_then(better_auth_core::utils::json::JsValue::as_f64)
                    .is_some_and(|number| {
                        !number.is_finite() && (field == "iss" || !number.is_nan())
                    })
                {
                    return Err(AuthError::internal(format!(
                        "\"{field}\" claim must be a string"
                    )));
                }
            }
            Ok(())
        })();
        let payload = payload
            .to_json_value()?
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::bad_request("JWT payload must be an object"))?;
        self.sign_jwt_checked(payload, options, request, ctx, validation)
            .await
    }

    async fn sign_jwt_checked(
        &self,
        payload: Map<String, Value>,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
        validation: AuthResult<()>,
    ) -> AuthResult<String> {
        let payload = self.default_claims(payload, options.claims.as_ref(), ctx)?;
        let resolved;
        let key = if let Some(key) = options.resolved_key.as_deref() {
            key
        } else {
            resolved = self
                .resolve_signing_key(options, request, ctx)
                .await?
                .ok_or_else(|| AuthError::internal("No local JWT signing key"))?;
            &resolved
        };
        // Upstream resolves/mints the local key before JOSE validates claims.
        validation?;
        Self::sign_resolved(payload, options, key)
    }

    async fn sign_remote_jwt(
        &self,
        mut raw_claims: better_auth_core::utils::json::JsValue,
        options: &JwtSignOptions,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        use better_auth_core::utils::json::JsValue;
        let JsValue::Object(payload) = &mut raw_claims else {
            return Err(AuthError::bad_request("JWT payload must be an object"));
        };
        let config = options.claims.as_ref().unwrap_or(&self.config.claims);
        let mut own_keys: Vec<String> = payload.keys().cloned().collect();
        // JavaScript enumerates canonical array-index property names first.
        own_keys.sort_by_key(|key| {
            key.parse::<u32>()
                .ok()
                .filter(|index| *index != u32::MAX && index.to_string() == *key)
                .map_or(u64::MAX, u64::from)
        });
        let mut undefined_claims = Vec::new();
        // Source spreads the original object, then assigns these properties in
        // this order. Undefined dates are still observable own properties.
        for name in ["iat", "exp", "nbf", "iss", "aud"] {
            if !payload.contains_key(name) {
                own_keys.push(name.to_owned());
                if name == "iat" || name == "nbf" {
                    undefined_claims.push(name.to_owned());
                }
            }
            if payload.get(name).is_none_or(JsValue::is_null) {
                let value = match name {
                    "exp" => config.expiration.timestamp_raw(payload.get("iat")),
                    "iss" => JsValue::String(
                        config
                            .issuer
                            .clone()
                            .unwrap_or_else(|| ctx.config.base_url.clone()),
                    ),
                    "aud" => serde_json::to_value(
                        config
                            .audience
                            .clone()
                            .unwrap_or_else(|| JwtAudience::One(ctx.config.base_url.clone())),
                    )?
                    .into(),
                    _ => continue,
                };
                drop(payload.insert(name.to_owned(), value));
            }
        }
        let payload = RemoteJwtPayload {
            raw_claims,
            own_keys,
            undefined_claims,
        };
        let remote = self
            .config
            .remote_signer
            .as_ref()
            .ok_or_else(|| AuthError::internal("No remote JWT signer"))?;
        remote
            .sign(&payload, options)
            .await
            .map_err(|error| match error {
                AuthError::Internal(_) => AuthError::CallbackFailure(Box::new(error)),
                error => error,
            })
    }

    fn default_claims(
        &self,
        mut payload: Map<String, Value>,
        override_claims: Option<&JwtClaimsConfig>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Map<String, Value>> {
        let config = override_claims.unwrap_or(&self.config.claims);
        if payload.get("exp").is_none_or(Value::is_null) {
            let expiration = config.expiration.timestamp(payload.get("iat"));
            drop(payload.insert("exp".to_owned(), expiration));
        }
        if payload.get("iss").is_none_or(Value::is_null) {
            drop(payload.insert(
                "iss".to_owned(),
                json!(config.issuer.as_deref().unwrap_or(&ctx.config.base_url)),
            ));
        }
        if payload.get("aud").is_none_or(Value::is_null) {
            drop(
                payload.insert(
                    "aud".to_owned(),
                    serde_json::to_value(
                        config
                            .audience
                            .clone()
                            .unwrap_or_else(|| JwtAudience::One(ctx.config.base_url.clone())),
                    )?,
                ),
            );
        }
        Ok(payload)
    }

    fn sign_resolved(
        mut payload: Map<String, Value>,
        options: &JwtSignOptions,
        key: &ResolvedJwtSigningKey,
    ) -> AuthResult<String> {
        let mut header = options.header.clone().unwrap_or_default();
        drop(header.insert("alg".to_owned(), json!(key.algorithm.as_str())));
        drop(header.insert("kid".to_owned(), json!(key.key_id)));
        validate_critical_header(&header, true)?;
        normalize_signing_claims(&mut payload)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(better_auth_core::utils::json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(better_auth_core::utils::json::to_vec(&payload)?)
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes())?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Verify a token against the persisted keyring and configured claims.
    /// Invalid signatures, malformed tokens and claim failures return `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if key loading, signature verification, or claim validation fails.
    pub async fn verify_jwt(
        &self,
        token: &str,
        issuer: Option<&str>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let claims = self.config.claims.clone();
        let issuer = issuer
            .filter(|issuer| !issuer.is_empty())
            .or(claims.issuer.as_deref())
            .unwrap_or(&ctx.config.base_url);
        let audience = claims
            .audience
            .unwrap_or_else(|| JwtAudience::One(ctx.config.base_url.clone()));
        let policy = JwtVerifyPolicy {
            issuer,
            audience: &audience,
            tolerance: 0,
            require_nonempty_subject: true,
        };
        Ok(self
            .verify_internal(token, &policy, request, ctx)
            .await
            .unwrap_or(None))
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    async fn verify_internal(
        &self,
        token: &str,
        policy: &JwtVerifyPolicy<'_>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Option<Map<String, Value>>> {
        let parts = token.split('.').collect::<Vec<_>>();
        let [header, payload, signature] = parts.as_slice() else {
            return Ok(None);
        };
        let header = decode_compact_json(header, false)?;
        let Some(header_object) = header.as_object() else {
            return Ok(None);
        };
        if validate_critical_header(header_object, false).is_err() {
            return Ok(None);
        }
        let Some(kid) = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let Some(key) = self
            .keys_at_path(request, "virtual:", ctx)
            .await?
            .into_iter()
            .find(|key| key.id == kid)
        else {
            return Ok(None);
        };
        let algorithm = key
            .alg
            .as_deref()
            .map(JwtAlgorithm::from_str)
            .unwrap_or(Ok(self.config.key_pair.algorithm))?;
        if header.get("alg").and_then(Value::as_str) != Some(algorithm.as_str()) {
            return Ok(None);
        }
        let public: Value = serde_json::from_str(&key.public_key)?;
        let input = format!("{}.{}", parts.first().copied().unwrap_or_default(), payload);
        if !crypto::verify(
            algorithm,
            &public,
            input.as_bytes(),
            &decode_compact_part(signature, true)?,
        )? {
            return Ok(None);
        }
        let Some(payload) = decode_compact_json(payload, true)?.as_object().cloned() else {
            return Ok(None);
        };
        let now = Utc::now().timestamp();
        for field in ["iat", "exp", "nbf"] {
            if payload.get(field).is_some_and(|value| !value.is_number()) {
                return Ok(None);
            }
        }
        if payload
            .get("exp")
            .and_then(Value::as_f64)
            .is_some_and(|exp| exp <= (now - policy.tolerance) as f64)
            || payload
                .get("nbf")
                .and_then(Value::as_f64)
                .is_some_and(|nbf| nbf > (now + policy.tolerance) as f64)
            || payload.get("iss").and_then(Value::as_str) != Some(policy.issuer)
            || !payload
                .get("aud")
                .is_some_and(|value| policy.audience.matches(value))
            || payload.get("aud").is_none_or(|value| !js_truthy(value))
            || (policy.require_nonempty_subject
                && payload.get("sub").is_none_or(|value| !js_truthy(value)))
        {
            return Ok(None);
        }
        Ok(Some(payload))
    }

    async fn session_token(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let read = better_auth_core::cache::runtime::authenticated(ctx, req, false)
            .await
            .map_err(|_error| unauthorized())?
            .ok_or_else(unauthorized)?;
        let session = JwtSession {
            user: match read.user {
                better_auth_core::AuthenticatedUser::Stored(user) => ctx.user_view(&user),
                better_auth_core::AuthenticatedUser::Cached(user) => *user,
            },
            // A virtual principal already carries its exact runtime snapshot;
            // applying persisted-session output defaults would add fields.
            session: req.virtual_session().cloned().unwrap_or(read.session),
            needs_refresh: read.needs_refresh,
            updated_at: None,
            version: None,
        };
        self.sign_session_token(Some(req), ctx, &session).await
    }

    async fn sign_session_token(
        &self,
        req: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
        session: &JwtSession,
    ) -> AuthResult<String> {
        let application_payload = match &self.config.define_payload {
            Some(define) => define.define_payload(session).await?,
            None => serde_json::to_value(&session.user)?
                .as_object()
                .cloned()
                .ok_or_else(|| AuthError::internal("User payload was not an object"))?,
        };
        // getJwtToken starts with iat before spreading the application payload;
        // an explicit application iat replaces the value in that position.
        let mut payload = Map::new();
        drop(payload.insert("iat".to_owned(), json!(Utc::now().timestamp())));
        payload.extend(application_payload);
        let subject = match &self.config.define_subject {
            Some(define) => define
                .subject(session)
                .await?
                .unwrap_or_else(|| session.user.id.clone()),
            None => session.user.id.clone(),
        };
        drop(payload.insert("sub".to_owned(), json!(subject)));
        self.sign_jwt(payload, &JwtSignOptions::default(), req, ctx)
            .await
    }

    async fn jwks(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if self.config.remote_url.is_some() {
            return Ok(AuthResponse::new(404).with_header("content-type", "application/json"));
        }
        Ok(AuthResponse::json(
            200,
            &self.jwks_value(Some(req), ctx).await?,
        )?)
    }

    async fn jwks_value(
        &self,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Value> {
        if self.config.remote_url.is_some() {
            return Err(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            });
        }
        let mut keys = self.keys(request, ctx).await?;
        if keys.is_empty() {
            drop(self.create_jwk(None, request, ctx).await?);
            keys = self.keys(request, ctx).await?;
        }
        if keys.is_empty() {
            return Err(AuthError::config(
                "No key sets found. Make sure you have a key in your database.",
            ));
        }
        let now = Utc::now();
        let keys = keys
            .into_iter()
            .filter(|key| {
                key.expires_at
                    .is_none_or(|expires| expires + self.config.grace_period > now)
            })
            .map(|key| {
                let mut public = Map::new();
                drop(public.insert(
                    "alg".to_owned(),
                    json!(
                        key.alg
                            .as_deref()
                            .unwrap_or(self.config.key_pair.algorithm.as_str())
                    ),
                ));
                if let Some(curve) = &key.crv {
                    drop(public.insert("crv".to_owned(), json!(curve)));
                }
                let parsed: Map<String, Value> = serde_json::from_str(&key.public_key)?;
                public.extend(parsed);
                drop(public.insert("kid".to_owned(), json!(key.id)));
                Ok::<_, AuthError>(public)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(json!({ "keys": keys }))
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for JwtPlugin {
    fn name(&self) -> &'static str {
        "jwt"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get(&self.config.jwks_path, "get_jwks"),
            AuthRoute::get("/token", "get_token"),
        ]
    }
    fn server_endpoints(&self) -> Vec<better_auth_core::endpoint::EndpointDefinition> {
        endpoint::definitions(&self.config.jwks_path)
    }

    fn validate_endpoint(
        &self,
        call: &better_auth_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::endpoint::EndpointInput> {
        endpoint::validate(call)
    }

    async fn on_endpoint(
        &self,
        call: &better_auth_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::endpoint::EndpointResponse> {
        self.call_endpoint(call, ctx).await
    }

    async fn on_init(&self, _ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        if self.config.jwks_path.is_empty()
            || !self.config.jwks_path.starts_with('/')
            || self.config.jwks_path.contains("..")
        {
            return Err(AuthError::config(
                "JWKS path must start with '/' and not contain '..'",
            ));
        }
        if self.config.remote_signer.is_some() && self.config.remote_url.is_none() {
            return Err(AuthError::config(
                "Remote JWKS URL must be set when using a custom JWT signer",
            ));
        }
        Ok(())
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, path) if path == self.config.jwks_path => {
                Ok(Some(self.jwks(req, ctx).await.map_err(public_jwt_error)?))
            }
            (HttpMethod::Get, "/token") => Ok(Some(AuthResponse::json(
                200,
                &json!({ "token": self.session_token(req, ctx).await.map_err(public_jwt_error)? }),
            )?)),
            _ => Ok(None),
        }
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if req.path() != "/get-session" || self.config.disable_setting_jwt_header {
            return Ok(response);
        }
        let Some((user, session)) = req.session_hook_snapshot() else {
            return Ok(response);
        };
        let cache = better_auth_core::cache::runtime::session_hook_cache_metadata(req);
        let token = self
            .sign_session_token(
                Some(req),
                ctx,
                &JwtSession {
                    user,
                    session,
                    needs_refresh: None,
                    updated_at: cache.as_ref().map(|metadata| metadata.updated_at),
                    version: cache.and_then(|metadata| metadata.version),
                },
            )
            .await
            .map_err(public_jwt_error)?;
        let mut expose = response
            .headers
            .get("access-control-expose-headers")
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .fold(Vec::new(), |mut headers, header| {
                if !headers.iter().any(|existing| existing == header) {
                    headers.push(header.to_owned());
                }
                headers
            });
        if !expose.iter().any(|header| header == "set-auth-jwt") {
            expose.push("set-auth-jwt".to_owned());
        }
        drop(response.headers.insert("set-auth-jwt", token));
        drop(
            response
                .headers
                .insert("access-control-expose-headers", expose.join(", ")),
        );
        Ok(response)
    }
}

fn public_jwt_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Config(_)
        | AuthError::Database(_)
        | AuthError::Serialization(_)
        | AuthError::Plugin { .. }
        | AuthError::Internal(_)
        | AuthError::PasswordHash(_)
        | AuthError::Jwt(_) => AuthError::CallbackFailure(Box::new(error)),
        error => error,
    }
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => better_auth_core::utils::json::number_as_f64(value)
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn js_raw_primitive_string(value: &better_auth_core::utils::json::JsValue) -> String {
    use better_auth_core::utils::json::JsValue;
    match value {
        JsValue::Null => "null".to_owned(),
        JsValue::String(value) => value.clone(),
        JsValue::Bool(value) => value.to_string(),
        JsValue::Number(value) if value.is_nan() => "NaN".to_owned(),
        JsValue::Number(value) if *value == f64::INFINITY => "Infinity".to_owned(),
        JsValue::Number(value) if *value == f64::NEG_INFINITY => "-Infinity".to_owned(),
        JsValue::Number(value) => serde_json::Number::from_f64(*value)
            .and_then(|number| better_auth_core::utils::json::number_to_string(&number).ok())
            .unwrap_or_default(),
        JsValue::Array(values) => values
            .iter()
            .map(|value| {
                if value.is_null() {
                    String::new()
                } else {
                    js_raw_primitive_string(value)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        JsValue::Object(_) => "[object Object]".to_owned(),
    }
}

fn js_primitive_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.as_f64().unwrap_or_default().to_string(),
        Value::Array(values) => values
            .iter()
            .map(|value_2| {
                if value_2.is_null() {
                    String::new()
                } else {
                    js_primitive_string(value_2)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_owned(),
    }
}

fn decode_compact_part(value: &str, allow_whitespace: bool) -> AuthResult<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    // Bun's JOSE decoder accepts these five ASCII whitespace characters and
    // unused trailing bits, while requiring the exact optional padding count.
    let bytes = value
        .bytes()
        .filter(|byte| !allow_whitespace || !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
        .collect::<Vec<_>>();
    let end = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(bytes.len());
    let (encoded, padded) = bytes
        .split_at_checked(end)
        .ok_or_else(|| AuthError::bad_request("Invalid JWT base64url encoding"))?;
    let padding = padded.len();
    if padding > 0
        && (padding > 2
            || !padded.iter().all(|byte| *byte == b'=')
            || end % 4 == 0
            || bytes.len() % 4 != 0)
    {
        return Err(AuthError::bad_request("Invalid JWT base64url encoding"));
    }
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
    .decode(encoded)
    .map_err(|_error| AuthError::bad_request("Invalid JWT base64url encoding"))
}

fn decode_compact_json(value: &str, allow_whitespace: bool) -> AuthResult<Value> {
    let bytes = decode_compact_part(value, allow_whitespace)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_error| AuthError::bad_request("Invalid JWT JSON UTF8"))?;
    Ok(better_auth_core::utils::json::parse_value(text)?.to_json_value()?)
}

fn validate_numeric_date(field: &str, number: Option<f64>) -> AuthResult<()> {
    if number.is_some_and(|number| !number.is_finite()) {
        return Err(AuthError::internal(format!("Invalid {field} input")));
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn normalize_signing_claims(payload: &mut Map<String, Value>) -> AuthResult<()> {
    let now = Utc::now().timestamp();
    for field in ["exp", "iat", "nbf"] {
        if let Some(value) = payload.get(field)
            && (field == "exp" || js_truthy(value))
        {
            let value = match value {
                Value::Number(number) => {
                    validate_numeric_date(
                        field,
                        better_auth_core::utils::json::number_as_f64(number),
                    )?;
                    value.clone()
                }
                Value::String(value) => json!(now as f64 + relative_numeric_date(value)?),
                Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
                    return Err(AuthError::internal("Invalid time period format"));
                }
            };
            drop(payload.insert(field.to_owned(), value));
        }
    }
    for field in ["iss", "sub", "jti"] {
        if let Some(value) = payload.get(field)
            && (field == "iss" || js_truthy(value))
            && !value.is_string()
        {
            return Err(AuthError::internal(format!(
                "\"{field}\" claim must be a string"
            )));
        }
    }
    if let Some(value) = payload.get("aud")
        && !value.is_string()
        && !value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err(AuthError::internal(
            "\"aud\" claim must be a string or an array of strings",
        ));
    }
    Ok(())
}

// JOSE's relative NumericDate grammar, including its rounding and year length.
fn relative_numeric_date(value: &str) -> AuthResult<f64> {
    let invalid = || AuthError::internal("Invalid time period format");
    let lower = value.to_ascii_lowercase();
    let ago = value.ends_with(" ago");
    let (value, suffix) = if lower.ends_with(" from now") {
        (
            value
                .get(..value.len().saturating_sub(9))
                .ok_or_else(invalid)?,
            true,
        )
    } else if lower.ends_with(" ago") {
        (
            value
                .get(..value.len().saturating_sub(4))
                .ok_or_else(invalid)?,
            true,
        )
    } else {
        (value, false)
    };
    let (number, negative, signed) = value.strip_prefix('-').map_or_else(
        || {
            value
                .strip_prefix('+')
                .map_or((value, false, false), |value| (value, false, true))
        },
        |value| (value, true, true),
    );
    if suffix && signed {
        return Err(invalid());
    }
    let number = number.strip_prefix(' ').unwrap_or(number);
    let split = number
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .ok_or_else(invalid)?;
    let digits = number.get(..split).ok_or_else(invalid)?;
    let unit = number.get(split..).ok_or_else(invalid)?;
    let unit = unit.strip_prefix(' ').unwrap_or(unit).to_ascii_lowercase();
    let mut parts = digits.split('.');
    if !parts
        .next()
        .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        || parts
            .next()
            .is_some_and(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || parts.next().is_some()
    {
        return Err(invalid());
    }
    let multiplier = match unit.as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
        "d" | "day" | "days" => 86400.0,
        "w" | "week" | "weeks" => 604_800.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600.0,
        _ => return Err(invalid()),
    };
    let seconds = digits
        .parse::<f64>()
        .map_err(|_error| invalid())?
        .mul_add(multiplier, 0.5)
        .floor();
    if !seconds.is_finite() {
        return Err(invalid());
    }
    // The reference regex is case insensitive; its `ago` sign check is literal.
    let negative = negative || ago;
    Ok(if negative { -seconds } else { seconds })
}

fn validate_critical_header(header: &Map<String, Value>, signing: bool) -> AuthResult<()> {
    let Some(critical) = header.get("crit") else {
        return Ok(());
    };
    let critical = critical.as_array().filter(|values| {
        !values.is_empty() && values.iter().all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
    }).ok_or_else(|| AuthError::internal("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present"))?;
    if signing {
        let mut seen = std::collections::HashSet::new();
        if critical
            .iter()
            .any(|value| !seen.insert(value.as_str().unwrap_or_default()))
        {
            return Err(AuthError::internal(
                "\"crit\" (Critical) Header Parameter MUST NOT contain duplicate values",
            ));
        }
    }
    for value in critical {
        let parameter = value.as_str().unwrap_or_default();
        if parameter != "b64" {
            return Err(AuthError::internal(format!(
                "Extension Header Parameter \"{parameter}\" is not recognized"
            )));
        }
        match header.get("b64") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => {
                return Err(AuthError::internal("JWTs MUST NOT use unencoded payload"));
            }
            None => {
                return Err(AuthError::internal(
                    "Extension Header Parameter \"b64\" is missing",
                ));
            }
            _ => {
                return Err(AuthError::internal(
                    "The \"b64\" (base64url-encode payload) Header Parameter must be a boolean",
                ));
            }
        }
    }
    Ok(())
}

const fn unauthorized() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
    }
}
