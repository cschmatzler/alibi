//! Asymmetric session JWTs, public JWKS, and trusted server-side signing.

mod crypto;
mod endpoint;
use super::token_crypto::{decrypt_with_config, encrypt_with_config};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateJwk, HttpMethod, Jwk,
};
use chrono::{DateTime, Duration, Utc};
pub use endpoint::{JwtTokenOutput, JwtVerifyOutput};
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
    /// Protect JWT session cookies using the managed local keyring.
    pub session_cookie_cache: bool,
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
            session_cookie_cache: false,
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

    async fn keys_in_transaction<S: AuthSchema>(
        &self,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
    ) -> AuthResult<Vec<Jwk>> {
        if self.config.keyring.is_none()
            && let Some(transaction) = transaction
        {
            transaction.list_jwks().await
        } else {
            self.keys(request, ctx).await
        }
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
    pub async fn create_jwk<S: AuthSchema>(
        &self,
        config: Option<&JwtKeyPairConfig>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Jwk> {
        self.create_jwk_in_transaction(config, request, ctx, None)
            .await
    }

    async fn create_jwk_in_transaction<S: AuthSchema>(
        &self,
        config: Option<&JwtKeyPairConfig>,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
    ) -> AuthResult<Jwk> {
        let config = config.unwrap_or(&self.config.key_pair);
        let (public, private) = crypto::generate(config)?;
        let private = serde_json::to_string(&private)?;
        let private_key = if self.config.disable_private_key_encryption {
            private
        } else {
            serde_json::to_string(&encrypt_with_config(&private, &ctx.config)?)?
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
            None => match transaction {
                Some(transaction) => transaction.create_jwk(data).await,
                None => ctx.database.create_jwk(data).await,
            },
        }
    }

    /// Select a live key, with explicit key or algorithm pinning when requested.
    ///
    /// # Errors
    ///
    /// Returns an error if a usable signing key cannot be loaded or generated.
    pub async fn resolve_signing_key<S: AuthSchema>(
        &self,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<ResolvedJwtSigningKey>> {
        self.resolve_signing_key_in_transaction(options, request, ctx, None)
            .await
    }

    async fn resolve_signing_key_in_transaction<S: AuthSchema>(
        &self,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
    ) -> AuthResult<Option<ResolvedJwtSigningKey>> {
        if self.config.remote_signer.is_some() {
            return Ok(None);
        }
        // Pinned IDs use findOne independently of the adapter's findMany
        // limit. Custom keyrings supply the raw full set once for this lookup.
        let mut keys = if options.signing_key_id.is_some() {
            Vec::new()
        } else {
            self.keys_in_transaction(request, ctx, transaction).await?
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
                Some(_) => self.keys_in_transaction(request, ctx, transaction).await?.into_iter().find(|key| &key.id == id),
                None => match transaction {Some(transaction)=>transaction.get_jwk_by_id(id).await?,None=>ctx.database.get_jwk_by_id(id).await?},
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
                self.create_jwk_in_transaction(Some(config), request, ctx, transaction)
                    .await?
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
                let mut fallback = self.keys_in_transaction(request, ctx, transaction).await?;
                fallback.sort_by_key(|key| std::cmp::Reverse(key.created_at));
                if let Some(key) = fallback
                    .into_iter()
                    .find(|key| key.expires_at.is_none_or(|expiry| expiry > Utc::now()))
                {
                    key
                } else {
                    minted_unpinned_key = true;
                    self.create_jwk_in_transaction(None, request, ctx, transaction)
                        .await?
                }
            }
        };
        if !minted_unpinned_key && key.expires_at.is_some_and(|expiry| expiry < Utc::now()) {
            if options.signing_key_id.is_some() || options.signing_algorithm.is_some() {
                return Err(AuthError::config(
                    "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.",
                ));
            }
            key = self
                .create_jwk_in_transaction(None, request, ctx, transaction)
                .await?;
        }
        let private = if self.config.disable_private_key_encryption {
            key.private_key
        } else {
            let encrypted: String = serde_json::from_str(&key.private_key)?;
            decrypt_with_config(&encrypted, &ctx.config).map_err(|_error| AuthError::config("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?
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

    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
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
        if self.config.session_cookie_cache {
            if ctx
                .config
                .session
                .cookie_cache
                .as_ref()
                .is_none_or(|cache| cache.strategy != better_auth_core::CookieCacheStrategy::Jwt)
            {
                return Err(AuthError::config(
                    "Managed JWT session caching requires the JWT cookie-cache strategy",
                ));
            }
            if self.config.remote_signer.is_some() {
                return Err(AuthError::config(
                    "Managed JWT session caching requires locally managed signing keys",
                ));
            }
            ctx.extensions
                .insert(better_auth_core::cache::jwt::CookieCacheSignerHandle::<S>(
                    Arc::new(self.clone()),
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

#[async_trait]
impl<S: AuthSchema> better_auth_core::cache::jwt::CookieCacheSigner<S> for JwtPlugin {
    async fn sign(
        &self,
        payload: Value,
        max_age: f64,
        ctx: &AuthContext<S>,
        transaction: Option<&dyn better_auth_core::store::AuthTransaction<S>>,
    ) -> AuthResult<String> {
        let key = self
            .resolve_signing_key_in_transaction(&JwtSignOptions::default(), None, ctx, transaction)
            .await?
            .ok_or_else(|| {
                AuthError::config(
                    "Managed JWT session caching requires locally managed signing keys",
                )
            })?;
        let mut payload = better_auth_core::cache::jwt::time_claims(payload, max_age)?;
        let claims = payload
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Invalid session cache payload"))?;
        let sid = claims
            .get("session")
            .and_then(|session| session.get("token"))
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing session token"))?;
        let sub = claims
            .get("user")
            .and_then(|user| user.get("id"))
            .cloned()
            .ok_or_else(|| AuthError::internal("Missing session owner"))?;
        drop(claims.insert("sid".into(), sid));
        drop(claims.insert("sub".into(), sub));
        drop(claims.insert("iss".into(), json!(cache_issuer(ctx))));
        drop(claims.insert("aud".into(), json!("better-auth:session-cache")));
        let options = JwtSignOptions {
            header: Some(serde_json::from_value(
                json!({"typ":"better-auth.session-cache+jwt"}),
            )?),
            ..JwtSignOptions::default()
        };
        Self::sign_resolved(claims.clone(), &options, &key)
    }

    async fn verify(&self, token: &str, ctx: &AuthContext<S>) -> AuthResult<Option<Value>> {
        let header = match token
            .split('.')
            .next()
            .and_then(|header| decode_compact_json(header, false).ok())
        {
            Some(header) => header,
            None => return Ok(None),
        };
        if header.get("typ").and_then(Value::as_str) != Some("better-auth.session-cache+jwt") {
            return Ok(None);
        }
        let audience = JwtAudience::One("better-auth:session-cache".into());
        let policy = JwtVerifyPolicy {
            issuer: cache_issuer(ctx),
            audience: &audience,
            tolerance: 15,
            require_nonempty_subject: true,
        };
        let Some(payload) = self
            .verify_internal(token, &policy, None, ctx)
            .await
            .unwrap_or(None)
        else {
            return Ok(None);
        };
        if payload.get("sub") != payload.get("user").and_then(|user| user.get("id"))
            || payload.get("sid")
                != payload
                    .get("session")
                    .and_then(|session| session.get("token"))
        {
            return Ok(None);
        }
        Ok(Some(Value::Object(payload)))
    }
}

fn cache_issuer<S: AuthSchema>(ctx: &AuthContext<S>) -> &str {
    if ctx.config.base_url.is_empty() {
        "better-auth:session-cache"
    } else {
        &ctx.config.base_url
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "asserted JWT contracts with real keys and SQLite"
    )]

    use super::*;
    use crate::plugins::test_helpers;
    use crate::plugins::token_crypto::{decrypt, encrypt};
    use better_auth_core::CreateUser;

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    struct ApplicationClaims;

    #[async_trait]
    impl DefineJwtPayload for ApplicationClaims {
        async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
            Ok(
            json!({"purpose":"application","ownerId":session.user.id,"loginId":session.session.id})
                .as_object()
                .unwrap()
                .clone(),
        )
        }
    }

    struct ApplicationSubject(Option<String>);

    #[async_trait]
    impl DefineJwtSubject for ApplicationSubject {
        async fn subject(&self, _session: &JwtSession) -> AuthResult<Option<String>> {
            Ok(self.0.clone())
        }
    }

    struct ApplicationKeyring {
        database: Arc<dyn better_auth_core::AuthStore<TestSchema>>,
    }

    #[async_trait]
    impl JwtKeyring for ApplicationKeyring {
        async fn keys(&self, _context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
            self.database.list_jwks().await
        }
        async fn create_key(
            &self,
            mut key: CreateJwk,
            context: &JwtKeyringContext<'_>,
        ) -> AuthResult<Jwk> {
            if context.request.map(AuthRequest::path) != Some("/jwks") {
                return Err(AuthError::forbidden(
                    "Application key provisioning requires its public key request",
                ));
            }
            key.id = Some("application-signing-key".to_owned());
            self.database.create_jwk(key).await
        }
    }

    struct ApplicationSigner {
        context: AuthContext<TestSchema>,
        plugin: JwtPlugin,
    }

    #[async_trait]
    impl SignRemoteJwt for ApplicationSigner {
        async fn sign(
            &self,
            payload: &RemoteJwtPayload,
            options: &JwtSignOptions,
        ) -> AuthResult<String> {
            self.plugin
                .sign_jwt_json(payload.raw_claims(), options, None, &self.context)
                .await
        }
    }

    fn payload(subject: &str) -> Map<String, Value> {
        json!({ "sub": subject, "application": "jwt-tests" })
            .as_object()
            .unwrap()
            .clone()
    }

    fn decoded(token: &str) -> (Value, Value) {
        let parts = token.split('.').collect::<Vec<_>>();
        (
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
        )
    }

    #[tokio::test]
    async fn default_keys_are_encrypted_and_jwt_claims_signature_and_public_material_are_real() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let token = plugin
            .sign_jwt(payload("subject-1"), &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let (header, claims) = decoded(&token);
        assert_eq!(header["alg"], "EdDSA");
        assert!(header.get("typ").is_none());
        assert!(claims.get("iat").is_none());
        assert_eq!(claims["iss"], ctx.config.base_url);
        assert_eq!(claims["aud"], ctx.config.base_url);
        assert!((claims["exp"].as_i64().unwrap() - Utc::now().timestamp() - 900).abs() <= 1);
        let keys = ctx.database.list_jwks().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(header["kid"], keys[0].id);
        assert!(serde_json::from_str::<String>(&keys[0].private_key).is_ok());
        assert!(!keys[0].private_key.contains("\"d\""));
        let private = decrypt(
            &serde_json::from_str::<String>(&keys[0].private_key).unwrap(),
            &ctx.config.secret,
        )
        .unwrap();
        assert!(serde_json::from_str::<Value>(&private).unwrap()["d"].is_string());
        let public = plugin
            .jwks(
                &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
                &ctx,
            )
            .await
            .unwrap();
        let public: Value = serde_json::from_slice(&public.body).unwrap();
        assert_eq!(public["keys"][0]["kid"], header["kid"]);
        assert_eq!(public["keys"][0]["crv"], "Ed25519");
        assert!(public["keys"][0].get("d").is_none());
        assert!(public["keys"][0].get("privateKey").is_none());
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .unwrap(),
            claims.as_object().unwrap().clone()
        );
    }

    #[tokio::test]
    async fn explicit_key_pinning_is_independent_of_the_public_keyring_limit() {
        use better_auth_seaorm::{Database, SeaOrmStore};
        let mut config = test_helpers::create_test_config();
        config.advanced.database.default_find_many_limit = 1;
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let ctx = AuthContext::<TestSchema>::new(
            Arc::new(config.clone()),
            Arc::new(SeaOrmStore::<TestSchema>::new(
                config.clone(),
                database.clone(),
            )),
        );
        let plugin = JwtPlugin::new();
        let first = plugin.create_jwk(None, None, &ctx).await.unwrap();
        let pinned = plugin.create_jwk(None, None, &ctx).await.unwrap();
        assert_eq!(
            ctx.database
                .list_jwks()
                .await
                .unwrap()
                .iter()
                .map(|key| key.id.as_str())
                .collect::<Vec<_>>(),
            vec![first.id.as_str()]
        );
        let token = plugin
            .sign_jwt(
                payload("pinned-owner"),
                &JwtSignOptions {
                    signing_key_id: Some(pinned.id.clone()),
                    ..Default::default()
                },
                None,
                &ctx,
            )
            .await
            .expect("explicit key lookup must use findOne rather than a limited public list");
        assert_eq!(decoded(&token).0["kid"], pinned.id);
        // Verification intentionally uses findMany and cannot see this key under
        // the same limit. A full keyring verifies the actual issued signature.
        assert!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        config.advanced.database.default_find_many_limit = 100;
        let full = AuthContext::<TestSchema>::new(
            Arc::new(config.clone()),
            Arc::new(SeaOrmStore::<TestSchema>::new(config, database)),
        );
        assert_eq!(full.database.list_jwks().await.unwrap().len(), 2);
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &full)
                .await
                .unwrap()
                .unwrap()["sub"],
            "pinned-owner"
        );
    }

    #[tokio::test]
    async fn verification_rejects_tampering_wrong_claims_unknown_key_and_algorithm_confusion() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let options = JwtSignOptions::default();
        for overrides in [
            json!({"iss":"wrong-issuer"}),
            json!({"aud":"wrong-audience"}),
            json!({"exp":0}),
            json!({"nbf":Utc::now().timestamp()+1000}),
            json!({"sub":""}),
        ] {
            let mut claims = payload("subject-1");
            claims.extend(overrides.as_object().unwrap().clone());
            let token = plugin.sign_jwt(claims, &options, None, &ctx).await.unwrap();
            assert!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let token = plugin
            .sign_jwt(payload("subject-1"), &options, None, &ctx)
            .await
            .unwrap();
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        let mut header = decoded(&token).0;
        header["kid"] = json!("unknown-key");
        parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        assert!(
            plugin
                .verify_jwt(&parts.join("."), None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        header["kid"] = decoded(&token).0["kid"].clone();
        header["alg"] = json!("HS256");
        parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        assert!(
            plugin
                .verify_jwt(&parts.join("."), None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        parts[0] = token.split('.').next().unwrap().to_owned();
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload("wrong-user")).unwrap());
        assert!(
            plugin
                .verify_jwt(&parts.join("."), None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        for malformed in ["", "two.parts", "a.b.c", "a.b.c.d"] {
            assert!(
                plugin
                    .verify_jwt(malformed, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            plugin
                .verify_jwt(&token, Some("wrong-issuer"), None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    async fn signing_normalizes_jose_numeric_dates_and_rejects_invalid_claim_types() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        for (expiry, seconds) in [
            ("1m", 60.0),
            (" 1.5 minutes", 90.0),
            ("+1 hr", 3600.0),
            ("1 minute ago", -60.0),
            ("1 minute AGO", 60.0),
            ("1 year from now", 31_557_600.0),
            ("-0.5 secs", -1.0),
        ] {
            let before = Utc::now().timestamp() as f64;
            let mut claims = payload("subject");
            drop(claims.insert("exp".to_owned(), json!(expiry)));
            let token = plugin
                .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
                .await
                .unwrap();
            let after = Utc::now().timestamp() as f64;
            let expiry_2 = decoded(&token).1["exp"].as_f64().unwrap();
            assert!(expiry_2 >= before + seconds && expiry_2 <= after + seconds);
            assert_eq!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some(),
                seconds > 0.0,
            );
        }
        for overrides in [
            json!({"exp":"invalid"}),
            json!({"exp":"+1m ago"}),
            json!({"exp":false}),
            json!({"iat":true}),
            json!({"nbf":true}),
            json!({"iss":123}),
            json!({"sub":123}),
            json!({"jti":true}),
            json!({"aud":[ctx.config.base_url,123]}),
            json!({"iat":"1m"}),
            json!({"iat":""}),
        ] {
            let mut claims = payload("subject");
            claims.extend(overrides.as_object().unwrap().clone());
            assert!(
                plugin
                    .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
                    .await
                    .is_err()
            );
        }
        let mut relative_iat = payload("relative-iat-owner");
        relative_iat.extend(
            json!({"iat":"1m","exp":4_102_444_800_i64})
                .as_object()
                .unwrap()
                .clone(),
        );
        let before = Utc::now().timestamp();
        let token = plugin
            .sign_jwt(relative_iat, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let claims = decoded(&token).1;
        assert!(claims["iat"].as_f64().unwrap() >= (before + 60) as f64);
        assert!(claims["iat"].as_f64().unwrap() <= (Utc::now().timestamp() + 60) as f64);
        assert_eq!(claims["exp"], 4_102_444_800_i64);
        let mut false_iat = payload("false-iat-owner");
        drop(false_iat.insert("iat".to_owned(), json!(false)));
        let token_2 = plugin
            .sign_jwt(false_iat, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        assert_eq!(decoded(&token_2).1["iat"], false);
        assert_eq!(decoded(&token_2).1["exp"], 900);
        // Falsy optional claims are retained by the pinned signer rather than sent
        // to JOSE's setters; its verifier still checks NumericDate types.
        let token_3 = plugin
            .sign_jwt(
                json!({"sub":"subject","iat":null,"jti":false})
                    .as_object()
                    .unwrap()
                    .clone(),
                &JwtSignOptions::default(),
                None,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(decoded(&token_3).1["jti"], false);
        assert!(
            plugin
                .verify_jwt(&token_3, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn signing_and_verification_enforce_jose_headers_and_externally_signed_claims() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let key = plugin
            .resolve_signing_key(&JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap()
            .unwrap();
        let claims = json!({"sub":"subject","exp":4_102_444_800_i64,"iss":ctx.config.base_url,"aud":ctx.config.base_url});
        for (header, signs, verifies) in [
            (json!({}), true, true),
            (json!({"crit":["unknown"],"unknown":true}), false, false),
            (json!({"crit":[]}), false, false),
            (json!({"crit":["b64"]}), false, false),
            (json!({"crit":["b64"],"b64":false}), false, false),
            (json!({"crit":["b64"],"b64":true}), true, true),
            (json!({"crit":["b64","b64"],"b64":true}), false, true),
            (json!({"b64":false}), true, true),
        ] {
            let mut header = header.as_object().unwrap().clone();
            let options = JwtSignOptions {
                header: Some(header.clone()),
                ..Default::default()
            };
            assert_eq!(
                plugin
                    .sign_jwt(claims.as_object().unwrap().clone(), &options, None, &ctx)
                    .await
                    .is_ok(),
                signs
            );
            drop(header.insert("alg".to_owned(), json!(key.algorithm.as_str())));
            drop(header.insert("kid".to_owned(), json!(key.key_id)));
            // Use the key directly to create a cryptographically valid JWT even
            // when the public signer correctly refuses its extension header.
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature =
                crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
            let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
            assert_eq!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some(),
                verifies
            );
        }
        // JOSE verifies the signature and the pinned helper then applies JS
        // truthiness to sub. Preserve this upstream behavior for externally signed
        // tokens, including truthy JSON values the built-in signer refuses.
        for (subject, verifies) in [
            (json!(123), true),
            (json!(true), true),
            (json!([]), true),
            (json!({}), true),
            (json!(false), false),
            (Value::Null, false),
            (json!(""), false),
        ] {
            let mut claims = claims.as_object().unwrap().clone();
            drop(claims.insert("sub".to_owned(), subject));
            let header = json!({"alg":key.algorithm.as_str(),"kid":key.key_id});
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature =
                crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
            let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
            assert_eq!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some(),
                verifies
            );
        }
        for invalid in [
            json!({"iat":"invalid"}),
            json!({"exp":"1m"}),
            json!({"nbf":true}),
        ] {
            let mut claims = claims.as_object().unwrap().clone();
            claims.extend(invalid.as_object().unwrap().clone());
            let header = json!({"alg":key.algorithm.as_str(),"kid":key.key_id});
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature =
                crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
            let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
            assert!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn verification_imports_persisted_jwk_metadata_as_the_pinned_runtime_does() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let (public, private) = crypto::generate(&JwtKeyPairConfig::default()).unwrap();
        let claims = json!({"sub":"subject","exp":4_102_444_800_i64,"iss":ctx.config.base_url,"aud":ctx.config.base_url});
        for (index, (metadata, verifies)) in [
            (json!({}), true),
            (json!({"ext":false}), true),
            (json!({"key_ops":["verify"]}), true),
            // importJWK removes alg and use before WebCrypto imports the key.
            (json!({"alg":"HS256","use":"enc"}), true),
            (json!({"kty":"EC"}), false),
            (json!({"crv":"P-256"}), false),
            (json!({"ext":"false"}), false),
            (json!({"key_ops":[]}), false),
            (json!({"key_ops":["sign"]}), false),
            (json!({"key_ops":["verify","verify"]}), false),
            (json!({"d":private["d"]}), false),
        ]
        .into_iter()
        .enumerate()
        {
            let mut material = public.as_object().unwrap().clone();
            material.extend(metadata.as_object().unwrap().clone());
            let key = ctx
                .database
                .create_jwk(CreateJwk {
                    id: Some(format!("metadata-{index}")),
                    public_key: serde_json::to_string(&material).unwrap(),
                    private_key: serde_json::to_string(&private).unwrap(),
                    created_at: Utc::now(),
                    expires_at: None,
                    alg: Some("EdDSA".to_owned()),
                    crv: Some("Ed25519".to_owned()),
                })
                .await
                .unwrap();
            let header = json!({"alg":"EdDSA","kid":key.id});
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            );
            let signature = crypto::sign(JwtAlgorithm::EdDsa, &private, input.as_bytes()).unwrap();
            let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
            assert_eq!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some(),
                verifies
            );
        }
    }

    #[tokio::test]
    async fn all_official_algorithms_generate_sign_and_verify_with_matching_jwks() {
        for algorithm in [
            JwtAlgorithm::EdDsa,
            JwtAlgorithm::Es256,
            JwtAlgorithm::Es512,
            JwtAlgorithm::Rs256,
            JwtAlgorithm::Ps256,
        ] {
            let ctx = test_helpers::create_test_context().await;
            let plugin = JwtPlugin::with_config(JwtPluginConfig {
                key_pair: JwtKeyPairConfig {
                    algorithm,
                    modulus_length: None,
                },
                ..Default::default()
            });
            let claims = json!({ "sub": "subject", "iat": 100, "exp": 4_102_444_800_i64 })
                .as_object()
                .unwrap()
                .clone();
            let token = plugin
                .sign_jwt(claims.clone(), &JwtSignOptions::default(), None, &ctx)
                .await
                .unwrap();
            let (header, _) = decoded(&token);
            assert_eq!(header["alg"], algorithm.as_str());
            let repeated = plugin
                .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
                .await
                .unwrap();
            assert_eq!(decoded(&token), decoded(&repeated));
            if matches!(algorithm, JwtAlgorithm::EdDsa | JwtAlgorithm::Rs256) {
                assert_eq!(token, repeated);
            } else {
                // Pinned WebCrypto uses fresh ECDSA nonces and PSS salt even when
                // the exact protected header and claims are signed twice.
                assert_ne!(token, repeated);
            }
            assert!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some()
            );
            let key = ctx
                .database
                .get_jwk_by_id(header["kid"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(key.alg.as_deref(), Some(algorithm.as_str()));
            assert_eq!(key.crv.as_deref(), algorithm.curve());
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn rotation_keeps_public_keys_for_grace_and_pinning_never_silently_changes_keys() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            grace_period: Duration::hours(2),
            ..Default::default()
        });
        let (public, private) = crypto::generate(&JwtKeyPairConfig::default()).unwrap();
        let old = ctx
            .database
            .create_jwk(CreateJwk {
                id: Some("expired-key".to_owned()),
                public_key: serde_json::to_string(&public).unwrap(),
                private_key: serde_json::to_string(
                    &encrypt(
                        &serde_json::to_string(&private).unwrap(),
                        &ctx.config.secret,
                    )
                    .unwrap(),
                )
                .unwrap(),
                created_at: Utc::now() - Duration::days(1),
                expires_at: Some(Utc::now() - Duration::hours(1)),
                alg: Some("EdDSA".to_owned()),
                crv: Some("Ed25519".to_owned()),
            })
            .await
            .unwrap();
        let old_token = JwtPlugin::sign_resolved(
            plugin
                .default_claims(payload("old-subject"), None, &ctx)
                .unwrap(),
            &JwtSignOptions::default(),
            &ResolvedJwtSigningKey {
                algorithm: JwtAlgorithm::EdDsa,
                key_id: old.id.clone(),
                private_key: private,
            },
        )
        .unwrap();
        let current_token = plugin
            .sign_jwt(
                payload("new-subject"),
                &JwtSignOptions::default(),
                None,
                &ctx,
            )
            .await
            .unwrap();
        assert_ne!(decoded(&current_token).0["kid"], old.id);
        let jwks = plugin
            .jwks(
                &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&jwks.body).unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            plugin
                .verify_jwt(&old_token, None, None, &ctx)
                .await
                .unwrap()
                .is_some()
        );
        let beyond_grace = JwtPlugin::with_config(JwtPluginConfig {
            grace_period: Duration::seconds(1),
            ..Default::default()
        });
        let jwks_2 = beyond_grace
            .jwks(
                &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&jwks_2.body).unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Server verification deliberately reads the keyring, even after the
        // public endpoint's grace window has ended, matching the pinned runtime.
        assert!(
            beyond_grace
                .verify_jwt(&old_token, None, None, &ctx)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            plugin
                .sign_jwt(
                    payload("subject"),
                    &JwtSignOptions {
                        signing_key_id: Some(old.id),
                        ..Default::default()
                    },
                    None,
                    &ctx
                )
                .await
                .is_err()
        );
        assert!(
            plugin
                .sign_jwt(
                    payload("subject"),
                    &JwtSignOptions {
                        signing_key_id: Some("missing".to_owned()),
                        ..Default::default()
                    },
                    None,
                    &ctx
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn explicit_algorithm_lazy_mints_only_configured_keys_and_default_uses_primary() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            additional_key_pairs: vec![JwtKeyPairConfig {
                algorithm: JwtAlgorithm::Es256,
                modulus_length: None,
            }],
            ..Default::default()
        });
        let extra = plugin
            .sign_jwt(
                payload("extra"),
                &JwtSignOptions {
                    signing_algorithm: Some(JwtAlgorithm::Es256),
                    header: Some(json!({"typ":"logout+jwt"}).as_object().unwrap().clone()),
                    ..Default::default()
                },
                None,
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(decoded(&extra).0["alg"], "ES256");
        assert_eq!(decoded(&extra).0["typ"], "logout+jwt");
        // A primary key is provisioned explicitly because upstream's unpinned
        // fallback uses a previously provisioned live extra key when none exists.
        plugin.create_jwk(None, None, &ctx).await.unwrap();
        let primary = plugin
            .sign_jwt(payload("primary"), &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        assert_eq!(decoded(&primary).0["alg"], "EdDSA");
        assert!(
            plugin
                .sign_jwt(
                    payload("unconfigured"),
                    &JwtSignOptions {
                        signing_algorithm: Some(JwtAlgorithm::Rs256),
                        ..Default::default()
                    },
                    None,
                    &ctx
                )
                .await
                .is_err()
        );
        let extra_id = decoded(&extra).0["kid"].as_str().unwrap().to_owned();
        assert!(
            plugin
                .sign_jwt(
                    payload("mismatch"),
                    &JwtSignOptions {
                        signing_key_id: Some(extra_id),
                        signing_algorithm: Some(JwtAlgorithm::EdDsa),
                        ..Default::default()
                    },
                    None,
                    &ctx
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn session_payload_and_server_only_endpoints_have_distinct_authority() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let (user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new().with_email("jwt@fixture.test"),
            Duration::days(1),
        )
        .await;
        let mut request =
            test_helpers::create_auth_request_no_query(HttpMethod::Get, "/token", None, None);
        assert!(matches!(
            plugin.session_token(&request, &ctx).await,
            Err(AuthError::Upstream { status: 401, .. })
        ));
        request.headers.insert(
            "cookie".to_owned(),
            better_auth_core::utils::cookie_utils::create_session_cookie(
                &session.token,
                &ctx.config,
            )
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        );
        let token = plugin.session_token(&request, &ctx).await.unwrap();
        let claims = plugin
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claims["sub"], user.id);
        assert_eq!(claims["email"], user.email.as_deref().unwrap());
        for path in ["/sign-jwt", "/verify-jwt", "/jwt/sign", "/jwt/verify"] {
            assert!(
                plugin
                    .on_request(
                        &test_helpers::create_auth_request_no_query(
                            HttpMethod::Post,
                            path,
                            None,
                            None
                        ),
                        &ctx
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            <JwtPlugin as AuthPlugin<TestSchema>>::routes(&plugin).len(),
            2
        );
    }

    #[tokio::test]
    async fn application_session_callbacks_replace_default_claims_and_preserve_subject_fallback() {
        let ctx = test_helpers::create_test_context().await;
        let (user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("callback-owner@fixture.test")
                .with_name("Private name"),
            Duration::hours(1),
        )
        .await;
        let request = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/token",
            Some(&session.token),
            None,
        );
        for subject in [Some("application-subject".to_owned()), None] {
            let plugin = JwtPlugin::with_config(JwtPluginConfig {
                define_payload: Some(Arc::new(ApplicationClaims)),
                define_subject: Some(Arc::new(ApplicationSubject(subject.clone()))),
                ..Default::default()
            });
            let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
            assert_eq!(response.status, 200);
            let response: Value = serde_json::from_slice(&response.body).unwrap();
            let claims = plugin
                .verify_jwt(response["token"].as_str().unwrap(), None, None, &ctx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claims["purpose"], "application");
            assert_eq!(claims["ownerId"], user.id);
            assert_eq!(claims["loginId"], session.id);
            assert_eq!(claims["sub"], subject.as_deref().unwrap_or(&user.id));
            assert!(!claims.contains_key("email"));
            assert!(!claims.contains_key("name"));
            assert_eq!(
                claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
                900
            );
        }
    }

    #[tokio::test]
    async fn application_keyring_persists_and_resolves_keys_outside_auth_storage() {
        let ctx = test_helpers::create_test_context().await;
        let application_keys = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            keyring: Some(Arc::new(ApplicationKeyring {
                database: Arc::clone(&application_keys.database),
            })),
            ..Default::default()
        });
        let request =
            test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None);
        let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let public: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(public["keys"][0]["kid"], "application-signing-key");
        let options = JwtSignOptions {
            signing_key_id: Some("application-signing-key".to_owned()),
            ..Default::default()
        };
        let token = plugin
            .sign_jwt(payload("external-key-owner"), &options, None, &ctx)
            .await
            .unwrap();
        let (header, claims) = decoded(&token);
        assert_eq!(header["kid"], "application-signing-key");
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .unwrap(),
            claims.as_object().unwrap().clone()
        );
        assert!(ctx.database.list_jwks().await.unwrap().is_empty());
        let persisted = application_keys.database.list_jwks().await.unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].id, "application-signing-key");
        assert!(!persisted[0].private_key.contains("\"d\""));
        let private = decrypt(
            &serde_json::from_str::<String>(&persisted[0].private_key).unwrap(),
            &ctx.config.secret,
        )
        .unwrap();
        assert!(serde_json::from_str::<Value>(&private).unwrap()["d"].is_string());
        assert!(
            JwtPlugin::new()
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delegated_signing_uses_external_keys_and_preserves_explicit_payload_and_headers() {
        let ctx = test_helpers::create_test_context().await;
        let service = Arc::new(ApplicationSigner {
            context: test_helpers::create_test_context().await,
            plugin: JwtPlugin::new(),
        });
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            remote_url: Some("https://keys.fixture.test/jwks".to_owned()),
            remote_signer: Some(Arc::<ApplicationSigner>::clone(&service)),
            ..Default::default()
        });
        let options = JwtSignOptions {
            header: Some(
                json!({"typ":"application+jwt"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            ..Default::default()
        };
        let explicit = json!({"sub":"delegated-owner","permission":"read","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+600}).as_object().unwrap().clone();
        let token = plugin
            .sign_jwt(explicit.clone(), &options, None, &ctx)
            .await
            .unwrap();
        let (header, claims) = decoded(&token);
        assert_eq!(header["typ"], "application+jwt");
        for (name, value) in explicit {
            assert_eq!(claims[&name], value);
        }
        assert_eq!(claims["iss"], ctx.config.base_url);
        assert_eq!(claims["aud"], ctx.config.base_url);
        assert_eq!(
            service
                .plugin
                .verify_jwt(&token, None, None, &service.context)
                .await
                .unwrap()
                .unwrap(),
            claims.as_object().unwrap().clone()
        );
        assert!(ctx.database.list_jwks().await.unwrap().is_empty());
        assert_eq!(service.context.database.list_jwks().await.unwrap().len(), 1);
        let request =
            test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None);
        let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body.len(), 0);
        // The reference verifier reads its configured keyring; remoteUrl does not
        // substitute external keys for the local verification adapter.
        assert!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
        let invalid = JwtPlugin::with_config(JwtPluginConfig {
            remote_signer: Some(service),
            ..Default::default()
        });
        let mut init = AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        assert!(invalid.on_init(&mut init).await.is_err());
    }

    // Fixture produced by the unchanged pinned createJwk/signJWT implementation.
    // Rust consumes the imported encrypted row rather than encrypting its own key.
    #[tokio::test]
    async fn signs_pinned_typescript_encrypted_key_and_refuses_a_changed_secret() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/jwt/typescript-1.7.6-encrypted-jwk.json"
        ))
        .unwrap();
        assert_eq!(fixture["referenceVersion"], "better-auth@1.7.6");
        let config = better_auth_core::AuthConfig::new(fixture["secret"].as_str().unwrap())
            .base_url(fixture["origin"].as_str().unwrap());
        let ctx = test_helpers::create_test_context_with_config(config.clone()).await;
        let key = &fixture["key"];
        let imported = ctx
            .database
            .create_jwk(CreateJwk {
                id: Some(key["id"].as_str().unwrap().to_owned()),
                public_key: key["publicKey"].as_str().unwrap().to_owned(),
                private_key: key["privateKey"].as_str().unwrap().to_owned(),
                created_at: key["createdAt"].as_str().unwrap().parse().unwrap(),
                expires_at: None,
                alg: Some("EdDSA".to_owned()),
                crv: Some("Ed25519".to_owned()),
            })
            .await
            .unwrap();
        let plugin = JwtPlugin::new();
        let payload = fixture["payload"].as_object().unwrap().clone();
        let options = JwtSignOptions {
            signing_key_id: Some(imported.id.clone()),
            ..Default::default()
        };
        let token = plugin
            .sign_jwt(payload.clone(), &options, None, &ctx)
            .await
            .unwrap();
        assert_eq!(token, fixture["token"].as_str().unwrap());
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        let mut changed = config;
        changed.secret = "a-different-keyring-secret-at-least-32-characters".to_owned();
        let changed = AuthContext::<TestSchema>::new(Arc::new(changed), Arc::clone(&ctx.database));
        let error = plugin
            .sign_jwt(
                fixture["payload"].as_object().unwrap().clone(),
                &options,
                None,
                &changed,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Failed to decrypt private key"));
        assert_eq!(ctx.database.list_jwks().await.unwrap().len(), 1);
        assert_eq!(
            ctx.database
                .get_jwk_by_id(&imported.id)
                .await
                .unwrap()
                .unwrap()
                .private_key,
            imported.private_key
        );
        assert_eq!(
            plugin
                .sign_jwt(
                    fixture["payload"].as_object().unwrap().clone(),
                    &options,
                    None,
                    &ctx
                )
                .await
                .unwrap(),
            token
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn imported_private_ec_coordinates_must_match_the_secret_scalar() {
        for algorithm in [
            JwtAlgorithm::Es256,
            JwtAlgorithm::Es512,
            JwtAlgorithm::EdDsa,
        ] {
            let ctx = test_helpers::create_test_context().await;
            let pair = JwtKeyPairConfig {
                algorithm,
                ..Default::default()
            };
            let plugin = JwtPlugin::with_config(JwtPluginConfig {
                key_pair: pair.clone(),
                ..Default::default()
            });
            let (public, mut private) = crypto::generate(&pair).unwrap();
            let (_, unrelated) = crypto::generate(&pair).unwrap();
            private["x"] = unrelated["x"].clone();
            if algorithm != JwtAlgorithm::EdDsa {
                private["y"] = unrelated["y"].clone();
            }
            let stored = ctx
                .database
                .create_jwk(CreateJwk {
                    id: Some(format!("imported-{}", algorithm.as_str())),
                    public_key: serde_json::to_string(&public).unwrap(),
                    private_key: serde_json::to_string(
                        &encrypt(
                            &serde_json::to_string(&private).unwrap(),
                            &ctx.config.secret,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    created_at: Utc::now(),
                    expires_at: None,
                    alg: Some(algorithm.as_str().to_owned()),
                    crv: algorithm.curve().map(str::to_owned),
                })
                .await
                .unwrap();
            let result = plugin
                .sign_jwt(
                    payload("imported-owner"),
                    &JwtSignOptions {
                        signing_key_id: Some(stored.id.clone()),
                        ..Default::default()
                    },
                    None,
                    &ctx,
                )
                .await;
            if algorithm == JwtAlgorithm::EdDsa {
                // Pinned Ed25519 import derives x from d and accepts unrelated x.
                let token = result.expect("EdDSA intentionally retains the pinned import behavior");
                assert!(
                    plugin
                        .verify_jwt(&token, None, None, &ctx)
                        .await
                        .unwrap()
                        .is_some()
                );
            } else {
                assert!(
                    result.is_err(),
                    "EC imports must reject unrelated public coordinates"
                );
            }
            assert_eq!(ctx.database.list_jwks().await.unwrap().len(), 1);
            assert_eq!(
                ctx.database
                    .get_jwk_by_id(&stored.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .private_key,
                stored.private_key
            );
            if algorithm != JwtAlgorithm::EdDsa {
                let (public_3, mut private_3, scalar) = loop {
                    let (public_2, private_2) = crypto::generate(&pair).unwrap();
                    let scalar = URL_SAFE_NO_PAD
                        .decode(private_2["d"].as_str().unwrap())
                        .unwrap();
                    if scalar.first() == Some(&0) {
                        break (public_2, private_2, scalar);
                    }
                };
                let mut padded_once = vec![0];
                padded_once.extend(&scalar);
                let mut padded_many = vec![0; 32];
                padded_many.extend(&scalar);
                let mut overflow = vec![1];
                overflow.extend(&scalar);
                for (index, (scalar_2, accepted)) in [
                    (scalar[1..].to_vec(), true),
                    (padded_once, true),
                    (padded_many, true),
                    (overflow, false),
                ]
                .into_iter()
                .enumerate()
                {
                    private_3["d"] = json!(URL_SAFE_NO_PAD.encode(scalar_2));
                    let imported = ctx
                        .database
                        .create_jwk(CreateJwk {
                            id: Some(format!("unsigned-scalar-{}-{index}", algorithm.as_str())),
                            public_key: serde_json::to_string(&public_3).unwrap(),
                            private_key: serde_json::to_string(
                                &encrypt(
                                    &serde_json::to_string(&private_3).unwrap(),
                                    &ctx.config.secret,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            created_at: Utc::now(),
                            expires_at: None,
                            alg: Some(algorithm.as_str().to_owned()),
                            crv: algorithm.curve().map(str::to_owned),
                        })
                        .await
                        .unwrap();
                    let result_2 = plugin
                        .sign_jwt(
                            payload("matching-owner"),
                            &JwtSignOptions {
                                signing_key_id: Some(imported.id.clone()),
                                ..Default::default()
                            },
                            None,
                            &ctx,
                        )
                        .await;
                    if accepted {
                        let token = result_2.expect("unsigned scalar leading zero representations with matching coordinates remain valid");
                        assert!(
                            plugin
                                .verify_jwt(&token, None, None, &ctx)
                                .await
                                .unwrap()
                                .is_some()
                        );
                    } else {
                        assert!(
                            result_2.is_err(),
                            "nonzero scalar overflow must fail import"
                        );
                    }
                    assert_eq!(ctx.database.list_jwks().await.unwrap().len(), index + 2);
                    assert_eq!(
                        ctx.database
                            .get_jwk_by_id(&imported.id)
                            .await
                            .unwrap()
                            .unwrap()
                            .private_key,
                        imported.private_key
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn negative_rotation_issues_one_expired_key_per_request() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            rotation_interval: Some(Duration::seconds(-1)),
            ..Default::default()
        });
        for count in [1, 2] {
            let token = plugin
                .sign_jwt(
                    payload("negative-rotation-owner"),
                    &JwtSignOptions::default(),
                    None,
                    &ctx,
                )
                .await
                .unwrap();
            let keys = ctx.database.list_jwks().await.unwrap();
            assert_eq!(
                keys.len(),
                count,
                "one issuance must persist exactly one replacement key"
            );
            let signing_id = decoded(&token).0["kid"].as_str().unwrap().to_owned();
            assert!(keys.iter().any(|key| key.id == signing_id
                && key.expires_at.is_some_and(|expiry| expiry < Utc::now())));
            assert!(
                plugin
                    .verify_jwt(&token, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                plugin
                    .sign_jwt(
                        payload("explicit-owner"),
                        &JwtSignOptions {
                            signing_key_id: Some(signing_id),
                            ..Default::default()
                        },
                        None,
                        &ctx
                    )
                    .await
                    .is_err()
            );
            assert_eq!(ctx.database.list_jwks().await.unwrap().len(), count);
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn verifies_compact_signature_padding_bits_and_ascii_whitespace_without_accepting_base64_alphabet()
     {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let token = plugin
            .sign_jwt(
                payload("encoding-owner"),
                &JwtSignOptions::default(),
                None,
                &ctx,
            )
            .await
            .unwrap();
        let parts = token.split('.').collect::<Vec<_>>();
        let signature = parts[2];
        assert_eq!(signature.len() % 4, 2);
        for (suffix, accepted) in [
            ("", true),
            ("=", false),
            ("==", true),
            ("===", false),
            ("====", false),
        ] {
            let encoded = format!("{}.{}.{}{suffix}", parts[0], parts[1], signature);
            assert_eq!(
                plugin
                    .verify_jwt(&encoded, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some(),
                accepted
            );
        }

        let final_index = ALPHABET
            .iter()
            .position(|value| *value == *signature.as_bytes().last().unwrap())
            .unwrap();
        for offset in [1, 2, 15] {
            let alternate = format!(
                "{}.{}.{}{}",
                parts[0],
                parts[1],
                (signature)
                    .get(..signature.len() - 1)
                    .expect("fixture range is on a UTF-8 boundary"),
                char::from(
                    *ALPHABET
                        .get(final_index + offset)
                        .expect("fixture index is in the alphabet")
                )
            );
            assert!(
                plugin
                    .verify_jwt(&alternate, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        for whitespace in [" ", "\t", "\n", "\r", "\u{000c}"] {
            let alternate = format!(
                "{}.{}.{}{}{}=={}",
                parts[0],
                parts[1],
                (signature)
                    .get(..20)
                    .expect("fixture range is on a UTF-8 boundary"),
                whitespace,
                (signature)
                    .get(20..)
                    .expect("fixture range is on a UTF-8 boundary"),
                whitespace
            );
            assert!(
                plugin
                    .verify_jwt(&alternate, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        for rejected in [
            format!(
                "+{}",
                (signature)
                    .get(1..)
                    .expect("fixture range is on a UTF-8 boundary")
            ),
            format!(
                "/{}",
                (signature)
                    .get(1..)
                    .expect("fixture range is on a UTF-8 boundary")
            ),
            format!("={signature}"),
            format!("{signature}==A"),
            format!("{signature}\u{000b}"),
            format!("{signature}\u{00a0}"),
        ] {
            let alternate = format!("{}.{}.{}", parts[0], parts[1], rejected);
            assert!(
                plugin
                    .verify_jwt(&alternate, None, None, &ctx)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        let stored = ctx.database.list_jwks().await.unwrap().remove(0);
        let private: Value = serde_json::from_str(
            &decrypt(
                &serde_json::from_str::<String>(&stored.private_key).unwrap(),
                &ctx.config.secret,
            )
            .unwrap(),
        )
        .unwrap();
        // Re-sign changed header/payload encodings. A rejection must come from
        // decoding, rather than the unchanged signature no longer covering them.
        for extra in 0..3 {
            let proof = format!("{}\u{ffff}", "x".repeat(extra));
            let header = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({"alg":"EdDSA","kid":stored.id,"proof":proof})).unwrap(),
            );
            let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"sub":"encoding-owner","exp":4_102_444_800_i64,"iss":ctx.config.base_url,"aud":ctx.config.base_url,"proof":proof})).unwrap());
            for (index, source) in [&header, &claims].into_iter().enumerate() {
                let remainder = source.len() % 4;
                let mut variants = vec![(source.clone(), true)];
                for padding in 1..=4 {
                    variants.push((
                        format!("{source}{}", "=".repeat(padding)),
                        remainder != 0 && padding == 4 - remainder,
                    ));
                }
                if matches!(remainder, 2 | 3) {
                    let last = ALPHABET
                        .iter()
                        .position(|value| *value == *source.as_bytes().last().unwrap())
                        .unwrap();
                    variants.push((
                        format!(
                            "{}{}",
                            (source)
                                .get(..source.len() - 1)
                                .expect("fixture range is on a UTF-8 boundary"),
                            char::from(
                                *ALPHABET
                                    .get(last + 1)
                                    .expect("fixture index is in the alphabet")
                            )
                        ),
                        true,
                    ));
                }
                for whitespace in [" ", "\t", "\n", "\r", "\u{000c}", "\u{000b}", "\u{00a0}"] {
                    variants.push((
                        format!(
                            "{}{}{}",
                            (source)
                                .get(..3)
                                .expect("fixture range is on a UTF-8 boundary"),
                            whitespace,
                            (source)
                                .get(3..)
                                .expect("fixture range is on a UTF-8 boundary")
                        ),
                        index == 1 && matches!(whitespace, " " | "\t" | "\n" | "\r" | "\u{000c}"),
                    ));
                }
                let ordinary = source.replace('-', "+").replace('_', "/");
                if ordinary != *source {
                    variants.push((ordinary, false));
                }
                for (variant, accepted) in variants {
                    let mut segments = [header.clone(), claims.clone()];
                    segments[index] = variant;
                    let input = segments.join(".");
                    let signature_2 =
                        crypto::sign(JwtAlgorithm::EdDsa, &private, input.as_bytes()).unwrap();
                    let token_2 = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature_2));
                    assert_eq!(
                        plugin
                            .verify_jwt(&token_2, None, None, &ctx)
                            .await
                            .unwrap()
                            .is_some(),
                        accepted,
                        "segment {index}, remainder {remainder}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn imported_jwk_material_accepts_padded_coordinates_and_rejects_other_alphabets_and_whitespace()
     {
        for algorithm in [JwtAlgorithm::Es256, JwtAlgorithm::Es512] {
            let ctx = test_helpers::create_test_context().await;
            let pair = JwtKeyPairConfig {
                algorithm,
                ..Default::default()
            };
            let plugin = JwtPlugin::with_config(JwtPluginConfig {
                key_pair: pair.clone(),
                disable_private_key_encryption: true,
                ..Default::default()
            });
            let (public, private) = crypto::generate(&pair).unwrap();
            let mut imports = Vec::<(Value, Value, bool, Option<Value>)>::new();
            for suffix in ["", "=", "==", "===", "===="] {
                let mut imported_private = private.clone();
                let mut imported_public = public.clone();
                for name in ["d", "x", "y"] {
                    imported_private[name] =
                        json!(format!("{}{suffix}", private[name].as_str().unwrap()));
                    if name != "d" {
                        imported_public[name] = imported_private[name].clone();
                    }
                }
                imports.push((imported_public, imported_private, true, None));
            }
            if algorithm == JwtAlgorithm::Es256 {
                const ALPHABET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                for offset in [1, 3] {
                    let mut imported_private = private.clone();
                    let mut imported_public = public.clone();
                    for name in ["d", "x", "y"] {
                        let source = private[name].as_str().unwrap();
                        let last = ALPHABET
                            .iter()
                            .position(|value| *value == *source.as_bytes().last().unwrap())
                            .unwrap();
                        imported_private[name] = json!(format!(
                            "{}{}",
                            (source)
                                .get(..source.len() - 1)
                                .expect("fixture range is on a UTF-8 boundary"),
                            char::from(
                                *ALPHABET
                                    .get(last + offset)
                                    .expect("fixture index is in the alphabet")
                            )
                        ));
                        if name != "d" {
                            imported_public[name] = imported_private[name].clone();
                        }
                    }
                    imports.push((imported_public, imported_private, true, None));
                }
            }
            let (coordinate_public, coordinate_private, x) = loop {
                let (public_2, private_2) = crypto::generate(&pair).unwrap();
                let x = URL_SAFE_NO_PAD
                    .decode(public_2["x"].as_str().unwrap())
                    .unwrap();
                if x.first() == Some(&0) {
                    break (public_2, private_2, x);
                }
            };
            for variation in 0..4 {
                let mut imported_public = coordinate_public.clone();
                let mut imported_private = coordinate_private.clone();
                let x = match variation {
                    0 => x[1..].to_vec(),
                    1 => {
                        let mut value = vec![0];
                        value.extend(&x);
                        value
                    }
                    2 => {
                        let mut value = vec![0; 32];
                        value.extend(&x);
                        value
                    }
                    _ => {
                        let mut value = vec![1];
                        value.extend(&x);
                        value
                    }
                };
                imported_public["x"] = json!(URL_SAFE_NO_PAD.encode(x));
                imported_private["x"] = imported_public["x"].clone();
                if variation == 2 {
                    let mut y = vec![0; 32];
                    y.extend(
                        URL_SAFE_NO_PAD
                            .decode(coordinate_public["y"].as_str().unwrap())
                            .unwrap(),
                    );
                    imported_public["y"] = json!(URL_SAFE_NO_PAD.encode(y));
                    imported_private["y"] = imported_public["y"].clone();
                }
                imports.push((
                    imported_public,
                    imported_private,
                    variation != 3,
                    (variation == 3).then(|| coordinate_private.clone()),
                ));
            }
            let scalar = private["d"].as_str().unwrap();
            let mut invalid = vec![
                format!(
                    "+{}",
                    (scalar)
                        .get(1..)
                        .expect("fixture range is on a UTF-8 boundary")
                ),
                format!(
                    "/{}",
                    (scalar)
                        .get(1..)
                        .expect("fixture range is on a UTF-8 boundary")
                ),
                format!("={scalar}"),
                format!("{scalar}=A"),
                URL_SAFE_NO_PAD.encode(vec![
                    1;
                    if algorithm == JwtAlgorithm::Es256 {
                        31
                    } else {
                        65
                    }
                ]),
            ];
            for whitespace in [" ", "\t", "\n", "\r", "\u{000c}", "\u{000b}", "\u{00a0}"] {
                invalid.push(format!(
                    "{}{}{}",
                    (scalar)
                        .get(..3)
                        .expect("fixture range is on a UTF-8 boundary"),
                    whitespace,
                    (scalar)
                        .get(3..)
                        .expect("fixture range is on a UTF-8 boundary")
                ));
            }
            for scalar_2 in invalid {
                let mut imported_private = private.clone();
                imported_private["d"] = json!(scalar_2);
                imports.push((public.clone(), imported_private, false, None));
            }
            for (index, (public_3, private_3, accepted, verification_control)) in
                imports.into_iter().enumerate()
            {
                let key = ctx
                    .database
                    .create_jwk(CreateJwk {
                        id: Some(format!("imported-{}-{index}", algorithm.as_str())),
                        public_key: serde_json::to_string(&public_3).unwrap(),
                        private_key: serde_json::to_string(&private_3).unwrap(),
                        created_at: Utc::now(),
                        expires_at: None,
                        alg: Some(algorithm.as_str().to_owned()),
                        crv: algorithm.curve().map(str::to_owned),
                    })
                    .await
                    .unwrap();
                let result = plugin
                    .sign_jwt(
                        payload("imported-key-owner"),
                        &JwtSignOptions {
                            signing_key_id: Some(key.id.clone()),
                            ..Default::default()
                        },
                        None,
                        &ctx,
                    )
                    .await;
                if accepted {
                    let token =
                        result.expect("WebCrypto accepts padding and unused bits in JWK material");
                    assert!(
                        plugin
                            .verify_jwt(&token, None, None, &ctx)
                            .await
                            .unwrap()
                            .is_some()
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "WebCrypto rejects this imported private scalar"
                    );
                }
                if let Some(private_key) = verification_control {
                    let token = JwtPlugin::sign_resolved(
                        plugin
                            .default_claims(payload("coordinate-owner"), None, &ctx)
                            .unwrap(),
                        &JwtSignOptions::default(),
                        &ResolvedJwtSigningKey {
                            algorithm,
                            key_id: key.id.clone(),
                            private_key,
                        },
                    )
                    .unwrap();
                    assert!(
                        plugin
                            .verify_jwt(&token, None, None, &ctx)
                            .await
                            .unwrap()
                            .is_none(),
                        "a nonzero overflow coordinate cannot verify a correctly signed token"
                    );
                }
                assert_eq!(
                    ctx.database
                        .get_jwk_by_id(&key.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .private_key,
                    key.private_key
                );
                assert_eq!(ctx.database.list_jwks().await.unwrap().len(), index + 1);
            }
        }
    }

    // Raw JSON input has JavaScript Number semantics before cryptographic emission.
    // Ordinary object keys and string-valued IDs must not enter number decoding.
    #[tokio::test]
    async fn raw_json_signing_normalizes_application_numbers_and_preserves_literal_keys() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        let payload = better_auth_core::utils::json::parse_value(
        r#"{"sub":"9007199254740993","exp":4102444800,"rounded":9007199254740993,"overflow":1e400,"nested":[-0.0,-1e400],"literal":{"$serde_json::private::Number":"1e400","$serde_json::private::RawValue":"hello"}}"#,
    ).unwrap();
        let token = plugin
            .sign_jwt_json(&payload, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let (_, signed) = decoded(&token);
        assert_eq!(signed["rounded"], 9_007_199_254_740_992_u64);
        assert_eq!(signed["overflow"], Value::Null);
        assert_eq!(signed["nested"], json!([0, null]));
        assert_eq!(signed["sub"], "9007199254740993");
        assert_eq!(
            signed["literal"],
            json!({"$serde_json::private::Number":"1e400","$serde_json::private::RawValue":"hello"})
        );
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .unwrap(),
            signed.as_object().unwrap().clone()
        );

        // A literal private serde marker as the first and only key must survive
        // managed verification even when SQLx enables serde_json raw_value.
        let literal = better_auth_core::utils::json::parse_value(
        r#"{"sub":"literal-key-owner","exp":4102444800,"singleton":{"$serde_json::private::RawValue":"hello"}}"#,
    )
    .unwrap();
        let token_2 = plugin
            .sign_jwt_json(&literal, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let verified = plugin
            .verify_jwt(&token_2, None, None, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            verified["singleton"]["$serde_json::private::RawValue"],
            "hello"
        );

        // Native Map<Value> callers use the same JSON signing boundary, including headers.
        let options = JwtSignOptions {
            header: Some(
                json!({"proof":u64::MAX,"literal":"1e400"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            ..Default::default()
        };
        let native = plugin
        .sign_jwt(
            json!({"sub":"native-numbers","exp":4_102_444_800_u64,"rounded":9_007_199_254_740_993_u64})
                .as_object()
                .unwrap()
                .clone(),
            &options,
            None,
            &ctx,
        )
        .await
        .unwrap();
        let (header, signed_2) = decoded(&native);
        assert_eq!(signed_2["rounded"], 9_007_199_254_740_992_u64);
        assert_eq!(header["literal"], "1e400");
        let header_text = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(native.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(header_text.contains("\"proof\":18446744073709552000"));
    }

    // Signing must reject nonfinite registered claims before nullable JSON emission.
    // Lazy key creation precedes the rejection in pinned JOSE and remains observable.
    #[tokio::test]
    async fn raw_json_signing_rejects_nonfinite_dates_and_truthy_scalar_subjects() {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::new();
        assert!(ctx.database.list_jwks().await.unwrap().is_empty());
        for (field, literal) in [
            ("exp", "1e400"),
            ("exp", "-1e400"),
            ("iat", "1e400"),
            ("iat", "-1e400"),
            ("nbf", "1e400"),
            ("nbf", "-1e400"),
            ("sub", "1e400"),
            ("jti", "-1e400"),
            ("iss", "1e400"),
        ] {
            let input = format!("{{\"exp\":4102444800,\"{field}\":{literal}}}");
            let payload = better_auth_core::utils::json::parse_value(&input).unwrap();
            assert!(
                plugin
                    .sign_jwt_json(&payload, &JwtSignOptions::default(), None, &ctx)
                    .await
                    .is_err(),
                "{field}: {literal}"
            );
            assert_eq!(ctx.database.list_jwks().await.unwrap().len(), 1);
        }
        let payload = better_auth_core::utils::json::parse_value(
            r#"{"exp":4102444800,"sub":0,"jti":false,"iat":null,"nbf":false}"#,
        )
        .unwrap();
        let token = plugin
            .sign_jwt_json(&payload, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let (_, signed) = decoded(&token);
        assert_eq!(signed["sub"], 0);
        assert_eq!(signed["jti"], false);
        assert_eq!(signed["iat"], Value::Null);
        assert_eq!(signed["nbf"], false);
    }
}
// LCOV_EXCL_STOP
