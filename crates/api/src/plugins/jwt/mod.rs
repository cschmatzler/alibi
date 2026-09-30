//! Asymmetric session JWTs, public JWKS, and trusted server-side signing.

use std::{str::FromStr, sync::Arc};

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

use super::token_crypto::{decrypt, encrypt};

mod crypto;

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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es512 => "ES512",
            Self::Ps256 => "PS256",
            Self::Rs256 => "RS256",
        }
    }
    pub fn curve(self) -> Option<&'static str> {
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
    At(DateTime<Utc>),
    Numeric(i64),
}
impl Default for JwtExpiration {
    fn default() -> Self {
        Self::After(Duration::minutes(15))
    }
}
impl JwtExpiration {
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
                        return json!(format!("{}{seconds}", js_primitive_string(value)));
                    }
                };
                base + seconds
            }
            Self::At(date) => date.timestamp() as f64,
            Self::Numeric(value) => *value as f64,
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
            Self::One(value) => vec![value],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        };
        match value {
            Value::String(value) => expected.contains(&value.as_str()),
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .any(|value| expected.contains(&value)),
            _ => false,
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
    async fn keys(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<Jwk>>;
    async fn create_key(&self, key: CreateJwk, request: Option<&AuthRequest>) -> AuthResult<Jwk>;
}
#[async_trait]
pub trait SignRemoteJwt: Send + Sync {
    async fn sign(
        &self,
        payload: &Map<String, Value>,
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
    pub header: Map<String, Value>,
    pub signing_key_id: Option<String>,
    pub signing_algorithm: Option<JwtAlgorithm>,
    pub claims: Option<JwtClaimsConfig>,
}

/// A selected server signing key. Private material stays inside the plugin.
pub struct ResolvedJwtSigningKey {
    pub algorithm: JwtAlgorithm,
    pub key_id: String,
    private_key: Value,
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
impl JwtPlugin {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_config(config: JwtPluginConfig) -> Self {
        Self { config }
    }

    async fn keys(
        &self,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Vec<Jwk>> {
        match &self.config.keyring {
            Some(keyring) => keyring.keys(request).await,
            None => ctx.database.list_jwks().await,
        }
    }

    /// Provision a private signing key and its public JWK in persistent storage.
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
        match &self.config.keyring {
            Some(keyring) => keyring.create_key(data, request).await,
            None => ctx.database.create_jwk(data).await,
        }
    }

    /// Select a live key, with explicit key or algorithm pinning when requested.
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
                .map(JwtAlgorithm::from_str)
                .unwrap_or(Ok(primary))
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
            match keys
                .iter()
                .filter(live)
                .find(|key| key_alg(key).is_ok_and(|alg| alg == algorithm))
                .cloned()
            {
                Some(key) => key,
                None => {
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
            }
        } else {
            match keys
                .iter()
                .filter(live)
                .find(|key| key_alg(key).is_ok_and(|alg| alg == primary))
                .or_else(|| keys.iter().find(live))
                .cloned()
            {
                Some(key) => key,
                None => {
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
            decrypt(&encrypted, &ctx.config.secret).map_err(|_| AuthError::config("Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption."))?
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
    pub async fn sign_jwt(
        &self,
        payload: Map<String, Value>,
        options: &JwtSignOptions,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let payload = self.default_claims(payload, options.claims.as_ref(), ctx)?;
        if let Some(remote) = &self.config.remote_signer {
            return remote.sign(&payload, options).await;
        }
        let key = self
            .resolve_signing_key(options, request, ctx)
            .await?
            .ok_or_else(|| AuthError::internal("No local JWT signing key"))?;
        self.sign_resolved(payload, options, &key)
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
            let _ = payload.insert("exp".to_owned(), expiration);
        }
        if payload.get("iss").is_none_or(Value::is_null) {
            let _ = payload.insert(
                "iss".to_owned(),
                json!(config.issuer.as_deref().unwrap_or(&ctx.config.base_url)),
            );
        }
        if payload.get("aud").is_none_or(Value::is_null) {
            let _ = payload.insert(
                "aud".to_owned(),
                serde_json::to_value(
                    config
                        .audience
                        .clone()
                        .unwrap_or_else(|| JwtAudience::One(ctx.config.base_url.clone())),
                )?,
            );
        }
        Ok(payload)
    }

    fn sign_resolved(
        &self,
        mut payload: Map<String, Value>,
        options: &JwtSignOptions,
        key: &ResolvedJwtSigningKey,
    ) -> AuthResult<String> {
        let mut header = options.header.clone();
        let _ = header.insert("alg".to_owned(), json!(key.algorithm.as_str()));
        let _ = header.insert("kid".to_owned(), json!(key.key_id));
        validate_critical_header(&header, true)?;
        normalize_signing_claims(&mut payload)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes())?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Verify a token against the persisted keyring and configured claims.
    /// Invalid signatures, malformed tokens and claim failures return `None`.
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
        let header: Value = serde_json::from_slice(&decode_compact_part(header, false)?)?;
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
            .keys(request, ctx)
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
        let payload: Map<String, Value> =
            serde_json::from_slice(&decode_compact_part(payload, true)?)?;
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
        let (user, session, needs_refresh) = ctx
            .require_session_with_refresh_state(req)
            .await
            .map_err(|_| unauthorized())?;
        let session = JwtSession {
            user: ctx.user_view(&user),
            session,
            needs_refresh,
        };
        self.sign_session_token(req, ctx, &session).await
    }

    async fn sign_session_token(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        session: &JwtSession,
    ) -> AuthResult<String> {
        let mut payload = match &self.config.define_payload {
            Some(define) => define.define_payload(session).await?,
            None => serde_json::to_value(&session.user)?
                .as_object()
                .cloned()
                .ok_or_else(|| AuthError::internal("User payload was not an object"))?,
        };
        let _ = payload
            .entry("iat".to_owned())
            .or_insert_with(|| json!(Utc::now().timestamp()));
        let subject = match &self.config.define_subject {
            Some(define) => define
                .subject(session)
                .await?
                .unwrap_or_else(|| session.user.id.clone()),
            None => session.user.id.clone(),
        };
        let _ = payload.insert("sub".to_owned(), json!(subject));
        self.sign_jwt(payload, &JwtSignOptions::default(), Some(req), ctx)
            .await
    }

    async fn jwks(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if self.config.remote_url.is_some() {
            return Ok(AuthResponse::new(404));
        }
        let mut keys = self.keys(Some(req), ctx).await?;
        if keys.is_empty() {
            let _ = self.create_jwk(None, Some(req), ctx).await?;
            keys = self.keys(Some(req), ctx).await?;
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
                let _ = public.insert(
                    "alg".to_owned(),
                    json!(
                        key.alg
                            .as_deref()
                            .unwrap_or(self.config.key_pair.algorithm.as_str())
                    ),
                );
                if let Some(curve) = &key.crv {
                    let _ = public.insert("crv".to_owned(), json!(curve));
                }
                let parsed: Map<String, Value> = serde_json::from_str(&key.public_key)?;
                public.extend(parsed);
                let _ = public.insert("kid".to_owned(), json!(key.id));
                Ok::<_, AuthError>(public)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(AuthResponse::json(200, &json!({ "keys": keys }))?)
    }
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
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
            .map(|value| {
                if value.is_null() {
                    String::new()
                } else {
                    js_primitive_string(value)
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
    .map_err(|_| AuthError::bad_request("Invalid JWT base64url encoding"))
}

fn normalize_signing_claims(payload: &mut Map<String, Value>) -> AuthResult<()> {
    let now = Utc::now().timestamp();
    for field in ["exp", "iat", "nbf"] {
        if let Some(value) = payload.get(field)
            && (field == "exp" || js_truthy(value))
        {
            let value = match value {
                Value::Number(_) => value.clone(),
                Value::String(value) => json!(now as f64 + relative_numeric_date(value)?),
                _ => return Err(AuthError::internal("Invalid time period format")),
            };
            let _ = payload.insert(field.to_owned(), value);
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
    let (number, negative, signed) = if let Some(value) = value.strip_prefix('-') {
        (value, true, true)
    } else if let Some(value) = value.strip_prefix('+') {
        (value, false, true)
    } else {
        (value, false, false)
    };
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
        "w" | "week" | "weeks" => 604800.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31557600.0,
        _ => return Err(invalid()),
    };
    let seconds = (digits.parse::<f64>().map_err(|_| invalid())? * multiplier + 0.5).floor();
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

fn unauthorized() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
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
                Ok(Some(self.jwks(req, ctx).await?))
            }
            (HttpMethod::Get, "/token") => Ok(Some(AuthResponse::json(
                200,
                &json!({ "token": self.session_token(req, ctx).await? }),
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
        let token = self
            .sign_session_token(
                req,
                ctx,
                &JwtSession {
                    user,
                    session,
                    needs_refresh: None,
                },
            )
            .await?;
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
        let _ = response.headers.insert("set-auth-jwt", token);
        let _ = response
            .headers
            .insert("access-control-expose-headers", expose.join(", "));
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
