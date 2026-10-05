use super::*;
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
    pub(in crate::plugins::jwt) fn timestamp_raw(
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
    pub(in crate::plugins::jwt) fn timestamp(&self, issued_at: Option<&Value>) -> Value {
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
    pub(in crate::plugins::jwt) fn matches(&self, value: &Value) -> bool {
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
