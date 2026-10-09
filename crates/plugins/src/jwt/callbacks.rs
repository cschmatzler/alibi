use super::*;
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
    pub endpoint: Option<&'a alibi_core::endpoint::EndpointCall>,
}

/// One property in an application-owned remote signing payload.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RemoteJwtClaim<'a> {
    Absent,
    Undefined,
    Value(&'a alibi_core::utils::json::JsValue),
}

/// Claims passed to a configured remote signer, before managed JOSE validation.
///
/// `raw_claims` preserves IEEE754 numbers and all supplied JSON values. The
/// added `iat` and `nbf` properties can be own properties with an undefined
/// value; use `claim` to distinguish these from absent or null properties.
/// Undefined properties are omitted from `raw_claims`, matching JSON.stringify.
#[derive(Clone, Debug)]
pub struct RemoteJwtPayload {
    pub(in crate::jwt) raw_claims: alibi_core::utils::json::JsValue,
    pub(in crate::jwt) own_keys: Vec<String>,
    pub(in crate::jwt) undefined_claims: Vec<String>,
}

impl RemoteJwtPayload {
    #[must_use]
    pub const fn raw_claims(&self) -> &alibi_core::utils::json::JsValue {
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
