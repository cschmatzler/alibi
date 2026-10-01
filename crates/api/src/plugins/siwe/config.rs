use async_trait::async_trait;
use better_auth_core::AuthResponse;
use rand::Rng;
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

/// An application callback may reject with an endpoint response or fail while contacting a wallet,
/// identity, or nonce provider.
///
/// SIWE preserves endpoint responses and translates provider failures to its documented HTTP
/// error.
#[derive(Debug)]
pub enum SiweCallbackError {
    Api(AuthResponse),
    Failed(String),
    Unknown,
}

impl fmt::Display for SiweCallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(response) => {
                write!(f, "SIWE callback rejected with HTTP {}", response.status)
            }
            Self::Failed(message) => f.write_str(message),
            Self::Unknown => f.write_str("Unknown error"),
        }
    }
}

impl std::error::Error for SiweCallbackError {}

pub type SiweCallbackResult<T> = Result<T, SiweCallbackError>;

#[async_trait]
pub trait SiweNonceProvider: Send + Sync {
    /// Return an ERC-4361 nonce containing 8–250 ASCII alphanumeric characters.
    async fn get_nonce(&self) -> SiweCallbackResult<String>;
}

/// A cryptographically random nonce provider suitable for ordinary deployments.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomSiweNonce;

#[async_trait]
impl SiweNonceProvider for RandomSiweNonce {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoHeader {
    pub t: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoPayload {
    pub domain: String,
    pub aud: String,
    pub nonce: String,
    pub iss: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoSignature {
    pub t: String,
    pub s: String,
}

/// CAIP-122 callback data constructed by Better Auth 1.7.6. Its domain, audience
/// and issuer retain the configured domain rather than the normalized host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cacao {
    pub h: CacaoHeader,
    pub p: CacaoPayload,
    pub s: CacaoSignature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiweVerification {
    pub message: String,
    pub signature: String,
    /// EIP-55 checksummed address from the signed message.
    pub address: String,
    /// The positive integer JavaScript Number parsed from the signed message.
    pub chain_id: f64,
    pub cacao: Cacao,
}

#[async_trait]
pub trait SiweVerifier: Send + Sync {
    /// Verify the original signed bytes for the supplied address and chain.
    /// Implementations may support externally owned or ERC-1271 contract wallets.
    async fn verify_message(&self, input: SiweVerification) -> SiweCallbackResult<bool>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnsProfile {
    pub name: Option<String>,
    pub avatar: Option<String>,
}

#[async_trait]
pub trait EnsLookup: Send + Sync {
    async fn lookup(&self, wallet_address: &str) -> SiweCallbackResult<EnsProfile>;
}

/// SIWE application policies. A verifier is required because contract-wallet
/// verification and chain-specific RPC access are owned by the application.
#[derive(Clone)]
pub struct SiweConfig {
    pub domain: String,
    pub nonce_provider: Arc<dyn SiweNonceProvider>,
    pub verifier: Arc<dyn SiweVerifier>,
    pub email_domain_name: Option<String>,
    /// When false, an email is required. Existing email identities are never
    /// linked to a wallet using that email alone.
    pub anonymous: bool,
    pub ens_lookup: Option<Arc<dyn EnsLookup>>,
}

impl SiweConfig {
    #[must_use]
    pub fn new(
        domain: impl Into<String>,
        nonce_provider: Arc<dyn SiweNonceProvider>,
        verifier: Arc<dyn SiweVerifier>,
    ) -> Self {
        Self {
            domain: domain.into(),
            nonce_provider,
            verifier,
            email_domain_name: None,
            anonymous: true,
            ens_lookup: None,
        }
    }
}

impl fmt::Debug for SiweConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiweConfig")
            .field("domain", &self.domain)
            .field("email_domain_name", &self.email_domain_name)
            .field("anonymous", &self.anonymous)
            .field("has_ens_lookup", &self.ens_lookup.is_some())
            .finish_non_exhaustive()
    }
}
