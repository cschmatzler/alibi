use crate::error::{AuthError, AuthResult};

use crate::types::{CreateJwk, Jwk};

use async_trait::async_trait;

#[async_trait]
pub trait JwkStore: Send + Sync {
    /// All keys, including expired signing keys that remain valid for public verification.
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Err(unsupported())
    }
    async fn get_jwk_by_id(&self, _id: &str) -> AuthResult<Option<Jwk>> {
        Err(unsupported())
    }
    async fn create_jwk(&self, _data: CreateJwk) -> AuthResult<Jwk> {
        Err(unsupported())
    }
}

fn unsupported() -> AuthError {
    AuthError::NotImplemented("JWKS storage is not supported by this store".to_owned())
}
