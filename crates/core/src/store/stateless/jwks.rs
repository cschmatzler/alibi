//! Managed key rows live for this store instance, including expired signing keys.
use super::*;

#[async_trait]
impl JwkStore for StatelessStore {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Ok(self.lock()?.jwks.values().cloned().collect())
    }

    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        Ok(self.lock()?.jwks.get(id).cloned())
    }

    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        let key = Jwk {
            id: data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            public_key: data.public_key,
            private_key: data.private_key,
            created_at: data.created_at,
            expires_at: data.expires_at,
            alg: data.alg,
            crv: data.crv,
        };
        let mut state = self.lock()?;
        if state.jwks.contains_key(&key.id) {
            return Err(AuthError::internal("duplicate JWK primary ID"));
        }
        _ = state.jwks.insert(key.id.clone(), key.clone());
        Ok(key)
    }
}
