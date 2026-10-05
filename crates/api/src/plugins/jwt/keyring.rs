use super::*;
impl JwtPlugin {
    pub(in crate::plugins::jwt) async fn keys(
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

    pub(in crate::plugins::jwt) async fn keys_in_transaction<S: AuthSchema>(
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

    pub(in crate::plugins::jwt) async fn keys_at_path(
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

    pub(in crate::plugins::jwt) async fn create_jwk_in_transaction<S: AuthSchema>(
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

    pub(in crate::plugins::jwt) async fn resolve_signing_key_in_transaction<S: AuthSchema>(
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
}
