use super::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, JwtAudience, JwtClaimsConfig,
    JwtPlugin, JwtSignOptions, Map, RemoteJwtPayload, ResolvedJwtSigningKey, URL_SAFE_NO_PAD,
    Value, crypto, json, normalize_signing_claims, validate_critical_header, validate_numeric_date,
};
use base64::Engine;
impl JwtPlugin {
    /// Sign an application-owned payload through the trusted server API.
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
    pub async fn sign_jwt_json(
        &self,
        payload: &alibi_core::utils::json::JsValue,
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
                        .and_then(alibi_core::utils::json::JsValue::as_f64),
                )?;
            }
            for field in ["iss", "sub", "jti"] {
                if object
                    .get(field)
                    .and_then(alibi_core::utils::json::JsValue::as_f64)
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

    pub(in crate::jwt) async fn sign_jwt_checked(
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

    pub(in crate::jwt) async fn sign_remote_jwt(
        &self,
        mut raw_claims: alibi_core::utils::json::JsValue,
        options: &JwtSignOptions,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        use alibi_core::utils::json::JsValue;
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
                _ = payload.insert(name.to_owned(), value);
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

    pub(in crate::jwt) fn default_claims(
        &self,
        mut payload: Map<String, Value>,
        override_claims: Option<&JwtClaimsConfig>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<Map<String, Value>> {
        let config = override_claims.unwrap_or(&self.config.claims);
        if payload.get("exp").is_none_or(Value::is_null) {
            let expiration = config.expiration.timestamp(payload.get("iat"));
            _ = payload.insert("exp".to_owned(), expiration);
        }
        if payload.get("iss").is_none_or(Value::is_null) {
            _ = payload.insert(
                "iss".to_owned(),
                json!(config.issuer.as_deref().unwrap_or(&ctx.config.base_url)),
            );
        }
        if payload.get("aud").is_none_or(Value::is_null) {
            _ = payload.insert(
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

    pub(in crate::jwt) fn sign_resolved(
        mut payload: Map<String, Value>,
        options: &JwtSignOptions,
        key: &ResolvedJwtSigningKey,
    ) -> AuthResult<String> {
        let mut header = options.header.clone().unwrap_or_default();
        _ = header.insert("alg".to_owned(), json!(key.algorithm.as_str()));
        _ = header.insert("kid".to_owned(), json!(key.key_id));
        validate_critical_header(&header, true)?;
        normalize_signing_claims(&mut payload)?;
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(alibi_core::utils::json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(alibi_core::utils::json::to_vec(&payload)?)
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes())?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}
