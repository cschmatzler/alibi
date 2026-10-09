use super::*;
impl JwtPlugin {
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
    pub(in crate::jwt) async fn verify_internal(
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
}
