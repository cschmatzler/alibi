//! Provider-owned OIDC claims signed through the installed JWT plugin.
use super::OAuthProviderPlugin;
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
impl OAuthProviderPlugin {
    pub(super) async fn issue_id_token<S: AuthSchema>(
        &self,
        client: &OAuthClient,
        proof: &Value,
        access_token: &str,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Result<Option<String>, alibi_core::endpoint::EndpointResponse>> {
        if self.config.disable_jwt_plugin
            && client.client_secret.as_ref().is_none_or(String::is_empty)
        {
            return Ok(Ok(None));
        }
        let issued = chrono::Utc::now().timestamp();
        let jwt = if self.config.disable_jwt_plugin {
            None
        } else {
            Some(
                ctx.extensions
                    .get::<crate::jwt::JwtPlugin>()
                    .ok_or_else(|| AuthError::config("jwt_config"))?,
            )
        };
        let mut options = crate::jwt::JwtSignOptions::default();
        let resolved = if let Some(jwt) = jwt.as_ref() {
            jwt.resolve_signing_key(&options, req.physical_request(), ctx)
                .await?
        } else {
            None
        };
        let algorithm = if self.config.disable_jwt_plugin {
            "HS256".into()
        } else {
            resolved
                .as_ref()
                .map(|key| key.algorithm.as_str().to_owned())
                .or_else(|| {
                    ctx.extensions
                        .get::<crate::jwt::JwtDiscoveryOptions>()
                        .and_then(|options| options.signing_algorithms.first().cloned())
                })
                .ok_or_else(|| AuthError::config("JWT signing algorithm is missing"))?
        };
        let hash = match algorithm.as_str() {
            "EdDSA" => Sha512::digest(access_token).to_vec(),
            algorithm if algorithm.ends_with("384") => Sha384::digest(access_token).to_vec(),
            algorithm if algorithm.ends_with("512") => Sha512::digest(access_token).to_vec(),
            _ => Sha256::digest(access_token).to_vec(),
        };
        let access_hash = URL_SAFE_NO_PAD.encode(
            hash.get(..hash.len() / 2)
                .ok_or_else(|| AuthError::internal("Invalid OIDC token digest"))?,
        );
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        let discovery = if self.config.disable_jwt_plugin {
            None
        } else {
            ctx.extensions.get::<crate::jwt::JwtDiscoveryOptions>()
        };
        let issuer = discovery
            .as_ref()
            .and_then(|options| options.issuer.as_ref())
            .unwrap_or(&base);
        let mut payload=json!({"iss":issuer,"sub":proof.get("userId"),"aud":client.client_id,"iat":issued,"exp":issued+36_000,"acr":"0","at_hash":access_hash}).as_object().cloned().ok_or_else(||AuthError::internal("Invalid OIDC claims"))?;
        if let Some(time) = proof.get("authTime").and_then(Value::as_i64) {
            _ = payload.insert("auth_time".into(), json!(time.div_euclid(1000)));
        }
        if let Some(nonce) = proof
            .get("query")
            .and_then(|query| query.get("nonce"))
            .filter(|v| !v.is_null())
        {
            _ = payload.insert("nonce".into(), nonce.clone());
        }
        let include_sid = client.metadata.get("enable_end_session") == Some(&Value::Bool(true))
            || client
                .metadata
                .get("backchannel_logout_uri")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        if include_sid && let Some(session) = proof.get("sessionId") {
            _ = payload.insert("sid".into(), session.clone());
        }
        if let Some(claims) = proof.get("idTokenClaims").and_then(Value::as_object) {
            for (key, value) in claims {
                if ![
                    "iss",
                    "sub",
                    "aud",
                    "exp",
                    "iat",
                    "nbf",
                    "jti",
                    "nonce",
                    "auth_time",
                    "acr",
                    "amr",
                    "azp",
                    "at_hash",
                    "c_hash",
                    "sid",
                    "name",
                    "given_name",
                    "family_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at",
                    "email",
                    "email_verified",
                    "phone_number",
                    "phone_number_verified",
                    "address",
                ]
                .contains(&key.as_str())
                    && !payload.contains_key(key)
                {
                    _ = payload.insert(key.clone(), value.clone());
                }
            }
        }
        let token = if let Some(jwt) = jwt {
            options.resolved_key = resolved.map(std::sync::Arc::new);
            jwt.sign_jwt(payload, &options, req.physical_request(), ctx)
                .await?
        } else {
            let stored = client
                .client_secret
                .as_deref()
                .ok_or_else(|| AuthError::internal("Client secret is missing"))?;
            let secret = super::client_secret::decrypt(ctx, &self.config, stored).await?;
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            header.typ = None;
            jsonwebtoken::encode(
                &header,
                &payload,
                &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            )
            .map_err(|error| AuthError::internal(error.to_string()))?
        };
        let header = token
            .split('.')
            .next()
            .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
            .and_then(|value| serde_json::from_slice::<Value>(&value).ok())
            .ok_or_else(|| AuthError::internal("Invalid signed ID token header"))?;
        if header.get("alg").and_then(Value::as_str) != Some(algorithm.as_str()) {
            return super::clients::status_protocol_error(500,"server_error",&format!("ID token signed with {} but at_hash was computed for {algorithm}. Ensure jwt.sign uses the algorithm declared in keyPairConfig.alg.",header.get("alg").unwrap_or(&Value::Null))).map(Err);
        }
        Ok(Ok(Some(token)))
    }
}
