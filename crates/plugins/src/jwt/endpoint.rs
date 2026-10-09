use super::{
    JwtAudience, JwtClaimsConfig, JwtExpiration, JwtKeyPairConfig, JwtPlugin, JwtSession,
    JwtSignOptions,
};
use crate::authentication_helpers::{JsonField, JsonFieldKind};
use crate::endpoint::{definition, validate_fields, validation};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};
use chrono::Duration;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct JwtTokenOutput {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtVerifyOutput {
    pub payload: Option<Map<String, Value>>,
}

pub(super) fn definitions(jwks_path: &str) -> Vec<EndpointDefinition> {
    vec![
        definition(
            "getToken",
            "getJSONWebToken",
            Some("/token"),
            HttpMethod::Get,
        ),
        definition(
            "getJwks",
            "getJSONWebKeySet",
            Some(jwks_path),
            HttpMethod::Get,
        ),
        definition("signJWT", "signJWT", None, HttpMethod::Post),
        definition("verifyJWT", "verifyJWT", None, HttpMethod::Post),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let body = match call.operation_id() {
        "signJWT" => Some(validate_fields(
            call.body(),
            "body",
            &[
                JsonField {
                    name: "payload",
                    kind: JsonFieldKind::Record,
                    required: true,
                },
                JsonField {
                    name: "overrideOptions",
                    kind: JsonFieldKind::Record,
                    required: false,
                },
            ],
        )?),
        "verifyJWT" => Some(validate_fields(
            call.body(),
            "body",
            &[
                JsonField::string("token", true),
                JsonField::string("issuer", false),
            ],
        )?),
        "getJSONWebToken" if call.headers().is_none() => {
            return Err(validation("Headers is required"));
        }
        _ => call.body().cloned(),
    };
    Ok(EndpointInput {
        body,
        query: call.query().cloned(),
    })
}

impl JwtPlugin {
    #[must_use]
    pub const fn token_endpoint() -> ServerEndpoint<JwtTokenOutput> {
        ServerEndpoint::new("jwt", "getToken")
    }

    #[must_use]
    pub const fn jwks_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("jwt", "getJwks")
    }

    /// Sign JSON through registered middleware; plain `sign_jwt` remains directly callable.
    #[must_use]
    pub fn sign_endpoint(payload: JsValue) -> ServerEndpoint<JwtTokenOutput> {
        ServerEndpoint::new("jwt", "signJWT").with_body_value(JsValue::Object(
            [("payload".into(), payload)].into_iter().collect(),
        ))
    }

    #[must_use]
    pub fn verify_endpoint(
        token: impl Into<String>,
        issuer: Option<String>,
    ) -> ServerEndpoint<JwtVerifyOutput> {
        let mut body = indexmap::IndexMap::new();
        _ = body.insert("token".into(), JsValue::String(token.into()));
        if let Some(issuer) = issuer {
            _ = body.insert("issuer".into(), JsValue::String(issuer));
        }
        ServerEndpoint::new("jwt", "verifyJWT").with_body_value(JsValue::Object(body))
    }

    pub(super) async fn call_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<EndpointResponse> {
        match call.operation_id() {
            "getJSONWebToken" => {
                let read =
                    alibi_core::session::cookie_cache::runtime::authenticated(ctx, call, false)
                        .await
                        .map_err(|_| super::unauthorized())?
                        .ok_or_else(super::unauthorized)?;
                let user = match &read.user {
                    alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
                    alibi_core::AuthenticatedUser::Cached(user) => (**user).clone(),
                };
                let session = JwtSession {
                    user,
                    session: call.virtual_session().unwrap_or(read.session),
                    needs_refresh: read.needs_refresh,
                    updated_at: None,
                    version: None,
                };
                call.record_authenticated_session(session.user.clone(), session.session.clone());
                EndpointResponse::json(
                    &serde_json::json!({"token":self.sign_session_token(call.request(),ctx,&session).await?}),
                )
            }
            "getJSONWebKeySet" => {
                EndpointResponse::json(&self.jwks_value(call.request(), ctx).await?)
            }
            "signJWT" => {
                let payload = call
                    .body()
                    .and_then(|body| body.get("payload"))
                    .ok_or_else(|| validation("[body.payload] Invalid input"))?;
                let plugin = self.with_json_overrides(
                    call.body().and_then(|body| body.get("overrideOptions")),
                )?;
                EndpointResponse::json(
                    &serde_json::json!({"token":plugin.sign_jwt_json(payload,&JwtSignOptions::default(),call.request(),ctx).await?}),
                )
            }
            "verifyJWT" => {
                #[derive(Deserialize)]
                struct Body {
                    token: String,
                    issuer: Option<String>,
                }
                let body: Body = call.body_as()?;
                EndpointResponse::json(
                    &serde_json::json!({"payload":self.verify_jwt(&body.token,body.issuer.as_deref(),call.request(),ctx).await?}),
                )
            }
            _ => Err(AuthError::not_found("Unregistered JWT operation")),
        }
    }

    fn with_json_overrides(&self, overrides: Option<&JsValue>) -> AuthResult<Self> {
        let mut plugin = self.clone();
        let Some(overrides) = overrides else {
            return Ok(plugin);
        };
        if let Some(jwt) = overrides.get("jwt") {
            plugin.config.claims = JwtClaimsConfig::default();
            plugin.config.remote_signer = None;
            if let Some(issuer) = jwt.get("issuer").filter(|value| !value.is_null()) {
                plugin.config.claims.issuer = Some(
                    issuer
                        .as_str()
                        .ok_or_else(|| AuthError::internal("JWT issuer must be a string"))?
                        .into(),
                );
            }
            if let Some(audience) = jwt.get("audience").filter(|value| !value.is_null()) {
                plugin.config.claims.audience = Some(alibi_core::utils::json::from_value::<
                    JwtAudience,
                >(audience.clone())?);
            }
            if let Some(expiration) = jwt.get("expirationTime").filter(|value| !value.is_null()) {
                plugin.config.claims.expiration = if let Some(value) = expiration.as_f64() {
                    JwtExpiration::Numeric(value)
                } else if let Some(value) = expiration.as_str() {
                    JwtExpiration::AfterSeconds(time_seconds(value)?)
                } else {
                    return Err(AuthError::internal("Invalid JWT expiration time"));
                };
            }
        }
        if let Some(jwks) = overrides.get("jwks") {
            plugin.config.key_pair = JwtKeyPairConfig::default();
            plugin.config.additional_key_pairs.clear();
            plugin.config.remote_url = jwks
                .get("remoteUrl")
                .and_then(JsValue::as_str)
                .map(str::to_owned);
            plugin.config.disable_private_key_encryption = jwks
                .get("disablePrivateKeyEncryption")
                .and_then(JsValue::as_bool)
                .unwrap_or(false);
            plugin.config.rotation_interval = jwks
                .get("rotationInterval")
                .and_then(JsValue::as_f64)
                .filter(|value| *value != 0.0)
                .map(duration)
                .transpose()?;
            plugin.config.grace_period = duration(
                jwks.get("gracePeriod")
                    .and_then(JsValue::as_f64)
                    .unwrap_or(2_592_000.0),
            )?;
            if let Some(config) = jwks.get("keyPairConfig") {
                plugin.config.key_pair = key_config(config)?;
            }
            if let Some(configs) = jwks.get("keyPairConfigs").and_then(JsValue::as_array) {
                plugin.config.additional_key_pairs =
                    configs.iter().map(key_config).collect::<AuthResult<_>>()?;
            }
        }
        if overrides.get("adapter").is_some() {
            plugin.config.keyring = None;
        }
        Ok(plugin)
    }
}

fn key_config(value: &JsValue) -> AuthResult<JwtKeyPairConfig> {
    Ok(JwtKeyPairConfig {
        algorithm: super::JwtAlgorithm::from_str(
            value
                .get("alg")
                .and_then(JsValue::as_str)
                .unwrap_or("EdDSA"),
        )?,
        modulus_length: value
            .get("modulusLength")
            .and_then(JsValue::as_f64)
            .map(|value| {
                value
                    .to_string()
                    .parse::<usize>()
                    .map_err(|error| AuthError::internal(error.to_string()))
            })
            .transpose()?,
    })
}

fn duration(value: f64) -> AuthResult<Duration> {
    let millis = (value * 1000.0)
        .trunc()
        .to_string()
        .parse::<i64>()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(Duration::milliseconds(millis))
}

fn time_seconds(value: &str) -> AuthResult<f64> {
    let invalid = || {
        AuthError::internal(format!(
            "Invalid time string format: \"{value}\". Use formats like \"7d\", \"30m\", \"1 hour\", etc."
        ))
    };
    let mut text = value;
    let sign = if let Some(rest) = text.strip_prefix('-') {
        text = rest;
        Some(-1.0)
    } else if let Some(rest) = text.strip_prefix('+') {
        text = rest;
        Some(1.0)
    } else {
        None
    };
    text = text.strip_prefix(' ').unwrap_or(text);
    let count = text
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
        .count();
    let number = text.get(..count).ok_or_else(invalid)?;
    if number.is_empty()
        || number.starts_with('.')
        || number.ends_with('.')
        || number.bytes().filter(|byte| *byte == b'.').count() > 1
    {
        return Err(invalid());
    }
    let mut unit = text
        .get(count..)
        .ok_or_else(invalid)?
        .strip_prefix(' ')
        .unwrap_or_else(|| &text[count..]);
    let ago = unit.ends_with(" ago");
    let from_now = unit.ends_with(" from now");
    if (ago || from_now) && sign.is_some() {
        return Err(invalid());
    }
    if ago {
        unit = unit.strip_suffix(" ago").ok_or_else(invalid)?;
    } else if from_now {
        unit = unit.strip_suffix(" from now").ok_or_else(invalid)?;
    }
    let factor = match unit.to_ascii_lowercase().as_str() {
        "second" | "seconds" | "sec" | "secs" | "s" => 1.0,
        "minute" | "minutes" | "min" | "mins" | "m" => 60.0,
        "hour" | "hours" | "hr" | "hrs" | "h" => 3600.0,
        "day" | "days" | "d" => 86400.0,
        "week" | "weeks" | "w" => 604_800.0,
        "month" | "months" | "mo" => 2_592_000.0,
        "year" | "years" | "yr" | "yrs" | "y" => 31_557_600.0,
        _ => return Err(invalid()),
    };
    let seconds = number.parse::<f64>().map_err(|_| invalid())?
        * factor
        * sign.unwrap_or(if ago { -1.0 } else { 1.0 });
    Ok((seconds + 0.5).floor())
}
