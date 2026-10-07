//! Trusted server signing through an actual application-owned HS256 signer.
use crate::TestSchema;
use axum::{Json, Router, body::Bytes, http::StatusCode, response::IntoResponse, routing::get};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use alibi::plugins::jwt::{
    DefineJwtPayload, JwtAlgorithm, JwtAudience, JwtClaimsConfig, JwtExpiration, JwtPlugin,
    JwtPluginConfig, JwtSession, JwtSignOptions, RemoteJwtClaim, RemoteJwtPayload, SignRemoteJwt,
};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use alibi_core::utils::json::JsValue;
use alibi_seaorm::DatabaseConnection;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
const SECRET: &str = "remote-jwt-application-secret-minimum-32-characters";
#[derive(Clone, Default)]
struct State {
    events: Arc<Mutex<Vec<Value>>>,
    failure: Arc<Mutex<Option<String>>>,
}
#[derive(Clone)]
struct Application {
    state: State,
    mode: &'static str,
}
#[async_trait::async_trait]
impl DefineJwtPayload for Application {
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
        let mut payload = serde_json::to_value(&session.user)?
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("session payload object"))?;
        if let Some(failure) = self
            .state
            .failure
            .lock()
            .map_err(|_| AuthError::internal("signer lock"))?
            .clone()
        {
            drop(payload.insert("applicationError".into(), json!(failure)));
        }
        let mut entries: Vec<_> = payload.into_iter().collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries.into_iter().collect())
    }
}
#[async_trait::async_trait]
impl SignRemoteJwt for Application {
    async fn sign(
        &self,
        payload: &RemoteJwtPayload,
        options: &JwtSignOptions,
    ) -> AuthResult<String> {
        let captured: Map<String, Value> = payload
            .own_keys()
            .iter()
            .map(|key| {
                let value = match payload.claim(key) {
                    RemoteJwtClaim::Undefined => json!({"$undefined":true}),
                    RemoteJwtClaim::Value(value) => capture(value),
                    RemoteJwtClaim::Absent => Value::Null,
                };
                (key.clone(), value)
            })
            .collect();
        let payload_json = payload.raw_claims().to_json_value()?;
        self.state.events.lock().map_err(|_|AuthError::internal("signer lock"))?.push(json!({"payload":captured,"ownKeys":payload.own_keys(),"header":options.header.as_ref().map_or_else(||json!({"$undefined":true}),|header|json!(header)),"options":{"signingKeyId":options.signing_key_id.as_ref().map_or_else(||json!({"$undefined":true}),|value|json!(value)),"signingAlgorithm":options.signing_algorithm.map_or_else(||json!({"$undefined":true}),|value|json!(value.as_str()))}}));
        if payload_json.get("applicationError").and_then(Value::as_str) == Some("ordinary") {
            return Err(AuthError::internal("application signer failed"));
        }
        if payload_json.get("applicationError").and_then(Value::as_str) == Some("api") {
            return Err(AuthError::Upstream {
                status: 403,
                code: "APPLICATION_SIGNING_DENIED",
                message: "application denied signing",
            });
        }
        if self.mode == "result" {
            if let Some(result) = payload_json.get("customResult").and_then(Value::as_str) {
                return Ok(result.into());
            }
        }
        let mut header = options.header.clone().unwrap_or_default();
        drop(header.insert("alg".into(), json!("HS256")));
        drop(header.insert("kid".into(), json!("application-remote-key")));
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(alibi_core::utils::json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(alibi_core::utils::json::to_vec(&payload_json)?)
        );
        let cookie = alibi_core::utils::cookie_utils::sign_cookie_value(&input, SECRET);
        let encoded = cookie
            .rsplit('.')
            .next()
            .ok_or_else(|| AuthError::internal("signature segment"))?;
        let decoded = url::form_urlencoded::parse(format!("signature={encoded}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .ok_or_else(|| AuthError::internal("signature decode"))?;
        let bytes = STANDARD
            .decode(decoded)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(bytes)))
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    operation: String,
    profile: Option<String>,
    payload: Option<JsValue>,
    #[serde(default)]
    nan_fields: Vec<String>,
    #[serde(default)]
    header: Map<String, Value>,
    signing_key_id: Option<String>,
    signing_algorithm: Option<JwtAlgorithm>,
    failure: Option<String>,
}
fn capture(value: &JsValue) -> Value {
    match value {
        JsValue::Number(number)
            if !number.is_finite() || (*number == 0.0 && number.is_sign_negative()) =>
        {
            json!({"$number":if number.is_nan(){"NaN"}else if *number==f64::INFINITY{"Infinity"}else if *number==f64::NEG_INFINITY{"-Infinity"}else{"-0"}})
        }
        JsValue::Array(values) => Value::Array(values.iter().map(capture).collect()),
        JsValue::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), capture(value)))
                .collect(),
        ),
        value => value.to_json_value().expect("finite JSON capture"),
    }
}
fn failure(error: AuthError) -> axum::response::Response {
    if let AuthError::CallbackFailure(error) = error {
        return failure(*error);
    }
    let (status, value) = match error {
        AuthError::Upstream {
            status,
            code,
            message,
        } => (
            status,
            json!({"error":{"status":status,"body":{"code":code,"message":message}}}),
        ),
        AuthError::Internal(message) => (500, json!({"error":{"message":message}})),
        other => (500, json!({"error":{"message":other.to_string()}})),
    };
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(value),
    )
        .into_response()
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let state = State::default();
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for mode in ["raw", "configured", "result", "error"] {
        let app = Arc::new(Application {
            state: state.clone(),
            mode,
        });
        let name = format!("jwt-remote-{mode}");
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base.clone().base_path(&path);
        let mut options = JwtPluginConfig {
            remote_url: Some("https://keys.fixture.test/remote-jwks".into()),
            remote_signer: Some(app.clone()),
            ..Default::default()
        };
        if mode == "raw" {
            options.claims.issuer = Some("remote-application-issuer".into());
            options.claims.audience = Some(JwtAudience::One("remote-application-audience".into()));
        }
        if mode == "configured" {
            options.claims = JwtClaimsConfig {
                issuer: Some("application-issuer".into()),
                audience: Some(JwtAudience::Many(vec![
                    "application-audience".into(),
                    "alternate-audience".into(),
                ])),
                expiration: JwtExpiration::After(chrono::Duration::seconds(60)),
            };
        }
        if mode == "error" {
            options.define_payload = Some(app);
        }
        let jwt = JwtPlugin::with_config(options);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(true),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(jwt.clone())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        drop(profiles.insert(name, (auth, jwt)));
    }
    let profiles = Arc::new(profiles);
    let observed = state.clone();
    router=router.route("/__test/jwt-remote",get(move||{let state=observed.clone();async move{let events=state.events.lock().map_err(|_|AuthError::internal("signer lock"))?.clone();Ok::<_,AuthError>(Json(json!({"events":events})))}}).post(move|body:Bytes|{let state=state.clone();let profiles=profiles.clone();async move{
  let operation=async{
   let body:Operation=alibi_core::utils::json::from_slice(&body)?;
   if body.operation=="clear"{state.events.lock().map_err(|_|AuthError::internal("signer lock"))?.clear();*state.failure.lock().map_err(|_|AuthError::internal("signer lock"))?=None;return Ok(json!({"changed":true}));}
   if body.operation=="failure"{*state.failure.lock().map_err(|_|AuthError::internal("signer lock"))?=body.failure;return Ok(json!({"changed":true}));}
   let (auth,jwt)=profiles.get(body.profile.as_deref().unwrap_or("jwt-remote-raw")).ok_or_else(||AuthError::bad_request("unknown signer profile"))?;
   let mut payload=body.payload.ok_or_else(||AuthError::bad_request("payload is required"))?;
   if let JsValue::Object(fields)=&mut payload{for key in body.nan_fields{drop(fields.insert(key,JsValue::Number(f64::NAN)));}}
   let options=JwtSignOptions{header:Some(body.header),signing_key_id:body.signing_key_id,signing_algorithm:body.signing_algorithm,..Default::default()};
   Ok::<_,AuthError>(json!({"token":jwt.sign_jwt_json(&payload,&options,None,auth.context()).await?}))
  }.await;
  match operation{Ok(value)=>Json(value).into_response(),Err(error)=>failure(error)}
 }}));
    Ok(router)
}
