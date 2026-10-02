//! Real installed endpoint callbacks and independently read persisted rows.
use crate::TestSchema;
use axum::{
    Json, Router,
    body::to_bytes,
    extract::Request,
    routing::{get, post},
};
use better_auth::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointError, EndpointHook,
    EndpointOptions, EndpointResponse, ServerEndpoint, current_endpoint_call_context,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::api_key::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyGenerationOptions, ApiKeyGenerator, ApiKeyGetter,
    ApiKeyValidator, RateLimitDefaults,
};
use better_auth::plugins::email_otp::{
    EmailOtpConfig, EmailOtpGenerator, EmailOtpPlugin, EmailOtpType,
};
use better_auth::plugins::haveibeenpwned::{
    HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient,
};
use better_auth::plugins::jwt::JwtPlugin;
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;
use better_auth::plugins::two_factor::TwoFactorConfig;
use better_auth::plugins::{
    ApiKeyPlugin, EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::utils::json::{self, JsValue};
use better_auth_core::{AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, HttpMethod};
use better_auth_core::{PasswordHasher, ScryptHasher};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement},
};
use serde::Deserialize;
use serde_json::{Value, json as value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const HASH_PASSWORD: &str = "Actual-Phase-Hash-Password-205";

#[derive(Clone, Default)]
struct Application {
    events: Arc<Mutex<Vec<Value>>>,
    mode: Arc<Mutex<String>>,
    other: Arc<Mutex<Option<Arc<better_auth::BetterAuth<TestSchema>>>>>,
    primary: Arc<Mutex<Option<Arc<better_auth::BetterAuth<TestSchema>>>>>,
    hash_phase: Arc<Mutex<String>>,
    ranges: Arc<Mutex<Vec<Value>>>,
    serial: Arc<std::sync::atomic::AtomicUsize>,
}
fn error_body(error: &AuthError) -> Value {
    let (_, code, message) = error.error_payload();
    let mut body = value!({"message":message});
    if let Some(code) = code {
        body["code"] = value!(code);
    }
    body
}
fn returned(response: Option<&EndpointResponse>) -> Value {
    response.map_or(Value::Null,|response| match response.result(){Ok(value)=>serde_json::to_value(value).unwrap(),Err(error)=>value!({"api":true,"status":error.status_code(),"body":response.error_body().map_or_else(||error_body(error),|body|serde_json::to_value(body).unwrap())})})
}
fn input_snapshot(call: &EndpointCall) -> Value {
    value!({"pathPresent":true,"path":call.path(),"methodPresent":call.has_method(),"method":call.method().map(|method|format!("{method:?}").to_uppercase()),"bodyPresent":call.has_body(),"body":call.body(),"queryPresent":call.has_query(),"query":call.query(),"headers":call.headers(),"request":call.request().map(|request|value!({"url":request.url().map(|url|url.as_str()),"method":format!("{:?}",request.method()).to_uppercase(),"headers":request.headers,"query":request.query,"body":request.body.as_ref().map(|body|String::from_utf8_lossy(body).into_owned())})),"session":call.session().map(|(user,session)|value!({"user":user,"session":session}))})
}
fn snapshot(call: &EndpointCall, response: Option<&EndpointResponse>) -> Value {
    let mut snapshot = input_snapshot(call);
    snapshot["returned"] = returned(response);
    snapshot["current"] = current_endpoint_call_context()
        .as_ref()
        .map_or(Value::Null, input_snapshot);
    snapshot["legacyRequest"] = better_auth_core::hooks::current_request_hook_context().map_or(Value::Null, |request|value!({"url":request.url.as_ref().map(url::Url::as_str),"method":format!("{:?}",request.method).to_uppercase(),"headers":request.headers,"query":request.query,"body":request.body.as_ref().map(|body|String::from_utf8_lossy(body).into_owned())}));
    snapshot
}
impl Application {
    fn record(&self, stage: String, call: &EndpointCall, response: Option<&EndpointResponse>) {
        let mut event = snapshot(call, response);
        event["stage"] = value!(stage);
        self.events.lock().unwrap().push(event);
    }
    async fn hash_at(&self, phase: &str, context: &AuthContext<TestSchema>) -> AuthResult<()> {
        *self.hash_phase.lock().unwrap() = phase.into();
        let hasher: Arc<dyn PasswordHasher> = Arc::new(self.clone());
        context.hash_password(Some(&hasher), HASH_PASSWORD).await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl better_auth_core::CookieCacheVersionResolver for Application {
    async fn resolve(&self, input: &better_auth_core::CacheVersionContext) -> AuthResult<String> {
        self.events.lock().unwrap().push(value!({
            "stage":"cache-version", "user":input.user(), "session":input.session(),
            "current":current_endpoint_call_context().as_ref().map_or(Value::Null,input_snapshot)
        }));
        tokio::task::yield_now().await;
        Ok(if input.session().expires_at > chrono::Utc::now() {
            "1"
        } else {
            "expired"
        }
        .into())
    }
}

#[async_trait::async_trait]
impl PasswordHasher for Application {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let hash = ScryptHasher.hash(password).await?;
        if self.mode.lock().unwrap().starts_with("hash-phase") {
            let call = current_endpoint_call_context()
                .ok_or_else(|| AuthError::internal("missing real hash frame"))?;
            let mut event = input_snapshot(&call);
            let (salt, key) = hash.split_once(':').unwrap();
            event["stage"] = value!("original-hash");
            event["phase"] = value!(*self.hash_phase.lock().unwrap());
            event["hash"] = value!({"token":hash,"salt":{"token":salt,"length":salt.len()},"derivedKey":{"token":key,"length":key.len()},"encoding":"hex-lower"});
            event["verified"] = value!(ScryptHasher.verify(&hash, password).await?);
            self.events.lock().unwrap().push(event);
        }
        Ok(hash)
    }
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        ScryptHasher.verify(hash, password).await
    }
}
struct Observer {
    id: &'static str,
    app: Application,
}
#[async_trait::async_trait]
impl EndpointHook<TestSchema> for Observer {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<TestSchema>) -> AuthResult<bool> {
        if self.id != "user" {
            self.app.record(format!("{}-matcher", self.id), call, None);
        }
        if self.id == "first" && *self.app.mode.lock().unwrap() == "matcher-error" {
            return Err(AuthError::internal("private matcher"));
        }
        Ok(true)
    }
    async fn before(
        &self,
        call: &EndpointCall,
        context: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        self.app.record(format!("{}-before", self.id), call, None);
        let mode = self.app.mode.lock().unwrap().clone();
        if self.id == "user" && mode.starts_with("hash-phase") {
            self.app.hash_at("before", context).await?;
        }
        if self.id == "user" && mode == "reset-app" {
            self.app
                .serial
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }
        if mode == "before-headers" {
            call.set_response_header(format!("x-{}", self.id), "before");
        }
        if self.id == "user" && (mode == "request-patch" || mode.starts_with("hash-phase")) {
            if let Some(request) = call.request() {
                let mut request = request.clone();
                drop(
                    request
                        .headers
                        .insert("x-physical-patch".into(), "actual-clone".into()),
                );
                return Ok(Some(BeforeEndpointAction::Patch(Box::new(
                    EndpointContextPatch {
                        request: Some(request),
                        ..Default::default()
                    },
                ))));
            }
        }
        if self.id == "first" {
            match mode.as_str() {
                "cancel" => {
                    call.set_response_header("x-before", "cancel");
                    return Ok(Some(BeforeEndpointAction::Respond(EndpointResponse::json(
                        &value!({"cancelled":true,"body":call.body()}),
                    )?)));
                }
                "before-error" => return Err(AuthError::internal("private before")),
                "before-api" => {
                    return Err(AuthError::Upstream {
                        status: 403,
                        code: "APP_BEFORE",
                        message: "before denied",
                    });
                }
                _ => {}
            }
        }
        if matches!(mode.as_str(), "patch" | "patch-existing-headers") {
            let body = match self.id {
                "user" => {
                    value!({"email":"UserPatch@Example.test","nested":{"user":true},"actions":["user"]})
                }
                "first" => {
                    value!({"email":"FirstPatch@Example.test","nested":{"first":true},"actions":["first"]})
                }
                _ => {
                    value!({"type":"sign-in","nested":{"second":true},"actions":["second"],"email":null})
                }
            };
            return Ok(Some(BeforeEndpointAction::Patch(Box::new(
                EndpointContextPatch {
                    body: Some(json::parse_value(&body.to_string())?),
                    headers: Some(HashMap::from([(
                        format!("x-{}", self.id),
                        "patched".into(),
                    )])),
                    ..Default::default()
                },
            ))));
        }
        Ok(None)
    }
    async fn after(
        &self,
        call: &EndpointCall,
        context: &AuthContext<TestSchema>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        self.app
            .record(format!("{}-after", self.id), call, Some(&response));
        let hash_phase = self.app.mode.lock().unwrap().starts_with("hash-phase");
        if self.id == "user" && hash_phase {
            self.app.hash_at("after", context).await?;
        }
        if self.id == "second" && *self.app.mode.lock().unwrap() == "scope-isolation" {
            let other = self.app.other.lock().unwrap().clone().unwrap();
            let session = match other.context().require_cached_session(call).await {
                Ok((user, session)) => {
                    Some(value!({"user":other.context().user_view(&user),"session":session}))
                }
                Err(AuthError::Unauthenticated) => None,
                Err(error) => return Err(error),
            };
            self.app
                .events
                .lock()
                .unwrap()
                .push(value!({"stage":"other-context-session","session":session}));
        }
        if self.id == "first" {
            match self.app.mode.lock().unwrap().as_str() {
                "after-api" => {
                    call.set_response_header("x-after", "api-error");
                    return Err(AuthError::Upstream {
                        status: 403,
                        code: "APP_AFTER",
                        message: "after denied",
                    });
                }
                "after-error" => return Err(AuthError::internal("private after")),
                "after-value" => {
                    call.set_response_header("x-after", "replacement");
                    response.replace(json::parse_value(
                        &value!({"replacement":true,"original":returned(Some(&response))})
                            .to_string(),
                    )?);
                }
                _ => {}
            }
        }
        Ok(response)
    }
}
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for Observer {
    fn name(&self) -> &'static str {
        if self.id == "first" {
            "server-dispatch-first"
        } else {
            "server-dispatch-second"
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    fn endpoint_hooks(&self) -> Vec<&dyn EndpointHook<TestSchema>> {
        vec![self]
    }
}
#[async_trait::async_trait]
impl EmailOtpGenerator for Application {
    async fn generate(
        &self,
        email: &str,
        otp_type: EmailOtpType,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<Option<String>> {
        let call = _context
            .endpoint
            .clone()
            .ok_or_else(|| AuthError::internal("missing actual logical context"))?;
        let mut event = snapshot(&call, None);
        event["stage"] = value!("otp-generator");
        event["input"] = value!({"email":email,"type":otp_type});
        self.events.lock().unwrap().push(event);
        if self.mode.lock().unwrap().starts_with("hash-phase") {
            let auth = self.primary.lock().unwrap().clone().unwrap();
            self.hash_at("handler", auth.context()).await?;
        }
        Ok(Some("591307".into()))
    }
}
#[async_trait::async_trait]
impl ApiKeyGenerator for Application {
    async fn generate_key(&self, input: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        self.events.lock().unwrap().push(value!({"stage":"api-key-generator","input":{"length":input.length,"prefix":input.prefix}}));
        Ok(format!(
            "server-dispatch-actual-key-{:06}",
            self.serial
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1
        ))
    }
}
impl ApiKeyGetter for Application {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>> {
        if let Some(call) = &context.endpoint {
            self.record("api-key-getter".into(), call, None);
            Ok(call
                .headers()
                .and_then(|headers| headers.get("x-api-key"))
                .cloned())
        } else {
            Ok(context
                .request
                .and_then(|request| request.headers.get("x-api-key"))
                .cloned())
        }
    }
}
#[async_trait::async_trait]
impl ApiKeyValidator for Application {
    async fn validate(&self, context: &ApiKeyCallbackContext<'_>, key: &str) -> AuthResult<bool> {
        if let Some(call) = &context.endpoint {
            let mut event = snapshot(call, None);
            event["stage"] = value!("api-key-validator");
            event["key"] = value!(key);
            self.events.lock().unwrap().push(event);
        }
        Ok(true)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    operation: String,
    mode: Option<String>,
    body: Option<JsValue>,
    query: Option<JsValue>,
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    physical_request: bool,
    #[serde(default)]
    logical_request_headers: bool,
}
fn header_snapshot(headers: &better_auth_core::Headers) -> HashMap<String, String> {
    let mut values: HashMap<_, _> = headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let cookies: Vec<_> = headers.get_all("set-cookie").cloned().collect();
    if !cookies.is_empty() {
        drop(values.insert("set-cookie".into(), cookies.join(", ")));
    }
    values
}
fn outcome(result: Result<better_auth::endpoint::EndpointOutput<JsValue>, EndpointError>) -> Value {
    match result {
        Ok(output) => {
            let mut result =
                value!({"headers":header_snapshot(output.headers()),"response":output.value()});
            if let Some(status) = output.status() {
                result["status"] = value!(status);
            }
            value!({"ok":true,"value":result})
        }
        Err(error) => {
            let api = better_auth::endpoint::is_endpoint_api_error(&error.error);
            let message = match &error.error {
                AuthError::Internal(message) => message.clone(),
                error => error.error_payload().2,
            };
            value!({"ok":false,"name":if api{"APIError"}else{"Error"},"status":if api{Some(error.error.status_code())}else{None},"body":error.body.map_or_else(||if api{error_body(&error.error)}else{Value::Null},|body|serde_json::to_value(body).unwrap()),"message":message,"headers":error.headers.map(|headers|header_snapshot(&headers))})
        }
    }
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    profile: &str,
    compact: bool,
) -> AuthResult<Router> {
    let path = format!("/__test/profiles/{profile}/api/auth");
    let control_path = format!("/__test/{profile}");
    let app = Application::default();
    let configured =
        base.clone()
            .base_path(&path)
            .session_cookie_cache(better_auth_core::CookieCacheConfig {
                enabled: compact,
                max_age: 300.0,
                version: if profile == "server-dispatch-cache-version" {
                    Some(better_auth_core::CookieCacheVersion::Resolver(Arc::new(
                        app.clone(),
                    )))
                } else {
                    None
                },
                ..Default::default()
            });
    let range_app = app.clone();
    let range=Router::new().fallback(move|request:Request|{
        let app=range_app.clone();async move{
            let (parts,body)=request.into_parts();
            let body=to_bytes(body,1_048_576).await.unwrap();
            let header=|name:&str|parts.headers.get(name).and_then(|value|value.to_str().ok());
            app.ranges.lock().unwrap().push(value!({"method":parts.method.as_str(),"path":parts.uri.path(),"query":parts.uri.query().map_or(String::new(),|query|format!("?{query}")),"headers":{"addPadding":header("add-padding"),"userAgent":header("user-agent"),"authorization":header("authorization"),"cookie":header("cookie")},"body":String::from_utf8_lossy(&body)}));
            // Corpus suffix of the fixed application password, independently
            // checked against SHA-1 by the client owner.
            let count=if *app.mode.lock().unwrap()=="hash-phase-deny" {1}else{0};
            ([("content-type","text/plain")],format!("A1BC493DA6992DF25BB5C58FF0946750656:{count}\r\n"))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let _range = tokio::spawn(async move { axum::serve(listener, range).await });
    let range_client = PwnedPasswordClient::new(
        reqwest::Client::new(),
        url::Url::parse(&format!("http://{address}/range/")).unwrap(),
    );
    let other = Arc::new(
        AuthBuilder::<TestSchema>::new(
            base.clone()
                .base_path(format!("{control_path}/other/api/auth")),
        )
        .store(SeaOrmStore::new(base.clone(), database.clone()))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?,
    );
    *app.other.lock().unwrap() = Some(other);
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(configured.clone())
            .store(SeaOrmStore::new(configured, database.clone()))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .endpoint_hook(Observer {
                id: "user",
                app: app.clone(),
            })
            .plugin(EmailPasswordPlugin::with_config(
                better_auth::plugins::EmailPasswordConfig {
                    enable_username: false,
                    password_hasher: Some(Arc::new(app.clone())),
                    ..Default::default()
                },
            ))
            .plugin(SessionManagementPlugin::new())
            .plugin(Observer {
                id: "first",
                app: app.clone(),
            })
            .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                generate_otp: Some(Arc::new(app.clone())),
                ..Default::default()
            }))
            .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                config_id: "dispatch".into(),
                enable_session_for_api_keys: true,
                enable_metadata: true,
                key_length: 16.0,
                custom_key_generator: Some(Arc::new(app.clone())),
                custom_api_key_getter: Some(Arc::new(app.clone())),
                custom_api_key_validator: Some(Arc::new(app.clone())),
                rate_limit: RateLimitDefaults {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            }))
            .plugin(Observer {
                id: "second",
                app: app.clone(),
            })
            .plugin(OneTimeTokenPlugin::new())
            .plugin(JwtPlugin::new())
            .plugin(OrganizationPlugin::new())
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                custom_backup_codes_generate: Some(Arc::new(|| {
                    Ok(vec![
                        "application-backup-one".into(),
                        "application-backup-two".into(),
                    ])
                })),
                ..Default::default()
            }))
            .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
                paths: Some(vec!["/".into(), "virtual:".into()]),
                client: range_client,
                ..Default::default()
            }))
            .build()
            .await?,
    );
    *app.primary.lock().unwrap() = Some(auth.clone());
    let mut router = Router::new().nest(&path, auth.clone().axum_router().with_state(auth.clone()));
    router = router.route(
        &format!("{control_path}/call"),
        post(move |request: Request| {
            let auth = auth.clone();
            let app = app.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 1_048_576).await.unwrap();
                let input: Input = json::from_slice(&bytes).unwrap();
                *app.mode.lock().unwrap() = input.mode.unwrap_or_else(|| "normal".into());
                app.events.lock().unwrap().clear();
                app.ranges.lock().unwrap().clear();
                let plugin = match input.operation.as_str() {
                    "createVerificationOTP" | "getVerificationOTP" => "email-otp",
                    "signJWT" | "verifyJWT" | "getToken" | "getJwks" => "jwt",
                    "createOrganization" | "deleteOrganization" | "addMember" | "removeMember" => {
                        "organization"
                    }
                    "generateOneTimeToken" | "verifyOneTimeToken" => "one-time-token",
                    "generateTOTP" | "viewBackupCodes" => "two-factor",
                    _ => "api-key",
                };
                // The control routes real input to the registered operation; hooks and
                // authentication are exclusively owned by production dispatch.
                let operation: &'static str = match input.operation.as_str() {
                    "createVerificationOTP" => "createVerificationOTP",
                    "getVerificationOTP" => "getVerificationOTP",
                    "signJWT" => "signJWT",
                    "verifyJWT" => "verifyJWT",
                    "getToken" => "getToken",
                    "getJwks" => "getJwks",
                    "createOrganization" => "createOrganization",
                    "deleteOrganization" => "deleteOrganization",
                    "addMember" => "addMember",
                    "removeMember" => "removeMember",
                    "generateOneTimeToken" => "generateOneTimeToken",
                    "verifyOneTimeToken" => "verifyOneTimeToken",
                    "generateTOTP" => "generateTOTP",
                    "viewBackupCodes" => "viewBackupCodes",
                    "createApiKey" => "createApiKey",
                    "updateApiKey" => "updateApiKey",
                    "verifyApiKey" => "verifyApiKey",
                    "deleteAllExpiredApiKeys" => "deleteAllExpiredApiKeys",
                    _ => "unknown",
                };
                let mut endpoint = ServerEndpoint::<JsValue>::new(plugin, operation);
                if let Some(body) = input.body {
                    endpoint = endpoint.with_body_value(body);
                }
                if let Some(query) = input.query {
                    endpoint = endpoint.with_query_value(query);
                }
                let logical_headers = input.headers.or_else(|| {
                    input.logical_request_headers.then(|| parts.headers.iter().map(|(name,value)| (name.to_string(),value.to_str().unwrap().to_owned())).collect())
                });
                let request = if input.physical_request {
                    let actual_host = parts
                        .headers
                        .get("host")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("localhost")
                        .to_owned();
                    let actual_scheme = parts.uri.scheme_str().unwrap_or("http").to_owned();
                    let headers = parts
                        .headers
                        .iter()
                        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
                        .collect();
                    let actual_url =
                        url::Url::parse(&format!("{actual_scheme}://{actual_host}{}", parts.uri))
                            .unwrap();
                    let query_pairs: Vec<_> = actual_url
                        .query_pairs()
                        .map(|(name, value)| (name.into_owned(), value.into_owned()))
                        .collect();
                    let mut request = AuthRequest::from_parts(
                        HttpMethod::Post,
                        parts.uri.path().into(),
                        headers,
                        Some(bytes.to_vec()),
                        query_pairs.iter().cloned().collect(),
                    )
                    .with_url(actual_url);
                    request.set_query_pairs(query_pairs);
                    Some(request)
                } else {
                    None
                };
                let result = outcome(
                    auth.dispatch_endpoint(
                        endpoint,
                        EndpointOptions {
                            headers: logical_headers,
                            request,
                            ..Default::default()
                        },
                    )
                    .await,
                );
                Json(value!({"events":app.events.lock().unwrap().clone(),"ranges":app.ranges.lock().unwrap().clone(),"result":result}))
            }
        }),
    );
    router=router.route(&format!("{control_path}/state"),get(move||{let database=database.clone();async move{
        let mut state=serde_json::Map::new();
        for (name,sql) in [
            ("verification","SELECT json_object('id',id,'identifier',identifier,'value',value,'expiresAt',expires_at,'createdAt',created_at,'updatedAt',updated_at) AS data FROM verifications ORDER BY identifier,id"),
            ("apikey","SELECT json_object('id',id,'name',name,'start',start,'prefix',prefix,'key',key,'referenceId',reference_id,'configId',config_id,'refillInterval',refill_interval,'refillAmount',refill_amount,'lastRefillAt',last_refill_at,'enabled',json(CASE enabled WHEN 1 THEN 'true' ELSE 'false' END),'rateLimitEnabled',json(CASE rate_limit_enabled WHEN 1 THEN 'true' ELSE 'false' END),'rateLimitTimeWindow',rate_limit_time_window,'rateLimitMax',rate_limit_max,'requestCount',request_count,'remaining',remaining,'lastRequest',last_request,'expiresAt',expires_at,'createdAt',created_at,'updatedAt',updated_at,'permissions',permissions,'metadata',metadata,'startHex',hex(CAST(start AS BLOB)),'startType',typeof(start)) AS data FROM api_keys ORDER BY name,id"),
            ("organization","SELECT json_object('id',id,'name',name,'slug',slug,'logo',logo,'createdAt',created_at,'metadata',metadata) AS data FROM organization ORDER BY slug,id"),
            ("member","SELECT json_object('id',id,'organizationId',organization_id,'userId',user_id,'role',role,'createdAt',created_at) AS data FROM member ORDER BY role,id"),
            ("session","SELECT json_object('id',id,'expiresAt',expires_at,'token',token,'createdAt',created_at,'updatedAt',updated_at,'ipAddress',ip_address,'userAgent',user_agent,'userId',user_id,'impersonatedBy',impersonated_by,'activeOrganizationId',active_organization_id,'activeTeamId',active_team_id) AS data FROM sessions ORDER BY created_at,id")
        ] {let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,sql)).await.unwrap();let rows:Vec<Value>=rows.iter().map(|row|serde_json::from_str(&row.try_get::<String>("","data").unwrap()).unwrap()).collect();drop(state.insert(name.into(),value!(rows)));}
        Json(Value::Object(state))
    }}));
    Ok(router)
}
