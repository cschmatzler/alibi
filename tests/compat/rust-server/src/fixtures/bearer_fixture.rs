//! Real session issuance with deterministic application-owned token hooks.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    ApiKeyConfig, ApiKeyPlugin, BearerConfig, BearerPlugin, EmailPasswordPlugin,
    MultiSessionPlugin, SessionManagementPlugin,
};
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult, prelude::CreateSession};
use axum::{Router,Json,routing::post,response::IntoResponse};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TokenHook(Arc<AtomicUsize>);
struct ApplicationExposure;
#[async_trait::async_trait]
impl alibi::AuthPlugin<TestSchema> for ApplicationExposure {
    fn name(&self) -> &'static str {
        "application-exposure"
    }
    fn endpoint_hooks(&self)->Vec<&dyn alibi::endpoint::EndpointHook<TestSchema>>{vec![self]}
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &alibi::AuthRequest,
        _: &alibi::AuthContext<TestSchema>,
    ) -> AuthResult<Option<alibi::AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        _: &alibi::AuthRequest,
        _: &alibi::AuthContext<TestSchema>,
        mut response: alibi::AuthResponse,
    ) -> AuthResult<alibi::AuthResponse> {
        drop(response.headers.insert(
            "access-control-expose-headers",
            "X-First, X-First, X-Second",
        ));
        Ok(response)
    }
}
#[async_trait::async_trait]
impl alibi::endpoint::EndpointHook<TestSchema> for ApplicationExposure{
 async fn after(&self,_call:&alibi::endpoint::EndpointCall,_ctx:&alibi::AuthContext<TestSchema>,response:alibi::endpoint::EndpointResponse)->AuthResult<alibi::endpoint::EndpointResponse>{Ok(response.with_header("access-control-expose-headers","X-First, X-First, X-Second"))}
}
#[async_trait::async_trait]
impl alibi::seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        session.token = Some(format!(
            "bearer{:026}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        ));
        Ok(alibi::seaorm::HookControl::Continue)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut sdk_profiles=std::collections::HashMap::new();
    for name in [
        "bearer-default",
        "bearer-signed",
        "bearer-composition",
        "bearer-renamed-cookie",
        "bearer-secure-cookie",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name == "bearer-renamed-cookie" {
            config.advanced.cookies.insert(
                "session_token".into(),
                alibi::CookieOverride {
                    name: Some("configured-bearer-token".into()),
                    ..Default::default()
                },
            );
        }
        if name == "bearer-secure-cookie" {
            config.advanced.use_secure_cookies = Some(true);
            config.advanced.cookie_prefix = Some("bearer-app".into());
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
                    .hook(TokenHook(counter.clone())),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new());
        let builder = if name == "bearer-signed" {
            builder.plugin(ApplicationExposure)
        } else {
            builder
        };
        let builder = builder.plugin(BearerPlugin::with_config(BearerConfig {
            require_signature: name == "bearer-signed",
        }));
        let builder = if name == "bearer-composition" {
            builder
                .plugin(MultiSessionPlugin::new())
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    enable_session_for_api_keys: true,
                    ..Default::default()
                }))
        } else {
            builder
        };
        let auth = Arc::new(builder.build().await?);
        _=sdk_profiles.insert(name.to_owned(),auth.clone());
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route("/__test/server-api/bearer",post(move|Json(input):Json<Value>|{let profiles=sdk_profiles.clone();async move{
        let profile=input.get("profile").and_then(Value::as_str).unwrap_or("bearer-default");let Some(auth)=profiles.get(profile)else{return axum::http::StatusCode::NOT_FOUND.into_response();};
        let (plugin,operation)=match input.get("action").and_then(Value::as_str){Some("sign-up")=>("email-password","signUpEmail"),Some("list")=>("multi-session","listDeviceSessions"),Some("sign-out")=>("session-management","signOut"),_=>("session-management","getSession")};let mut endpoint=alibi::endpoint::ServerEndpoint::<Value>::new(plugin,operation);if let Some(body)=input.get("body"){endpoint=endpoint.with_body(body).unwrap();}
        let request=input.get("requestHeaders").map(|headers|{let mut request=alibi::AuthRequest::new(alibi::HttpMethod::Get,"/get-session");request.headers=serde_json::from_value(headers.clone()).unwrap();request});
        let options=alibi::endpoint::EndpointOptions{headers:input.get("headers").map(|headers|serde_json::from_value(headers.clone()).unwrap()),request,..Default::default()};
        match auth.dispatch_endpoint(endpoint,options).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()}
    }})))
}
