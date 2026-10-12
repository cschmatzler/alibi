//! Direct public error calls retain actual response values and hook metadata.
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::integrations::axum::AxumIntegration;
use alibi::utils::json::JsValue;
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthRequest, AuthResult, HttpMethod};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::Request,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

#[path = "../../../../fixtures/server_error_application.rs"]
mod application;
use application::{Application, response_snapshot};

pub(crate) async fn router(base: &AuthConfig) -> AuthResult<Router> {
    let app = Application::default();
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for profile in ["default", "html", "configured"] {
        let path = format!("/__test/profiles/server-error-{profile}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.api_error_url = None;
        config.render_error_page = profile != "default";
        if profile == "configured" {
            config.api_error_url = Some("/problem?keep=a%2Bb#error-panel".into());
        }
        let auth = Arc::new(
            AuthBuilder::without_database(config)
                .endpoint_hook(app.clone())
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(profile, auth);
    }
    let event_app = app.clone();
    router = router.route(
        "/__test/server-error/events",
        get(move || {
            let app = event_app.clone();
            async move { Json(app.events.lock().unwrap().clone()) }
        }),
    );
    router=router.route("/__test/server-error/call",post(move|request:Request|{let app=app.clone();let profiles=profiles.clone();async move{
        let(parts,body)=request.into_parts();let bytes=to_bytes(body,1_048_576).await.unwrap();let input:Value=serde_json::from_slice(&bytes).unwrap();
        *app.mode.lock().unwrap()=input["mode"].as_str().unwrap_or("normal").into();app.events.lock().unwrap().clear();
        let actual_host=parts.headers.get("host").unwrap().to_str().unwrap();let actual_url=url::Url::parse(&format!("http://{actual_host}{}",parts.uri)).unwrap();
        let query=actual_url.query_pairs().map(|(k,v)|(k.into_owned(),v.into_owned())).collect::<Vec<_>>();
        let mut actual=AuthRequest::from_parts(HttpMethod::Post,parts.uri.path().into(),parts.headers.iter().map(|(k,v)|(k.to_string(),v.to_str().unwrap().into())).collect(),Some(bytes.to_vec()),query.iter().cloned().collect()).with_url(actual_url);actual.set_query_pairs(query);
        let mut endpoint=ServerEndpoint::<JsValue>::new("core","error");
        if let Some(query)=input.get("query"){endpoint=endpoint.with_query(query).unwrap();}
        if let Some(body)=input.get("body"){endpoint=endpoint.with_body(body).unwrap();}
        let options=EndpointOptions{headers:input.get("headers").map(|h|serde_json::from_value(h.clone()).unwrap()),request:input["physicalRequest"].as_bool().filter(|v|*v).map(|_|actual),..Default::default()};
        let auth=&profiles[input["profile"].as_str().unwrap_or("default")];
        let result=match auth.dispatch_endpoint(endpoint,options).await {
            Ok(output)=>if input["asResponse"].as_bool().unwrap_or(false){json!({"kind":"forwarded","response":response_snapshot(&output.into_response().unwrap())})}else{
                let mut result=json!({"kind":"metadata","headers":output.headers().iter().filter(|(k,_)|!k.eq_ignore_ascii_case("set-cookie")).map(|(k,v)|(k.to_ascii_lowercase(),v.clone())).collect::<HashMap<_,_>>(),"cookies":output.headers().get_all("set-cookie").cloned().collect::<Vec<_>>(),
                    "response":output.http_response().map_or_else(||json!({"kind":"json","value":output.value()}),response_snapshot)});
                if let Some(status)=output.status(){result["status"]=json!(status);}result
            },
            Err(error)=>json!({"kind":"failure","api":alibi::endpoint::is_endpoint_api_error(&error.error),"message":match &error.error{AuthError::Internal(message)=>message.clone(),other=>other.error_payload().2},"hasHeaders":error.headers.is_some()}),
        };Json(json!({"events":app.events.lock().unwrap().clone(),"result":result}))
    }}));
    Ok(router)
}
