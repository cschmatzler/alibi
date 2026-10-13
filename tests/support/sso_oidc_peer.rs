//! Controlled OIDC peer grants codes only after validating their PKCE challenge.
use axum::{
    Json, Router,
    extract::{Form, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use sha2::Digest as _;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub(super) struct Peer {
    pub base: String,
    pub email: Arc<Mutex<String>>,
    pub exchanges: Arc<Mutex<Vec<serde_json::Value>>>,
}
pub(super) async fn start() -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let email = Arc::new(Mutex::new(String::from("sso-employee@example.test")));
    let codes = Arc::new(Mutex::new(HashMap::<String, (String, String)>::new()));
    let tokens = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let authorize_codes = codes.clone();
    let authorize_email = email.clone();
    let token_codes = codes;
    let token_tokens = tokens.clone();
    let log = exchanges.clone();
    let app=Router::new().route("/authorize",get(move|Query(query):Query<HashMap<String,String>>|{let codes=authorize_codes.clone();let email=authorize_email.clone();async move{
 if query.get("client_id").map(String::as_str)!=Some("enterprise-client")||query.get("code_challenge_method").map(String::as_str)!=Some("S256"){return StatusCode::BAD_REQUEST.into_response();}
 let Some(challenge)=query.get("code_challenge")else{return StatusCode::BAD_REQUEST.into_response();};let Some(callback)=query.get("redirect_uri")else{return StatusCode::BAD_REQUEST.into_response();};
 let code=uuid::Uuid::new_v4().to_string();_ = codes.lock().unwrap().insert(code.clone(),(challenge.clone(),email.lock().unwrap().clone()));let mut location=url::Url::parse(callback).unwrap();_ = location.query_pairs_mut().append_pair("code",&code).append_pair("state",query.get("state").map_or("",String::as_str));
 (StatusCode::FOUND,[("location",location.to_string())]).into_response()
 }})).route("/token",post(move|headers:HeaderMap,Form(form):Form<HashMap<String,String>>|{let codes=token_codes.clone();let tokens=token_tokens.clone();let exchanges=log.clone();async move{
 exchanges.lock().unwrap().push(serde_json::json!({"authorization":headers.get("authorization").and_then(|header|header.to_str().ok()),"form":form}));
 if headers.get("authorization").and_then(|value|value.to_str().ok())!=Some("Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA=="){return failure();}
 let Some(code)=form.get("code")else{return failure();};let Some((challenge,email))=codes.lock().unwrap().remove(code)else{return failure();};
 let Some(verifier)=form.get("code_verifier")else{return failure();};if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()))!=challenge{return failure();}
 let token=uuid::Uuid::new_v4().to_string();_ = tokens.lock().unwrap().insert(token.clone(),email);Json(serde_json::json!({"access_token":token,"token_type":"Bearer","expires_in":3600,"scope":"openid email"})).into_response()
 }})).route("/userinfo",get(move|headers:HeaderMap|{let tokens=tokens.clone();async move{
 let token=headers.get("authorization").and_then(|value|value.to_str().ok()).and_then(|value|value.strip_prefix("Bearer ")).unwrap_or("");
 let email=tokens.lock().unwrap().get(token).cloned();match email{Some(email)=>Json(serde_json::json!({"sub":"employee-subject","email":email,"email_verified":true,"name":"SSO employee"})).into_response(),None=>StatusCode::UNAUTHORIZED.into_response()}
 }}));
    _ = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Peer {
        base,
        email,
        exchanges,
    }
}
fn failure() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error":"invalid_grant"})),
    )
        .into_response()
}
