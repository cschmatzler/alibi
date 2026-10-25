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
    pub profile: Arc<Mutex<Option<serde_json::Value>>>,
    pub email: Arc<Mutex<String>>,
    pub discovery_case: Arc<Mutex<String>>,
    pub id_token_case: Arc<Mutex<String>>,
    pub exchanges: Arc<Mutex<Vec<serde_json::Value>>>,
}
pub(super) async fn start() -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let email = Arc::new(Mutex::new(String::from("sso-employee@example.test")));
    let id_token_case = Arc::new(Mutex::new(String::from("none")));
    let discovery_case = Arc::new(Mutex::new(String::from("valid")));
    let discovery_mode = discovery_case.clone();
    let discovery_issuer = base.clone();
    let profile = Arc::new(Mutex::new(None::<serde_json::Value>));
    let authorize_profile = profile.clone();
    let authorize_case = id_token_case.clone();
    let token_issuer = base.clone();
    let codes = Arc::new(Mutex::new(HashMap::<
        String,
        (String, String, String, Option<serde_json::Value>),
    >::new()));
    let tokens = Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let authorize_codes = codes.clone();
    let authorize_email = email.clone();
    let token_codes = codes;
    let token_tokens = tokens.clone();
    let log = exchanges.clone();
    let token_handler = post(
        move |headers: HeaderMap,
              axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
              Form(form): Form<HashMap<String, String>>| {
            let codes = token_codes.clone();
            let tokens = token_tokens.clone();
            let exchanges = log.clone();
            let issuer = token_issuer.clone();
            async move {
                exchanges.lock().unwrap().push(serde_json::json!({"authorization":headers.get("authorization").and_then(|header|header.to_str().ok()),"form":form}));
                let authorization = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok());
                let authenticated = if uri.path() == "/token-jwt" {
                    authorization.is_none()
                        && !form.contains_key("client_secret")
                        && form.get("client_id").map(String::as_str) == Some("enterprise-client")
                        && form.get("client_assertion_type").map(String::as_str)
                            == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        && form.get("client_assertion").is_some_and(|assertion| {
                            verify_client_assertion(assertion, &format!("{issuer}/token-jwt"))
                        })
                } else {
                    authorization == Some("Basic ZW50ZXJwcmlzZS1jbGllbnQ6c3RvcmVkLXNlY3JldA==")
                        || (uri.path() == "/oauth/token"
                            && form.get("client_id").map(String::as_str)
                                == Some("enterprise-client")
                            && form.get("client_secret").map(String::as_str)
                                == Some("stored-secret"))
                };
                if !authenticated {
                    return failure();
                }
                let Some(code) = form.get("code") else {
                    return failure();
                };
                let Some((challenge, email, case, profile)) = codes.lock().unwrap().remove(code)
                else {
                    return failure();
                };
                let Some(verifier) = form.get("code_verifier") else {
                    return failure();
                };
                if base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes()))
                    != challenge
                {
                    return failure();
                }
                let profile=profile.unwrap_or_else(||serde_json::json!({"sub":"employee-subject","email":email,"email_verified":true,"name":"SSO employee"}));
                let token = uuid::Uuid::new_v4().to_string();
                _ = tokens
                    .lock()
                    .unwrap()
                    .insert(token.clone(), profile.clone());
                let mut output = serde_json::json!({"access_token":token,"token_type":"Bearer","expires_in":3600,"scope":"openid email"});
                if case != "none" {
                    output["id_token"] =
                        serde_json::json!(signed_id_token(&issuer, &email, &case, &profile));
                }
                Json(output).into_response()
            }
        },
    );
    let authorize_handler = get(move |Query(query): Query<HashMap<String, String>>| {
        let codes = authorize_codes.clone();
        let email = authorize_email.clone();
        let case = authorize_case.clone();
        let profile = authorize_profile.clone();
        async move {
            if query.get("client_id").map(String::as_str) != Some("enterprise-client")
                || query.get("code_challenge_method").map(String::as_str) != Some("S256")
            {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let Some(challenge) = query.get("code_challenge") else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(callback) = query.get("redirect_uri") else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let code = uuid::Uuid::new_v4().to_string();
            _ = codes.lock().unwrap().insert(
                code.clone(),
                (
                    challenge.clone(),
                    email.lock().unwrap().clone(),
                    case.lock().unwrap().clone(),
                    profile.lock().unwrap().clone(),
                ),
            );
            let mut location = url::Url::parse(callback).unwrap();
            _ = location
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", query.get("state").map_or("", String::as_str));
            (StatusCode::FOUND, [("location", location.to_string())]).into_response()
        }
    });
    let userinfo_handler = get(move |headers: HeaderMap| {
        let tokens = tokens.clone();
        async move {
            let token = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or("");
            let email = tokens.lock().unwrap().get(token).cloned();
            match email {
                Some(profile) => Json(profile).into_response(),
                None => StatusCode::UNAUTHORIZED.into_response(),
            }
        }
    });
    let app = Router::new()
        .route("/authorize", authorize_handler.clone())
        .route("/oauth/authorize", authorize_handler)
        .route("/token", token_handler.clone())
        .route("/oauth/token", token_handler.clone())
        .route("/token-jwt", token_handler)
        .route("/userinfo", userinfo_handler.clone())
        .route("/api/v4/user", userinfo_handler)
        .route(
            "/jwks",
            get(|| async {
                Json(
                    serde_json::from_str::<serde_json::Value>(include_str!(
                        "../fixtures/one-tap/jwks.json"
                    ))
                    .unwrap(),
                )
            }),
        );
    let app = app.route("/.well-known/openid-configuration",get(move || {
        let issuer = discovery_issuer.clone();
        let case = discovery_mode.lock().unwrap().clone();
        async move {
            let mut document = serde_json::json!({"issuer":issuer,"authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/jwks","userinfo_endpoint":"/userinfo","token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]});
            match case.as_str() {
                "missing" => {let _ = document.as_object_mut().unwrap().remove("jwks_uri");}
                "issuer" => document["issuer"] = serde_json::json!("https://wrong-issuer.example.test"),
                _ => {}
            }
            Json(document)
        }
    }));
    _ = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Peer {
        base,
        email,
        profile,
        id_token_case,
        discovery_case,
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

fn signed_id_token(issuer: &str, email: &str, case: &str, profile: &serde_json::Value) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = serde_json::json!({"iss":issuer,"aud":"enterprise-client","sub":"employee-subject","email":email,"email_verified":true,"name":"SSO employee","iat":now,"exp":now+3600});
    claims.as_object_mut().unwrap().extend(
        profile
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    match case {
        "issuer" => claims["iss"] = serde_json::json!("https://wrong-issuer.example.test"),
        "audience" => claims["aud"] = serde_json::json!("other-client"),
        "expired" => claims["exp"] = serde_json::json!(now - 3600),
        "authorized-party" => claims["azp"] = serde_json::json!("other-client"),
        "multi-audience" | "valid-multi-audience" => {
            claims["aud"] = serde_json::json!(["enterprise-client", "other-client"]);
            if case == "valid-multi-audience" {
                claims["azp"] = serde_json::json!("enterprise-client");
            }
        }
        "subject" => {
            let _ = claims.as_object_mut().unwrap().remove("sub");
        }
        "empty-subject" => claims["sub"] = serde_json::json!(""),
        "missing-exp" => {
            let _ = claims.as_object_mut().unwrap().remove("exp");
        }
        "missing-iat" => {
            let _ = claims.as_object_mut().unwrap().remove("iat");
        }
        "skewed-expiry" => claims["exp"] = serde_json::json!(now - 10),
        "userinfo-mismatch" => claims["sub"] = serde_json::json!("other-subject"),
        _ => {}
    }
    let private = if case == "signature" {
        include_bytes!("../fixtures/one-tap/wrong-private-key.pem").as_slice()
    } else {
        include_bytes!("../fixtures/one-tap/private-key.pem").as_slice()
    };
    let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"one-tap-local-rs256"});
    let encoded = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    };
    let input = format!("{}.{}", encoded(&header), encoded(&claims));
    let key = bergshamra::keys::loader::load_rsa_private_pem(private)
        .unwrap()
        .software_key()
        .unwrap()
        .unwrap();
    let algorithm = bergshamra::crypto::registry::AlgorithmRegistry::signature(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    )
    .unwrap();
    format!(
        "{input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(algorithm.sign(&key, input.as_bytes()).unwrap())
    )
}

fn verify_client_assertion(token: &str, audience: &str) -> bool {
    let verify = || -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Ok(false);
        }
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?,
        )?;
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?,
        )?;
        let now = chrono::Utc::now().timestamp() as f64;
        let iat = claims["iat"].as_f64().unwrap_or_default();
        if header["alg"] != "RS256"
            || header["typ"] != "JWT"
            || header["kid"] != "sso-key"
            || claims["iss"] != "enterprise-client"
            || claims["sub"] != "enterprise-client"
            || claims["aud"] != audience
            || iat > now + 2.0
            || iat < now - 5.0
            || claims["exp"].as_f64() != Some(iat + 120.0)
            || uuid::Uuid::parse_str(claims["jti"].as_str().unwrap_or_default()).is_err()
        {
            return Ok(false);
        }
        let key = bergshamra::keys::loader::load_x509_cert_pem(include_bytes!(
            "../compat/fixtures/salesforce-transport/leaf.pem"
        ))?;
        let signature = bergshamra::crypto::AlgorithmRegistry::signature(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        )?;
        let data = format!("{}.{}", parts[0], parts[1]);
        Ok(signature.verify(
            &key.software_key()?.ok_or("Missing verifier key")?,
            data.as_bytes(),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?,
        )?)
    };
    verify().unwrap_or(false)
}
