//! API key input validation, quota, rate limits, validator outcomes and
//! request-session substitution.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::api_key::*;
use alibi::plugins::{ApiKeyConfig, ApiKeyPlugin};
use alibi_core::{AuthError, AuthResult};

backend_tests!(api_key_input_matrix, api_key_session_outcomes);

#[derive(Default)]
struct Validator(Mutex<&'static str>);

#[async_trait::async_trait]
impl ApiKeyValidator for Validator {
    async fn validate(&self, _: &ApiKeyCallbackContext<'_>, _: &str) -> AuthResult<bool> {
        match *self.0.lock().unwrap() {
            "reject" => Ok(false),
            "fail" => Err(AuthError::internal("validator unavailable")),
            "deny" => Err(AuthError::forbidden("validator denied")),
            _ => Ok(true),
        }
    }
}

fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = alibi_core::HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

async fn api_key_input_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            enable_metadata: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = cookies(&signup(&auth, "keys@example.com").await);
    let bodies = [
        r#"{"name":"ok","prefix":"bad prefix!"}"#,
        r#"{"name":"ok","prefix":"p"}"#,
        r#"{"name":"x","expiresIn":-1}"#,
        r#"{"name":"x","expiresIn":1e999}"#,
        r#"{"name":"x","expiresIn":-1e999}"#,
        r#"{"name":"x","remaining":"many"}"#,
        r#"{"name":"x","remaining":-5}"#,
        r#"{"name":"x","metadata":"text"}"#,
        r#"{"name":"x","metadata":[1]}"#,
        r#"{"name":"x","permissions":{"files":"read"}}"#,
        r#"{"name":"x","refillAmount":5}"#,
        r#"{"name":"x","refillInterval":1000}"#,
        r#"{"name":5}"#,
        r#"{"name":true}"#,
        r#"{"name":null}"#,
        r#"{"name":{"nested":1}}"#,
        r#"{"name":"x","rateLimitMax":"ten"}"#,
        r#"{"name":"x","userId":"someone"}"#,
        r#"[]"#,
        r#"{"name":"valid","prefix":"app_","remaining":2,"metadata":{"team":"core"}}"#,
    ];
    for text in bodies {
        trace.response(
            text,
            &Box::pin(auth.handle_request(raw("/api-key/create", text, &owner))).await?,
        );
    }
    for query in [
        vec![("limit", "x")],
        vec![("limit", "-1")],
        vec![("offset", "NaN")],
        vec![("sortBy", "name"), ("sortDirection", "sideways")],
        vec![("sortBy", "metadata"), ("sortDirection", "desc"), ("limit", "1")],
        vec![("sortBy", "remaining"), ("sortDirection", "asc")],
    ] {
        let mut request = request("/api-key/list", None, &owner);
        request.set_query_pairs(query.iter().copied());
        trace.response(
            &format!("list {query:?}"),
            &Box::pin(auth.handle_request(request)).await?,
        );
    }
    trace.assert("api-key/input-matrix");
    B::close(connection).await
}

async fn api_key_session_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let validator = Arc::new(Validator::default());
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        enable_session_for_api_keys: true,
        custom_api_key_validator: Some(validator.clone()),
        ..Default::default()
    });
    let auth = builder::<B>(&connection).plugin(plugin).build().await?;
    let mut trace = Trace::default();
    let user_id = body(&signup(&auth, "session-keys@example.com").await)["user"]["id"].clone();
    let create = async |mut input: Value| {
        input["userId"] = user_id.clone();
        Box::pin(auth.dispatch_endpoint(
            ApiKeyPlugin::create_endpoint(&serde_json::from_value::<CreateKeyRequest>(input).unwrap())
                .unwrap(),
            alibi_core::endpoint::EndpointOptions::default(),
        ))
        .await
        .unwrap()
        .decode()
        .unwrap()
        .key
    };
    let session = async |key: &str| {
        let mut request = request("/get-session", None, "");
        _ = request.headers.insert("x-api-key".into(), key.into());
        Box::pin(auth.handle_request(request)).await.unwrap()
    };
    let limited = create(json!({
        "name": "limited",
        "remaining": 1,
        "rateLimitEnabled": true,
        "rateLimitTimeWindow": 60_000,
        "rateLimitMax": 5,
    }))
    .await;
    trace.response("first use", &session(&limited).await);
    trace.response("usage exceeded", &session(&limited).await);
    let throttled = create(json!({
        "name": "throttled",
        "rateLimitEnabled": true,
        "rateLimitTimeWindow": 60_000,
        "rateLimitMax": 1,
    }))
    .await;
    trace.response("within window", &session(&throttled).await);
    trace.response("rate limited", &session(&throttled).await);
    let plain = create(json!({"name": "plain"})).await;
    trace.response("unknown key", &session("not-a-real-key").await);
    for mode in ["reject", "fail", "deny"] {
        *validator.0.lock().unwrap() = mode;
        trace.response(mode, &session(&plain).await);
    }
    *validator.0.lock().unwrap() = "accept";
    let mut protected = request("/list-sessions", None, "");
    _ = protected.headers.insert("x-api-key".into(), plain.clone());
    trace.response("protected route", &Box::pin(auth.handle_request(protected)).await?);
    _ = db
        .execute(
            "UPDATE api_keys SET expires_at = $1",
            &[&(chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()],
        )
        .await;
    trace.response("expired", &session(&plain).await);
    trace.assert("api-key/session-outcomes");
    B::close(connection).await
}
