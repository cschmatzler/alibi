//! API-key handlers over real SQL adapters and native no-database records.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::plugins::api_key::{
    ApiKeyConfig, ApiKeyPlugin, ApiKeyVerificationInput, CreateKeyRequest, UpdateKeyRequest,
};
use better_auth::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use better_auth_core::endpoint::EndpointOptions;
use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod, UpdateApiKey};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const SECRET: &str = "native-apikey-172-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:43175";
backend_tests!(native_api_key_workflow);
postgres_tests!(native_api_key_workflow);

fn plugins<S: AuthSchema>(builder: AuthBuilder<S>) -> AuthBuilder<S> {
    builder.plugin(EmailPasswordPlugin::new()).plugin(
        ApiKeyPlugin::with_config(ApiKeyConfig {
            enable_metadata: true,
            ..Default::default()
        })
        .configuration(ApiKeyConfig {
            config_id: "billing".into(),
            enable_metadata: true,
            ..Default::default()
        }),
    )
}
fn request(path: &str, body: Option<Value>, cookie: &str) -> AuthRequest {
    let mut req = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(req.headers.insert("cookie".into(), cookie.into()));
    req.body = body.map(|body| serde_json::to_vec(&body).unwrap());
    req
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body)
        .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&response.body)}))
}
fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}
async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    trace: &mut Vec<Value>,
    path: &str,
    input: Option<Value>,
    cookie: &str,
    query: &[(&str, &str)],
) -> TestResult<AuthResponse> {
    let mut req = request(path, input, cookie);
    for (key, value) in query {
        drop(req.query.insert((*key).into(), (*value).into()));
    }
    let response = Box::pin(auth.handle_request(req)).await?;
    trace.push(json!({"path":path,"status":response.status,"body":String::from_utf8(response.body.clone())?,"cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>()}));
    Ok(response)
}
async fn native_api_key_workflow<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    let auth =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    workflow(
        &auth,
        std::any::type_name::<B>().rsplit("::").next().unwrap(),
    )
    .await?;
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(db.count("api_keys").await?, 0);
    B::close(connection).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_database_native_api_key_workflow() -> TestResult {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = plugins(AuthBuilder::without_database(config.clone()))
        .build()
        .await?;
    workflow(&auth, "without-database").await?;
    // A real generated, retained credential is lost on restart, even with its old cookie.
    let mut trace = Vec::new();
    let signup = call(
        &auth,
        &mut trace,
        "/sign-up/email",
        Some(
            json!({"name":"Retained","email":"retained172@fixture.test","password":"Password123!"}),
        ),
        "",
        &[],
    )
    .await?;
    let owner = body(&signup)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&signup);
    let created = call(
        &auth,
        &mut trace,
        "/api-key/create",
        Some(json!({"name":"Retained"})),
        &cookie,
        &[],
    )
    .await?;
    assert_eq!(created.status, 200, "{}", body(&created));
    let id = body(&created)["id"].as_str().unwrap().to_owned();
    let plain = body(&created)["key"].as_str().unwrap().to_owned();
    let retained = auth.store().get_api_key_by_id(&id).await?.unwrap();
    assert_eq!(
        auth.store()
            .get_api_key_by_hash(&retained.key_hash)
            .await?
            .unwrap()
            .id,
        id
    );
    let restarted = plugins(AuthBuilder::without_database(config))
        .build()
        .await?;
    assert!(restarted.store().get_api_key_by_id(&id).await?.is_none());
    assert!(
        restarted
            .store()
            .get_api_key_by_hash(&retained.key_hash)
            .await?
            .is_none()
    );
    assert!(
        restarted
            .store()
            .list_api_keys_by_reference(&owner)
            .await?
            .is_empty()
    );
    let verification = restarted
        .dispatch_endpoint(
            ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                key: plain,
                config_id: None,
                permissions: None,
            })?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert!(!verification.valid);
    let listing = call(&restarted, &mut trace, "/api-key/list", None, &cookie, &[]).await?;
    assert_eq!(
        listing.status,
        200,
        "cached identity may list empty native storage: {}",
        body(&listing)
    );
    assert_eq!(body(&listing)["total"], 0);
    // Guarded refill derives from the genuine shared snapshot. One refill funds three uses.
    let observed = auth
        .store()
        .update_api_key(
            &id,
            UpdateApiKey {
                remaining: Some(0.0),
                refill_amount: Some(3.0),
                refill_interval: Some(60_000.0),
                last_refill_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                rate_limit_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let store = Arc::clone(auth.store());
        let observed = observed.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .consume_api_key_usage_from_snapshot(&observed, false)
                .await
        }));
    }
    let mut counts = [0, 0];
    while let Some(result) = tasks.join_next().await {
        match result?? {
            ConsumeApiKeyResult::Allowed(row) => {
                counts[0] += 1;
                assert_eq!(row.id, id);
                assert_eq!(row.reference_id, owner);
            }
            ConsumeApiKeyResult::UsageExhausted => counts[1] += 1,
            ConsumeApiKeyResult::RateLimited { .. } => panic!("disabled rate limit"),
        }
    }
    assert_eq!(counts, [3, 5]);
    let exhausted = auth.store().get_api_key_by_id(&id).await?.unwrap();
    assert_eq!(exhausted.remaining, Some(0.0));
    assert_ne!(exhausted.last_refill_at, observed.last_refill_at);
    // The distinct combined public operation uses current counters under one lock.
    let _combined_start = auth
        .store()
        .update_api_key(
            &id,
            UpdateApiKey {
                remaining: Some(2.5),
                rate_limit_enabled: Some(true),
                rate_limit_time_window: Some(86_400_000.0),
                rate_limit_max: Some(1.5),
                request_count: Some(0.0),
                last_request: Some(None),
                ..Default::default()
            },
        )
        .await?;
    let mut combined_counts = [0, 0, 0];
    for _ in 0..4 {
        match auth.store().consume_api_key_usage(&id, true).await? {
            ConsumeApiKeyResult::Allowed(_) => combined_counts[0] += 1,
            ConsumeApiKeyResult::RateLimited { .. } => combined_counts[1] += 1,
            ConsumeApiKeyResult::UsageExhausted => combined_counts[2] += 1,
        }
    }
    assert_eq!(combined_counts, [2, 1, 1]);
    let combined = auth.store().get_api_key_by_id(&id).await?.unwrap();
    assert_eq!(combined.remaining, Some(-0.5));
    assert_eq!(combined.request_count, Some(2.0));
    assert_eq!(combined.reference_id, owner);
    if let Ok(dir) = std::env::var("APIKEY_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join("native-record-controls.json"),
            serde_json::to_vec_pretty(&json!({
                "retained":retained,"refillSnapshot":observed,"afterConcurrent":exhausted,
                "concurrentCounts":counts,"combinedCounts":combined_counts,"combined":combined,
                "restartVerification":serde_json::to_value(&verification.error)?,"restartListing":body(&listing)
            }))?,
        )?;
    }
    auth.store().delete_api_key(&id).await?;
    assert!(
        auth.store()
            .update_api_key(&id, UpdateApiKey::default())
            .await
            .is_err()
    );
    assert!(matches!(
        auth.store()
            .consume_api_key_usage_from_snapshot(&exhausted, true)
            .await?,
        ConsumeApiKeyResult::UsageExhausted
    ));
    assert!(auth.store().get_api_key_by_id(&id).await?.is_none());
    Ok(())
}
async fn workflow<S: AuthSchema>(auth: &BetterAuth<S>, backend: &str) -> TestResult {
    let mut trace = Vec::new();
    let signup = call(
        auth,
        &mut trace,
        "/sign-up/email",
        Some(json!({"name":"Owner","email":"apikey172@fixture.test","password":"Password123!"})),
        "",
        &[],
    )
    .await?;
    assert_eq!(signup.status, 200);
    let cookie = cookies(&signup);
    let owner = body(&signup)["user"]["id"].as_str().unwrap().to_owned();
    let other = call(
        auth,
        &mut trace,
        "/sign-up/email",
        Some(
            json!({"name":"Other","email":"foreignkey172@fixture.test","password":"Password456!"}),
        ),
        "",
        &[],
    )
    .await?;
    assert_eq!(other.status, 200);
    let foreign_cookie = cookies(&other);
    let created = call(
        auth,
        &mut trace,
        "/api-key/create",
        Some(json!({"name":"Original","metadata":{"purpose":"native"}})),
        &cookie,
        &[],
    )
    .await?;
    if let Ok(dir) = std::env::var("APIKEY_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{backend}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    assert_eq!(created.status, 200, "{}", body(&created));
    let id = body(&created)["id"].as_str().unwrap().to_owned();
    let before = auth.store().get_api_key_by_id(&id).await?.unwrap();
    assert_eq!(before.reference_id, owner);
    assert_eq!(before.config_id, "default");
    assert_eq!(before.metadata.as_deref(), Some("{\"purpose\":\"native\"}"));
    let billing = call(
        auth,
        &mut trace,
        "/api-key/create",
        Some(json!({"name":"Billing","configId":"billing"})),
        &cookie,
        &[],
    )
    .await?;
    assert_eq!(billing.status, 200);
    let billing_id = body(&billing)["id"].as_str().unwrap().to_owned();
    let foreign = call(
        auth,
        &mut trace,
        "/api-key/create",
        Some(json!({"name":"Foreign"})),
        &foreign_cookie,
        &[],
    )
    .await?;
    assert_eq!(foreign.status, 200);
    let foreign_id = body(&foreign)["id"].as_str().unwrap().to_owned();
    let foreign_before = auth.store().get_api_key_by_id(&foreign_id).await?.unwrap();
    for (path, input, query) in [
        ("/api-key/get", None, vec![("id", id.as_str())]),
        (
            "/api-key/update",
            Some(json!({"keyId":id,"name":"Stolen"})),
            vec![],
        ),
        ("/api-key/delete", Some(json!({"keyId":id})), vec![]),
    ] {
        let denied = call(auth, &mut trace, path, input, &foreign_cookie, &query).await?;
        assert_eq!(denied.status, 404, "{}", body(&denied));
    }
    assert_eq!(
        serde_json::to_value(auth.store().get_api_key_by_id(&id).await?)?,
        serde_json::to_value(Some(&before))?
    );
    let wrong_scope = call(
        auth,
        &mut trace,
        "/api-key/get",
        None,
        &cookie,
        &[("id", id.as_str()), ("configId", "billing")],
    )
    .await?;
    assert_eq!(wrong_scope.status, 404);
    let listing = call(
        auth,
        &mut trace,
        "/api-key/list",
        None,
        &cookie,
        &[("configId", "billing"), ("limit", "1"), ("offset", "0")],
    )
    .await?;
    assert_eq!(listing.status, 200);
    assert_eq!(body(&listing)["total"], 1);
    assert_eq!(body(&listing)["apiKeys"][0]["id"], billing_id);
    assert!(body(&listing)["apiKeys"][0].get("key").is_none());
    let renamed = call(
        auth,
        &mut trace,
        "/api-key/update",
        Some(json!({"keyId":id,"name":"Renamed"})),
        &cookie,
        &[],
    )
    .await?;
    assert_eq!(renamed.status, 200);
    assert_eq!(
        auth.store()
            .get_api_key_by_id(&id)
            .await?
            .unwrap()
            .name
            .as_deref(),
        Some("Renamed")
    );
    // Trusted updates can change quota; supplying another user never transfers
    // ownership. HTTP reads expose the resulting record without its secret.
    let update = UpdateKeyRequest {
        key_id: id.clone(),
        user_id: Some(owner.clone()),
        remaining: Some(5.0),
        ..Default::default()
    };
    let updated = auth
        .dispatch_endpoint(
            ApiKeyPlugin::update_endpoint(&update)?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert_eq!(updated.remaining, Some(5.0));
    assert_eq!(
        auth.store()
            .get_api_key_by_id(&id)
            .await?
            .unwrap()
            .remaining,
        Some(5.0)
    );
    let unchanged_key = serde_json::to_value(auth.store().get_api_key_by_id(&id).await?.unwrap())?;
    let forged = UpdateKeyRequest {
        user_id: Some(body(&other)["user"]["id"].as_str().unwrap().to_owned()),
        remaining: Some(999.0),
        name: Some("Foreign overwrite".into()),
        ..update
    };
    assert!(
        auth.dispatch_endpoint(
            ApiKeyPlugin::update_endpoint(&forged)?,
            EndpointOptions::default()
        )
        .await
        .is_err()
    );
    assert_eq!(
        serde_json::to_value(auth.store().get_api_key_by_id(&id).await?.unwrap())?,
        unchanged_key
    );
    let read = call(
        auth,
        &mut trace,
        "/api-key/get",
        None,
        &cookie,
        &[("id", &id)],
    )
    .await?;
    assert_eq!(read.status, 200);
    assert_eq!(body(&read)["id"], id);
    assert_eq!(body(&read)["remaining"], 5);
    assert!(body(&read).get("key").is_none());
    // Trusted endpoint exercises the actual plugin's permission, quota and rate consumers.
    let limited = auth
        .dispatch_endpoint(
            ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
                config_id: None,
                user_id: Some(owner.clone()),
                name: Some("Quota".into()),
                remaining: Some(3.0),
                rate_limit_time_window: Some(86_400_000.0),
                rate_limit_max: Some(1.0),
                permissions: Some(serde_json::from_value(json!({"files":["read"]}))?),
                ..Default::default()
            })?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let limited_id = limited.api_key.id.clone();
    let plain = limited.key.clone();
    let verify = |permissions| ApiKeyVerificationInput {
        key: plain.clone(),
        config_id: None,
        permissions,
    };
    let rejected = auth
        .dispatch_endpoint(
            ApiKeyPlugin::verify_endpoint(&verify(Some(serde_json::from_value(
                json!({"files":["write"]}),
            )?)))?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert!(!rejected.valid);
    assert_eq!(
        auth.store()
            .get_api_key_by_id(&limited_id)
            .await?
            .unwrap()
            .remaining,
        Some(3.0)
    );
    for expected in [true, false] {
        let result = auth
            .dispatch_endpoint(
                ApiKeyPlugin::verify_endpoint(&verify(None))?,
                EndpointOptions::default(),
            )
            .await?;
        trace
            .push(json!({"operation":"verifyApiKey","body":serde_json::to_value(result.value())?}));
        assert_eq!(result.decode()?.valid, expected);
    }
    let limited_row = auth.store().get_api_key_by_id(&limited_id).await?.unwrap();
    assert_eq!(limited_row.remaining, Some(1.0));
    assert_eq!(limited_row.request_count, Some(1.0));
    let invalid_update = auth
        .store()
        .update_api_key(
            &limited_id,
            UpdateApiKey {
                name: Some("Partial".into()),
                last_refill_at: Some(Some("invalid".into())),
                ..Default::default()
            },
        )
        .await;
    assert!(invalid_update.is_err());
    assert_eq!(
        serde_json::to_value(auth.store().get_api_key_by_id(&limited_id).await?)?,
        serde_json::to_value(Some(&limited_row))?
    );
    let expired = auth
        .store()
        .update_api_key(
            &limited_id,
            UpdateApiKey {
                expires_at: Some(Some((Utc::now() - Duration::minutes(1)).to_rfc3339())),
                ..Default::default()
            },
        )
        .await?;
    let cleaned = auth
        .dispatch_endpoint(
            ApiKeyPlugin::delete_all_expired_endpoint(),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert!(cleaned.success);
    assert!(cleaned.error.is_none());
    assert!(auth.store().get_api_key_by_id(&expired.id).await?.is_none());
    assert_eq!(
        serde_json::to_value(auth.store().get_api_key_by_id(&foreign_id).await?)?,
        serde_json::to_value(Some(&foreign_before))?
    );
    let foreign_after = auth.store().get_api_key_by_id(&foreign_id).await?;
    for key_id in [&id, &billing_id, &foreign_id] {
        let deleted=call(auth,&mut trace,"/api-key/delete",Some(json!({"keyId":key_id,"configId":if key_id==&billing_id {"billing"} else {"default"}})),if key_id==&foreign_id {&foreign_cookie} else {&cookie},&[]).await?;
        assert_eq!(deleted.status, 200);
        assert!(auth.store().get_api_key_by_id(key_id).await?.is_none());
    }
    if let Ok(dir) = std::env::var("APIKEY_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{backend}-workflow.json")),
            serde_json::to_vec_pretty(
                &json!({"trace":trace,"before":before,"limitedRow":limited_row,"foreignBefore":foreign_before,"foreignAfter":foreign_after}),
            )?,
        )?;
    }
    Ok(())
}
