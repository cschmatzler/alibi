//! Application key generation, permission defaults and lookup own real credentials.
use super::*;
use alibi::plugins::api_key::*;
use alibi::{AuthError, AuthResult};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};

backend_tests!(application_api_key_callbacks_preserve_delivery_authority_and_failure_effects);
postgres_tests!(application_api_key_callbacks_preserve_delivery_authority_and_failure_effects);

#[derive(Default)]
struct ApplicationKeys {
    mode: Mutex<&'static str>,
    events: Mutex<Vec<&'static str>>,
    generations: AtomicUsize,
    lookups: AtomicUsize,
}
#[async_trait]
impl ApiKeyGenerator for ApplicationKeys {
    async fn generate_key(&self, options: &ApiKeyGenerationOptions<'_>) -> AuthResult<String> {
        self.events.lock().unwrap().push("generate");
        assert_eq!(options.length, 24.5);
        assert_eq!(options.prefix, Some("app_"));
        if *self.mode.lock().unwrap() == "generate-error" {
            return Err(AuthError::bad_request("generation veto"));
        }
        Ok(format!(
            "application-owned-secret-number-{}",
            self.generations.fetch_add(1, Ordering::SeqCst)
        ))
    }
}
#[async_trait]
impl ApiKeyDefaultPermissions for ApplicationKeys {
    async fn default_permissions(
        &self,
        reference: &str,
        context: &ApiKeyCallbackContext<'_>,
    ) -> AuthResult<ApiKeyPermissions> {
        self.events.lock().unwrap().push("permissions");
        assert!(!reference.is_empty());
        assert_eq!(context.configuration_id, "default");
        if let Some(request) = context.request {
            assert!(request.path.ends_with("/api-key/create"));
        } else {
            assert!(context.endpoint.is_some());
        }
        if *self.mode.lock().unwrap() == "permissions-error" {
            return Err(AuthError::bad_request("permissions veto"));
        }
        Ok([("reports".into(), vec!["read".into()])]
            .into_iter()
            .collect())
    }
}
impl ApiKeyGetter for ApplicationKeys {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>> {
        let Some(request) = context.request else {
            assert!(context.endpoint.is_some());
            return Ok(None);
        };
        let call = self.lookups.fetch_add(1, Ordering::SeqCst);
        if request
            .headers
            .get("x-getter-error")
            .is_some_and(|mode| mode == "matching" || call == 1)
        {
            return Err(AuthError::forbidden("application lookup veto"));
        }
        Ok(request.headers.get("x-application-key").cloned())
    }
}
async fn application_api_key_callbacks_preserve_delivery_authority_and_failure_effects<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let callbacks = Arc::new(ApplicationKeys::default());
    let auth = builder::<B>(&connection)
        .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
            key_length: 24.5,
            prefix: Some("app_".into()),
            enable_session_for_api_keys: true,
            custom_key_generator: Some(callbacks.clone()),
            custom_api_key_getter: Some(callbacks.clone()),
            default_permissions_callback: Some(callbacks.clone()),
            default_permissions: Some(
                [("ignored".into(), vec!["none".into()])]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "custom-key@example.test").await;
    let mut key = String::new();
    let mut key_id = String::new();
    for mode in ["generate-error", "permissions-error", "explicit", "default"] {
        *callbacks.mode.lock().unwrap() = mode;
        callbacks.events.lock().unwrap().clear();
        let original = db.table("api_keys").await?;
        let mut input = json!({"name":"Application key"});
        if mode == "explicit" {
            input["permissions"] = json!({"reports":["write"]});
        }
        let denied = mode.ends_with("error");
        let result = if mode == "explicit" {
            input["userId"] = body(&owner)["user"]["id"].clone();
            let created = Box::pin(auth.dispatch_endpoint(
                ApiKeyPlugin::create_endpoint(&serde_json::from_value::<CreateKeyRequest>(input)?)?,
                alibi::endpoint::EndpointOptions::default(),
            ))
            .await?
            .decode()?;
            AuthResponse::json(200, &created)?
        } else {
            call(
                &auth,
                request("/api-key/create", Some(input), &cookies(&owner)),
                if denied { 400 } else { 200 },
            )
            .await
        };
        assert_eq!(
            *callbacks.events.lock().unwrap(),
            if mode == "generate-error" {
                vec!["generate"]
            } else {
                vec!["generate", "permissions"]
            },
            "{}",
            String::from_utf8_lossy(&result.body)
        );
        if denied {
            assert_eq!(db.table("api_keys").await?, original);
        } else {
            key = body(&result)["key"].as_str().unwrap().to_owned();
            key_id = body(&result)["id"].as_str().unwrap().to_owned();
            assert!(key.starts_with("application-owned-secret-number-"));
            assert!(
                !key.starts_with("app_"),
                "generator owns the complete credential"
            );
            let stored = auth.store().get_api_key_by_id(&key_id).await?.unwrap();
            assert_ne!(stored.key_hash, key);
            assert_eq!(stored.reference_id, body(&owner)["user"]["id"]);
            assert_eq!(
                serde_json::from_str::<Value>(stored.permissions.as_deref().unwrap())?,
                json!({"reports":[if mode == "explicit" { "write" } else { "read" }]})
            );
        }
    }
    let sessions = db.table("sessions").await?;
    let before = db.table("api_keys").await?;
    let mut configured_header = request("/get-session", None, "");
    drop(
        configured_header
            .headers
            .insert("x-api-key".into(), key.clone()),
    );
    assert!(body(&call(&auth, configured_header, 200).await).is_null());
    assert_eq!(db.table("api_keys").await?, before);
    authenticated(&auth, &cookies(&owner), "custom-key@example.test").await;
    for (mode, status) in [("matching", 500), ("handling", 403)] {
        callbacks.lookups.store(0, Ordering::SeqCst);
        let mut req = request("/get-session", None, "");
        req.headers.extend([
            ("x-application-key".into(), key.clone()),
            ("x-getter-error".into(), mode.into()),
        ]);
        let response = call(&auth, req, status).await;
        if mode == "handling" {
            assert_eq!(body(&response)["message"], "application lookup veto");
        }
        assert_eq!(db.table("api_keys").await?, before);
    }
    let mut req = request("/get-session", None, "");
    drop(req.headers.insert("x-application-key".into(), key));
    let result = call(&auth, req, 200).await;
    assert_eq!(body(&result)["user"]["id"], body(&owner)["user"]["id"]);
    assert_eq!(
        auth.store()
            .get_api_key_by_id(&key_id)
            .await?
            .unwrap()
            .request_count,
        Some(1.0)
    );
    assert_eq!(db.table("sessions").await?, sessions);
    B::close(connection).await
}
