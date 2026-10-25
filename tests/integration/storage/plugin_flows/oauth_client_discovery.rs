//! External registry provenance determines client lookup and fails closed on resolver loss.
use super::*;
use alibi::CallbackContext;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::{
    OAuthClientDiscovery, OAuthClientIdGenerator, OAuthProviderConfig, OAuthProviderPlugin,
    jwt::JwtPlugin,
};
use alibi::store::{CreateOAuthClient, OAuthClient};
use std::sync::atomic::{AtomicU8, Ordering};
backend_tests!(
    oauth_client_discovery_resolves_in_order_and_never_treats_owned_rows_as_managed,
    oauth_server_client_resolution_returns_raw_clients_and_uses_supplied_discoveries,
    oauth_trusted_client_cache_preserves_shared_authority_and_blocks_mutations
);
postgres_tests!(
    oauth_client_discovery_resolves_in_order_and_never_treats_owned_rows_as_managed,
    oauth_server_client_resolution_returns_raw_clients_and_uses_supplied_discoveries,
    oauth_trusted_client_cache_preserves_shared_authority_and_blocks_mutations
);
type Events = Arc<std::sync::Mutex<Vec<String>>>;
struct RegistryDiscovery<S: AuthSchema> {
    first: bool,
    state: Arc<AtomicU8>,
    events: Events,
    schema: std::marker::PhantomData<fn() -> S>,
}
impl<S: AuthSchema> std::fmt::Debug for RegistryDiscovery<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryDiscovery")
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> OAuthClientDiscovery for RegistryDiscovery<S> {
    fn id(&self) -> &str {
        if self.first {
            "registry-first"
        } else {
            "registry-live"
        }
    }
    fn matches(&self, id: &str) -> bool {
        self.events.lock().unwrap().push(
            if self.first {
                "first:matches"
            } else {
                "live:matches"
            }
            .into(),
        );
        id.starts_with("registry-") && (self.first || self.state.load(Ordering::SeqCst) != 2)
    }
    async fn resolve(
        &self,
        callback: &CallbackContext,
        id: &str,
        existing: Option<OAuthClient>,
    ) -> alibi::AuthResult<Option<OAuthClient>> {
        self.events.lock().unwrap().push(
            if self.first {
                "first:resolve"
            } else if existing.is_some() {
                "live:resolve:existing"
            } else {
                "live:resolve:new"
            }
            .into(),
        );
        if self.first || self.state.load(Ordering::SeqCst) == 1 {
            return Ok(None);
        }
        let ctx = callback
            .context::<S>()
            .ok_or_else(|| alibi::AuthError::internal("Missing real callback context"))?;
        if let Some(mut existing) = existing {
            if self.state.load(Ordering::SeqCst) == 3 {
                existing.metadata["client_name"] = json!("Updated registry");
                return ctx
                    .database
                    .update_oauth_client_metadata(id, existing.metadata, chrono::Utc::now())
                    .await;
            }
            return Ok(Some(existing));
        }
        ctx.database.create_oauth_client(CreateOAuthClient{client_id:id.into(),user_id:None,client_secret:None,metadata:json!({"client_discovery_id":"registry-live","client_name":"Registry client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none","scope":"email","grant_types":["authorization_code"],"response_types":["code"],"disabled":false}),created_at:chrono::Utc::now()}).await.map(Some)
    }
}
#[derive(Debug)]
struct ValidationDiscovery(String);
#[async_trait::async_trait]
impl OAuthClientDiscovery for ValidationDiscovery {
    fn id(&self) -> &str {
        &self.0
    }
    fn matches(&self, _: &str) -> bool {
        false
    }
    async fn resolve(
        &self,
        _: &CallbackContext,
        _: &str,
        _: Option<OAuthClient>,
    ) -> alibi::AuthResult<Option<OAuthClient>> {
        Ok(None)
    }
}
#[derive(Debug)]
struct ManagedRegistryId;
impl OAuthClientIdGenerator for ManagedRegistryId {
    fn generate(&self) -> alibi::AuthResult<String> {
        Ok("registry-managed".into())
    }
}
async fn read_public<S: AuthSchema>(
    auth: &Alibi<S>,
    cookie: &str,
    id: &str,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::get_oauth_client_public_endpoint(id)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookie.into())].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await;
    match result {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            response.to_response()
        }
    }
}
async fn oauth_client_discovery_resolves_in_order_and_never_treats_owned_rows_as_managed<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let events: Events = Arc::default();
    let state = Arc::new(AtomicU8::new(0));
    let discoveries: Vec<Arc<dyn OAuthClientDiscovery>> = [true, false]
        .into_iter()
        .map(|first| {
            Arc::new(RegistryDiscovery::<B::Schema> {
                first,
                state: state.clone(),
                events: events.clone(),
                schema: std::marker::PhantomData,
            }) as Arc<dyn OAuthClientDiscovery>
        })
        .collect();
    let cfg = OAuthProviderConfig {
        client_discoveries: discoveries,
        client_id_generator: Some(Arc::new(ManagedRegistryId)),
        ..Default::default()
    };
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(cfg))
        .build()
        .await?;
    let peer = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "registry-owner@example.test").await;
    let cookie = cookies(&owner);
    for (phase, mode, missing_owner, status, expected) in [
        (
            "new",
            0,
            false,
            200,
            vec![
                "first:matches",
                "first:resolve",
                "live:matches",
                "live:resolve:new",
            ],
        ),
        (
            "existing",
            0,
            false,
            200,
            vec!["live:matches", "live:resolve:existing"],
        ),
        (
            "reject",
            1,
            false,
            404,
            vec!["live:matches", "live:resolve:existing"],
        ),
        ("mismatch", 2, false, 404, vec!["live:matches"]),
        ("missing-owner", 0, true, 404, vec![]),
        (
            "restore",
            0,
            false,
            200,
            vec!["live:matches", "live:resolve:existing"],
        ),
        (
            "refresh",
            3,
            false,
            200,
            vec!["live:matches", "live:resolve:existing"],
        ),
    ] {
        state.store(mode, Ordering::SeqCst);
        events.lock().unwrap().clear();
        let before = db.table("oauthClient").await?;
        let response = read_public(
            if missing_owner { &peer } else { &auth },
            &cookie,
            "registry-client",
        )
        .await?;
        assert_eq!(response.status, status, "{phase}: {}", body(&response));
        assert_eq!(
            body(&response),
            if status == 200 {
                json!({"client_id":"registry-client","client_name":if phase=="refresh"{"Updated registry"}else{"Registry client"},"redirect_uris":[]})
            } else {
                json!({"error":"not_found","error_description":"client not found"})
            }
        );
        assert_eq!(*events.lock().unwrap(), expected, "{phase}");
        let row = auth
            .store()
            .get_oauth_client("registry-client")
            .await?
            .unwrap();
        assert_eq!(row.metadata["client_discovery_id"], "registry-live");
        assert_eq!(
            row.metadata["client_name"],
            if phase == "refresh" {
                "Updated registry"
            } else {
                "Registry client"
            }
        );
        if phase != "new" && phase != "refresh" {
            assert_eq!(db.table("oauthClient").await?, before, "{phase}");
        }
    }
    let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Managed client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    assert_eq!(body(&created)["client_id"], "registry-managed");
    events.lock().unwrap().clear();
    let managed = read_public(&auth, &cookie, "registry-managed").await?;
    assert_eq!(managed.status, 200);
    assert_eq!(
        body(&managed),
        json!({"client_id":"registry-managed","client_name":"Managed client","redirect_uris":[]})
    );
    assert!(events.lock().unwrap().is_empty());
    let empty = "OAuth Provider extension client discovery id cannot be empty";
    let duplicate = "OAuth Provider extensions register client discovery id \"same\" more than once. Extension contributions must be disjoint.";
    for (ids, expected) in [
        (vec![], None),
        (vec!["one", "two"], None),
        (vec![""], Some(empty)),
        (vec![" \t "], Some(empty)),
        (vec!["\u{feff}"], Some(empty)),
        (vec!["\u{85}"], None),
        (vec!["same", "same"], Some(duplicate)),
        (vec!["one", " one "], None),
    ] {
        let sources = ids
            .into_iter()
            .map(|id| Arc::new(ValidationDiscovery(id.into())) as Arc<dyn OAuthClientDiscovery>)
            .collect();
        let result = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_discoveries: sources,
                ..Default::default()
            }))
            .build()
            .await;
        match (result, expected) {
            (Ok(_), None) => {}
            (Err(alibi::AuthError::Config(actual)), Some(expected)) => assert_eq!(actual, expected),
            (Err(error), _) => panic!("unexpected configuration error: {error}"),
            (Ok(_), Some(expected)) => panic!("expected configuration error: {expected}"),
        }
    }
    B::close(connection).await
}

async fn oauth_server_client_resolution_returns_raw_clients_and_uses_supplied_discoveries<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let events: Events = Arc::default();
    let state = Arc::new(AtomicU8::new(0));
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        cached_trusted_clients: ["registry-client".into()].into(),
        client_discoveries: [true, false]
            .into_iter()
            .map(|first| {
                Arc::new(RegistryDiscovery::<B::Schema> {
                    first,
                    state: state.clone(),
                    events: events.clone(),
                    schema: std::marker::PhantomData,
                }) as Arc<dyn OAuthClientDiscovery>
            })
            .collect(),
        ..Default::default()
    });
    assert!(
        provider
            .get_client(auth.context(), "unknown-client")
            .await?
            .is_none()
    );
    assert_eq!(*events.lock().unwrap(), ["first:matches", "live:matches"]);
    let owner = signup(&auth, "server-client-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Server managed","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"client_secret_post"}))?,alibi::endpoint::EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    let id = client["client_id"].as_str().unwrap();
    events.lock().unwrap().clear();
    let stored = auth.store().get_oauth_client(id).await?.unwrap();
    let raw = provider.get_client(auth.context(), id).await?.unwrap();
    assert_eq!(raw.client_id, id);
    assert_eq!(raw.user_id, stored.user_id);
    assert_eq!(raw.client_secret, stored.client_secret);
    assert_ne!(
        raw.client_secret.as_deref(),
        client["client_secret"].as_str()
    );
    assert_eq!(raw.metadata["client_name"], "Server managed");
    assert!(events.lock().unwrap().is_empty());
    for (phase, mode, missing, found, expected) in [
        (
            "new",
            0,
            false,
            true,
            vec![
                "first:matches",
                "first:resolve",
                "live:matches",
                "live:resolve:new",
            ],
        ),
        (
            "existing",
            0,
            false,
            true,
            vec!["live:matches", "live:resolve:existing"],
        ),
        (
            "reject",
            1,
            false,
            false,
            vec!["live:matches", "live:resolve:existing"],
        ),
        ("mismatch", 2, false, false, vec!["live:matches"]),
        ("missing-owner", 0, true, false, vec![]),
        (
            "restore",
            0,
            false,
            true,
            vec!["live:matches", "live:resolve:existing"],
        ),
        (
            "refresh",
            3,
            false,
            true,
            vec!["live:matches", "live:resolve:existing"],
        ),
    ] {
        state.store(mode, Ordering::SeqCst);
        events.lock().unwrap().clear();
        let before = db
            .tables(&[
                "oauthClient",
                "oauthClientAssertion",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let raw = if missing {
            OAuthProviderPlugin::new()
                .get_client(auth.context(), "registry-client")
                .await?
        } else {
            provider
                .get_client(auth.context(), "registry-client")
                .await?
        };
        assert_eq!(raw.is_some(), found, "{phase}");
        assert_eq!(*events.lock().unwrap(), expected, "{phase}");
        if let Some(raw) = raw {
            assert_eq!(raw.client_id, "registry-client");
            assert_eq!(raw.metadata["client_discovery_id"], "registry-live");
            assert_eq!(
                raw.metadata["client_name"],
                if phase == "refresh" {
                    "Updated registry"
                } else {
                    "Registry client"
                }
            );
            assert!(raw.user_id.is_none());
        } else {
            assert_eq!(
                db.tables(&[
                    "oauthClient",
                    "oauthClientAssertion",
                    "oauthAccessToken",
                    "oauthRefreshToken"
                ])
                .await?,
                before,
                "{phase}"
            );
        }
    }
    B::close(connection).await
}

#[derive(Debug)]
struct TrustedClientId;
impl OAuthClientIdGenerator for TrustedClientId {
    fn generate(&self) -> alibi::AuthResult<String> {
        Ok("trusted-client".into())
    }
}
async fn oauth_trusted_client_cache_preserves_shared_authority_and_blocks_mutations<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = OAuthProviderConfig {
        cached_trusted_clients: ["trusted-client", "trusted-missing"]
            .map(str::to_owned)
            .into(),
        client_id_generator: Some(Arc::new(TrustedClientId)),
        ..Default::default()
    };
    let provider = OAuthProviderPlugin::with_config(config.clone());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let peer = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "trusted-owner@example.test").await;
    let other = signup(&auth, "trusted-other@example.test").await;
    let create=ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Original trusted","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"client_secret_post"}))?;
    let created = auth
        .dispatch_endpoint(
            create,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?
        .into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    assert_eq!(client["client_id"], "trusted-client");
    let first = provider
        .get_client(auth.context(), "trusted-client")
        .await?
        .unwrap();
    assert_eq!(first.metadata["client_name"], "Original trusted");
    let mut metadata = first.metadata.clone();
    metadata["client_name"] = json!("External update");
    let updated = auth
        .store()
        .update_oauth_client_metadata("trusted-client", metadata, chrono::Utc::now())
        .await?;
    assert!(updated.is_some());
    let mut returned = provider
        .get_client(auth.context(), "trusted-client")
        .await?
        .unwrap();
    assert_eq!(returned.metadata["client_name"], "Original trusted");
    returned.metadata["client_name"] = json!("changed return value");
    assert_eq!(
        provider
            .get_client(auth.context(), "trusted-client")
            .await?
            .unwrap()
            .metadata["client_name"],
        "Original trusted"
    );
    assert_eq!(
        OAuthProviderPlugin::with_config(config.clone())
            .get_client(auth.context(), "trusted-client")
            .await?
            .unwrap()
            .metadata["client_name"],
        "External update"
    );
    let before = db
        .tables(&[
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken",
            "verification",
        ])
        .await?;
    for cookie in [cookies(&owner), cookies(&other)] {
        for id in ["trusted-client", "trusted-missing"] {
            for operation in [
                "updateOAuthClient",
                "rotateClientSecret",
                "deleteOAuthClient",
            ] {
                let input = if operation == "updateOAuthClient" {
                    json!({"client_id":id,"update":{"client_name":"Forbidden"}})
                } else {
                    json!({"client_id":id})
                };
                let result = auth
                    .dispatch_endpoint(
                        ServerEndpoint::<Value>::new("oauth-provider", operation)
                            .with_body(&input)?,
                        EndpointOptions {
                            headers: Some(
                                [("cookie".into(), cookie.clone())].into_iter().collect(),
                            ),
                            ..Default::default()
                        },
                    )
                    .await;
                let response = match result {
                    Ok(output) => output.into_response()?,
                    Err(error) => {
                        let mut response = EndpointResponse::error(error.error);
                        if let Some(body) = error.body {
                            response = response.with_error_body(*body);
                        }
                        response.to_response()?
                    }
                };
                assert_eq!(
                    response.status,
                    400,
                    "{operation} {id}: {}",
                    body(&response)
                );
                assert_eq!(
                    body(&response),
                    json!({"error":"invalid_client","error_description":"trusted clients must be updated manually"})
                );
                assert_eq!(
                    db.tables(&[
                        "oauthClient",
                        "oauthAccessToken",
                        "oauthRefreshToken",
                        "verification"
                    ])
                    .await?,
                    before
                );
            }
        }
    }
    auth.store().delete_oauth_client("trusted-client").await?;
    assert!(
        auth.store()
            .get_oauth_client("trusted-client")
            .await?
            .is_none()
    );
    for instance in [&auth, &peer] {
        assert_eq!(
            provider
                .get_client(instance.context(), "trusted-client")
                .await?
                .unwrap()
                .metadata["client_name"],
            "Original trusted"
        );
        let result=instance.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","oauth2Introspect").with_body(&json!({"client_id":"trusted-client","client_secret":client["client_secret"],"token":"not-issued"}))?,EndpointOptions::default()).await?.into_response()?;
        assert_eq!(result.status, 200);
        assert_eq!(body(&result), json!({"active":false}));
    }
    assert!(
        OAuthProviderPlugin::with_config(config)
            .get_client(auth.context(), "trusted-client")
            .await?
            .is_none()
    );
    B::close(connection).await
}
