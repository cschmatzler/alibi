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
backend_tests!(oauth_client_discovery_resolves_in_order_and_never_treats_owned_rows_as_managed);
postgres_tests!(oauth_client_discovery_resolves_in_order_and_never_treats_owned_rows_as_managed);
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
