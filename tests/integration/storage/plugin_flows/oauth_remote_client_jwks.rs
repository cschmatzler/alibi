//! A discovered client's remote public keys authenticate real assertions and rotate on key misses.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::oauth::{
    OAuthClientAssertionContext, OAuthPrivateKeyJwtOptions, OAuthTokenGrant,
};
use alibi::plugins::{
    OAuthClientDiscovery, OAuthClientMetadataFetchOptions, OAuthClientMetadataFetchResponse,
    OAuthClientMetadataResourceFetch, OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin,
};
use alibi::store::{CreateOAuthClient, OAuthClient};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
backend_tests!(
    oauth_remote_client_jwks_caches_across_instances_and_refetches_only_for_key_misses,
    oauth_remote_client_jwks_validates_responses_and_uris_without_consuming_rejected_proofs
);
postgres_tests!(
    oauth_remote_client_jwks_caches_across_instances_and_refetches_only_for_key_misses,
    oauth_remote_client_jwks_validates_responses_and_uris_without_consuming_rejected_proofs
);
#[path = "../../../fixtures/oauth/remote-jwks-response.rs"]
mod remote_response;
const CLIENT: &str = "https://client.fixture.test/client.json";
const URI: &str = "https://client.fixture.test/jwks";
#[derive(Debug)]
struct Resource {
    mode: std::sync::Mutex<String>,
    uri: std::sync::Mutex<String>,
    document: std::sync::Mutex<Value>,
    fetches: std::sync::Mutex<Vec<Value>>,
}
#[async_trait::async_trait]
impl OAuthClientMetadataResourceFetch for Resource {
    async fn fetch(
        &self,
        url: &str,
        options: OAuthClientMetadataFetchOptions,
    ) -> alibi::AuthResult<OAuthClientMetadataFetchResponse> {
        self.fetches.lock().unwrap().push(json!({"url":url,"accept":options.headers.get("accept"),"redirect":options.redirect,"aborted":options.signal.aborted()}));
        let mode = self.mode.lock().unwrap().clone();
        if mode == "exception" {
            return Err(alibi::AuthError::internal("offline"));
        }
        let (status, headers, bytes) =
            remote_response::response(&mode, &self.document.lock().unwrap());
        let mut response = http::Response::builder().status(status);
        for (key, value) in headers {
            response = response.header(key, value);
        }
        let response = response.body(bytes).unwrap();
        Ok(OAuthClientMetadataFetchResponse {
            response: response.into(),
            redirected: false,
        })
    }
}
struct Registry<S: AuthSchema> {
    resource: Arc<Resource>,
    schema: std::marker::PhantomData<fn() -> S>,
}
impl<S: AuthSchema> std::fmt::Debug for Registry<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteRegistry")
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> OAuthClientDiscovery for Registry<S> {
    fn id(&self) -> &str {
        "remote-registry"
    }
    fn matches(&self, id: &str) -> bool {
        id == CLIENT
    }
    fn metadata_resource_fetch(&self) -> Option<Arc<dyn OAuthClientMetadataResourceFetch>> {
        if *self.resource.mode.lock().unwrap() == "no-transport" {
            None
        } else {
            Some(self.resource.clone())
        }
    }
    async fn resolve(
        &self,
        callback: &alibi::CallbackContext,
        id: &str,
        existing: Option<OAuthClient>,
    ) -> alibi::AuthResult<Option<OAuthClient>> {
        let mut client = if let Some(existing) = existing {
            existing
        } else {
            callback.context::<S>().unwrap().database.create_oauth_client(CreateOAuthClient{client_id:id.into(),client_secret:None,user_id:None,metadata:json!({"client_discovery_id":"remote-registry","client_name":"Remote client","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":URI,"scope":"email","grant_types":["authorization_code"],"response_types":["code"]}),created_at:chrono::Utc::now()}).await?
        };
        client.metadata["jwks_uri"] = json!(*self.resource.uri.lock().unwrap());
        Ok(Some(client))
    }
}
async fn proof<S: AuthSchema>(
    auth: &Alibi<S>,
    key: &Value,
    algorithm: &str,
    kid: &str,
) -> TestResult<String> {
    Ok(OAuthPrivateKeyJwtOptions {
        private_key_jwk: Some(key["privateJwk"].clone()),
        algorithm: Some(algorithm.into()),
        kid: Some(kid.into()),
        expires_in: Some(90.0),
        ..Default::default()
    }
    .into_assertion()?
    .0
    .get_client_assertion(OAuthClientAssertionContext {
        client_id: CLIENT.into(),
        token_endpoint: format!(
            "{}{}/oauth2/introspect",
            auth.config().base_url,
            auth.config().base_path
        ),
        grant_type: OAuthTokenGrant::AuthorizationCode,
    })
    .await?)
}
async fn inspect<S: AuthSchema>(
    auth: &Alibi<S>,
    assertion: &str,
) -> alibi::AuthResult<AuthResponse> {
    let input = json!({"token":"not-issued","client_assertion":assertion,"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"});
    let result = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&input)?,
        EndpointOptions {
            request: Some(request("/oauth2/introspect", Some(input), "")),
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
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
async fn oauth_remote_client_jwks_caches_across_instances_and_refetches_only_for_key_misses<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    let rsa = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "RSA")
        .unwrap();
    let ec = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "P-256")
        .unwrap();
    let document = |key: &Value, algorithm: &str, kid: &str| {
        let mut public = key["publicJwk"].clone();
        public["alg"] = json!(algorithm);
        public["kid"] = json!(kid);
        json!({"keys":[public]})
    };
    let resource = Arc::new(Resource {
        mode: std::sync::Mutex::new("valid".into()),
        uri: std::sync::Mutex::new(URI.into()),
        document: std::sync::Mutex::new(document(rsa, "RS256", "first")),
        fetches: std::sync::Mutex::default(),
    });
    let registry = Arc::new(Registry::<B::Schema> {
        resource: resource.clone(),
        schema: std::marker::PhantomData,
    });
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        client_discoveries: vec![registry],
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let peer = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider)
        .build()
        .await?;
    for (instance, phase) in [
        (&auth, "initial"),
        (&auth, "cached"),
        (&peer, "cached-peer"),
    ] {
        let response = inspect(instance, &proof(instance, rsa, "RS256", "first").await?).await?;
        assert_eq!(response.status, 200, "{phase}: {}", body(&response));
        assert_eq!(body(&response), json!({"active":false}));
        assert_eq!(resource.fetches.lock().unwrap().len(), 1, "{phase}");
    }
    *resource.document.lock().unwrap() = document(ec, "ES256", "second");
    let response = inspect(&auth, &proof(&auth, ec, "ES256", "second").await?).await?;
    assert_eq!(response.status, 200);
    assert_eq!(body(&response), json!({"active":false}));
    assert_eq!(resource.fetches.lock().unwrap().len(), 2);
    let assertion = proof(&auth, ec, "ES256", "second").await?;
    let (message, signature) = assertion.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature)?;
    bytes[0] ^= 1;
    let invalid = format!("{message}.{}", URL_SAFE_NO_PAD.encode(bytes));
    let before = db
        .tables(&[
            "oauthClientAssertion",
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken",
        ])
        .await?;
    let denied = inspect(&auth, &invalid).await?;
    assert_eq!(denied.status, 401);
    assert_eq!(
        body(&denied),
        json!({"error":"invalid_client","error_description":"client assertion signature verification failed"})
    );
    assert_eq!(resource.fetches.lock().unwrap().len(), 2);
    assert_eq!(
        db.tables(&[
            "oauthClientAssertion",
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken"
        ])
        .await?,
        before
    );
    let repaired = inspect(&peer, &assertion).await?;
    assert_eq!(repaired.status, 200);
    assert_eq!(body(&repaired), json!({"active":false}));
    assert_eq!(resource.fetches.lock().unwrap().len(), 2);
    assert_eq!(
        *resource.fetches.lock().unwrap(),
        vec![json!({"url":URI,"accept":"application/json","redirect":"error","aborted":false}); 2]
    );
    B::close(connection).await
}

async fn oauth_remote_client_jwks_validates_responses_and_uris_without_consuming_rejected_proofs<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oauth/client-assertion-keys.json"
    )))?;
    let rsa = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["family"] == "RSA")
        .unwrap();
    let mut public = rsa["publicJwk"].clone();
    public["alg"] = json!("RS256");
    public["kid"] = json!("first");
    let resource = Arc::new(Resource {
        mode: std::sync::Mutex::new("valid".into()),
        uri: std::sync::Mutex::new(URI.into()),
        document: std::sync::Mutex::new(json!({"keys":[public]})),
        fetches: std::sync::Mutex::default(),
    });
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        client_discoveries: vec![Arc::new(Registry::<B::Schema> {
            resource: resource.clone(),
            schema: std::marker::PhantomData,
        })],
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider)
        .build()
        .await?;
    assert_eq!(
        inspect(&auth, &proof(&auth, rsa, "RS256", "first").await?)
            .await?
            .status,
        200
    );
    let cases = [
        ("status", 400, 1, "failed to fetch client JWKS"),
        ("redirect", 400, 1, "failed to fetch client JWKS"),
        ("type", 400, 1, "failed to fetch client JWKS"),
        ("no-type", 400, 1, "failed to fetch client JWKS"),
        ("length", 400, 1, "failed to fetch client JWKS"),
        ("hex-length", 400, 1, "failed to fetch client JWKS"),
        ("invalid-length", 200, 1, ""),
        ("exact-body", 200, 1, ""),
        ("over-body", 400, 1, "failed to fetch client JWKS"),
        ("bad-json", 400, 1, "failed to fetch client JWKS"),
        ("empty-keys", 400, 1, "failed to fetch client JWKS"),
        ("symmetric", 400, 1, "failed to fetch client JWKS"),
        ("private-key", 400, 1, "failed to fetch client JWKS"),
        ("exception", 400, 1, "failed to fetch client JWKS"),
        ("bom", 200, 1, ""),
        ("nonfinite", 200, 1, ""),
        ("bad-utf8", 200, 1, ""),
        (
            "wrong-kid",
            401,
            2,
            "client assertion signature verification failed",
        ),
        (
            "ambiguous",
            401,
            1,
            "client assertion signature verification failed",
        ),
        (
            "no-transport",
            400,
            0,
            "client discovery does not provide a metadata resource transport",
        ),
        ("protocol", 400, 0, "jwks_uri must use HTTPS"),
        (
            "credentials",
            400,
            0,
            "jwks_uri must not contain credentials",
        ),
        (
            "fragment",
            400,
            0,
            "jwks_uri must not include a fragment component",
        ),
        (
            "private-host",
            400,
            0,
            "jwks_uri must not point to a private or reserved address",
        ),
        ("untrusted", 400, 0, "client jwks_uri is not trusted"),
        ("no-uri", 400, 0, "client has no JWKS configured"),
    ];
    for (name, status, fetches, description) in cases {
        let uri = match name {
            "protocol" => format!("http://client.fixture.test/jwks?case={name}"),
            "credentials" => format!("https://user:pass@client.fixture.test/jwks?case={name}"),
            "fragment" => format!("{URI}?case={name}#fragment"),
            "private-host" => "https://10.0.0.1/jwks".into(),
            "untrusted" => "https://other.fixture.test/jwks".into(),
            "no-uri" => String::new(),
            _ => format!("{URI}?case={name}"),
        };
        *resource.mode.lock().unwrap() = name.into();
        *resource.uri.lock().unwrap() = uri;
        resource.fetches.lock().unwrap().clear();
        let assertion = proof(&auth, rsa, "RS256", "first").await?;
        let before = db
            .tables(&[
                "oauthClientAssertion",
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        let response = inspect(&auth, &assertion).await?;
        assert_eq!(response.status, status, "{name}: {}", body(&response));
        assert_eq!(resource.fetches.lock().unwrap().len(), fetches, "{name}");
        if status == 200 {
            assert_eq!(body(&response), json!({"active":false}), "{name}");
        } else {
            assert_eq!(
                body(&response),
                json!({"error":"invalid_client","error_description":description}),
                "{name}"
            );
            assert_eq!(
                db.tables(&[
                    "oauthClientAssertion",
                    "oauthClient",
                    "oauthAccessToken",
                    "oauthRefreshToken"
                ])
                .await?,
                before,
                "{name}"
            );
            *resource.mode.lock().unwrap() = "valid".into();
            *resource.uri.lock().unwrap() = format!("{URI}?repaired={name}");
            let repaired = inspect(&auth, &assertion).await?;
            assert_eq!(repaired.status, 200, "{name} retry: {}", body(&repaired));
            assert_eq!(body(&repaired), json!({"active":false}));
            assert_eq!(
                resource.fetches.lock().unwrap().len(),
                fetches + 1,
                "{name} retry"
            );
        }
    }
    B::close(connection).await
}
