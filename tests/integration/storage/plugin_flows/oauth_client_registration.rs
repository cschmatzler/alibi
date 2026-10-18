//! Dynamic registration gates anonymous admission and persists real client credentials.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine;
use sha2::Digest;
#[path = "../../../fixtures/oauth/initial-access-token.rs"]
mod initial_access_token;
#[path = "../../../fixtures/oauth/metadata-document-owner.rs"]
mod metadata_document_owner;

const REGISTRATION_TABLES: &[&str] = &[
    "user",
    "account",
    "session",
    "verification",
    "jwks",
    "oauthClient",
];
backend_tests!(
    oauth_dynamic_registration_enforces_policy_and_persists_clients,
    oauth_registration_scope_capabilities_are_not_grants,
    oauth_registration_pkce_policy_controls_genuine_code_exchanges,
    oauth_registration_resources_persist_only_admitted_links,
    oauth_metadata_document_registration_owns_replacement
);
async fn oauth_metadata_document_registration_owns_replacement<B: Backend>(db: Db) -> TestResult {
    use alibi::plugins::oauth_provider::{
        OAuthClientMetadata, RegisterClientMetadataDocumentInput,
    };
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let resource = "https://api.fixture.test/cimd/a";
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        resources: vec![json!(resource)],
        client_registration_default_resources: Some(vec![resource.into()]),
        client_registration_default_scopes: Some(vec!["email".into()]),
        client_registration_allowed_scopes: Some(vec!["profile".into()]),
        client_discoveries: vec![Arc::new(metadata_document_owner::MetadataDocumentOwner)],
        custom_access_token_claims: Some(Arc::new(metadata_document_owner::MetadataDocumentClaims)),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let input = RegisterClientMetadataDocumentInput {
        metadata: serde_json::from_value::<OAuthClientMetadata>(
            json!({"client_id":"ignored", "redirect_uris":["https://app.fixture.test/callback"],"client_name":"Remote","unknown_root":"discarded","metadata":{"custom":{"version":1},"client_discovery_id":"opaque-not-owner","clientId":"forged","resources":["forged"],"metadata":{"nested":"reserved"}}}),
        )?,
        client_id: "https://client.fixture.test/metadata.json".into(),
        client_discovery_id: "trusted-document-owner".into(),
        existing_client: None,
    };
    let result = provider
        .register_client_metadata_document(input.clone(), auth.context())
        .await?;
    assert_eq!(
        result.client.metadata["client_discovery_id"],
        "trusted-document-owner"
    );
    assert_eq!(result.resources, vec![resource]);
    assert!(result.created);
    assert!(result.client_secret.is_none());
    assert!(result.client.client_secret.is_none());
    assert!(result.client.user_id.is_none());
    assert_eq!(result.client.metadata["scope"], "email profile");
    assert_eq!(result.client.metadata["custom"], json!({"version":1}));
    assert!(result.client.metadata.get("unknown_root").is_none());
    assert!(result.client.metadata.get("clientId").is_none());
    assert!(result.client.metadata.get("resources").is_none());
    let raw_metadata: Value = serde_json::from_str(
        &db.text(
            "SELECT metadata FROM \"oauthClient\" WHERE \"clientId\" = $1",
            &[&input.client_id],
        )
        .await?
        .unwrap(),
    )?;
    assert_eq!(
        raw_metadata,
        json!({"custom":{"version":1},"client_discovery_id":"opaque-not-owner"})
    );
    assert_eq!(
        db.text(
            "SELECT \"clientDiscoveryId\" FROM \"oauthClient\" WHERE \"clientId\" = $1",
            &[&input.client_id]
        )
        .await?
        .as_deref(),
        Some("trusted-document-owner")
    );
    let owner = Box::pin(signup(&auth, "cimd-claims@example.test")).await;
    let cookie = cookies(&owner);
    let mut managed_id = String::new();
    for source in ["managed-create", "managed-update", "document"] {
        let extensions = json!({"custom":{"version":if source == "managed-update" {2}else{1}},"client_discovery_id":"opaque-not-owner"});
        if source == "managed-create" {
            let created = Box::pin(auth.dispatch_endpoint(
                OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"email profile","token_endpoint_auth_method":"none","metadata":{"custom":{"version":1},"client_discovery_id":"opaque-not-owner","clientDiscoveryId":"forged","skip_consent":true}}))?,
                EndpointOptions { headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()), ..Default::default() },
            )).await?.into_response()?;
            assert_eq!(created.status, 201);
            assert_eq!(body(&created)["client_discovery_id"], "opaque-not-owner");
            managed_id = body(&created)["client_id"].as_str().unwrap().into();
        } else if source == "managed-update" {
            let updated = Box::pin(auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider","adminUpdateOAuthClient").with_body(&json!({"client_id":managed_id,"update":{"metadata":{"custom":{"version":2},"client_discovery_id":"opaque-not-owner","clientDiscoveryId":"forged","skip_consent":true}}}))?,
                EndpointOptions { headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()), ..Default::default() },
            )).await?.into_response()?;
            assert_eq!(updated.status, 200);
            assert_eq!(body(&updated)["client_discovery_id"], "opaque-not-owner");
        }
        let client_id = if source == "document" {
            &input.client_id
        } else {
            &managed_id
        };
        let raw_metadata: Value = serde_json::from_str(
            &db.text(
                "SELECT metadata FROM \"oauthClient\" WHERE \"clientId\" = $1",
                &[client_id],
            )
            .await?
            .unwrap(),
        )?;
        assert_eq!(raw_metadata, extensions, "{source}: physical opaque column");
        let expected_owner = (source == "document").then_some("trusted-document-owner");
        assert_eq!(
            db.text(
                "SELECT \"clientDiscoveryId\" FROM \"oauthClient\" WHERE \"clientId\" = $1",
                &[client_id]
            )
            .await?
            .as_deref(),
            expected_owner,
            "{source}: physical authority column"
        );
        let client = provider
            .get_client(auth.context(), client_id)
            .await?
            .expect("real lookup must not mistake opaque metadata for source ownership");
        assert_eq!(
            client
                .metadata
                .get("client_discovery_id")
                .and_then(Value::as_str),
            expected_owner
        );
        assert_eq!(client.metadata["scope"], "email profile");
        if source != "document" {
            let read = Box::pin(auth.dispatch_endpoint(
                OAuthProviderPlugin::get_oauth_client_endpoint(client_id)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await?
            .into_response()?;
            assert_eq!(read.status, 200);
            assert_eq!(body(&read)["client_discovery_id"], "opaque-not-owner");
            assert_eq!(body(&read)["custom"], extensions["custom"]);
        }
        let verifier = "cimd-verifier-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
        let authorized = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_authorize_endpoint(&json!({"client_id":client_id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":resource,"prompt":"consent","code_challenge":challenge,"code_challenge_method":"S256"}))?,
        EndpointOptions { headers: Some([("cookie".into(),cookie.clone()),("accept".into(),"application/json".into())].into_iter().collect()), request:Some(request("/oauth2/authorize",None,&cookie)), ..Default::default() },
    )).await?.into_response()?;
        let target = url::Url::parse(ORIGIN)?.join(body(&authorized)["url"].as_str().unwrap())?;
        assert_eq!(target.path(), "/consent");
        let consent = Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_consent_endpoint(true, None, target.query())?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                request: Some(request("/oauth2/consent", None, &cookie)),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        let callback = url::Url::parse(body(&consent)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let token = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"authorization_code","client_id":client_id,"redirect_uri":"https://app.fixture.test/callback","code":code,"code_verifier":verifier}))?,
        EndpointOptions::default(),
    )).await?.into_response()?;
        assert_eq!(token.status, 200);
        let verifier = JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                issuer: Some(format!("{ORIGIN}/api/auth")),
                audience: Some(alibi::plugins::jwt::JwtAudience::One(resource.into())),
                ..Default::default()
            },
            ..Default::default()
        });
        let claims = verifier
            .verify_jwt(
                body(&token)["access_token"].as_str().unwrap(),
                None,
                None,
                auth.context(),
            )
            .await?
            .unwrap();
        assert_eq!(
            claims["document_metadata"], extensions,
            "{source}: actual operator callback"
        );
        assert_eq!(claims["client_id"], *client_id);
        assert_eq!(claims["sub"], body(&owner)["user"]["id"]);
        assert_eq!(claims["scope"], "email");
    }
    for (extension, expected) in [
        (
            json!({"custom":{"version":2},"other":false,"client_secret":"forged"}),
            json!({"custom":{"version":2},"other":false}),
        ),
        (Value::Null, json!({"custom":{"version":2},"other":false})),
        (json!({}), json!({"custom":{"version":2},"other":false})),
        (
            json!({"clientId":"forged","resources":[],"metadata":{}}),
            json!({"custom":{"version":2},"other":false}),
        ),
        (
            json!({"final":[1,null,true]}),
            json!({"final":[1,null,true]}),
        ),
    ] {
        let mut replacement = input.clone();
        let mut wire = serde_json::to_value(&input.metadata)?;
        wire["metadata"] = extension;
        replacement.metadata = serde_json::from_value(wire)?;
        replacement.existing_client = auth.store().get_oauth_client(&input.client_id).await?;
        let replaced = provider
            .register_client_metadata_document(replacement, auth.context())
            .await?;
        for key in ["custom", "other", "final"] {
            assert_eq!(replaced.client.metadata.get(key), expected.get(key));
        }
        assert!(replaced.client.metadata.get("client_secret").is_none());
        assert!(replaced.client.metadata.get("metadata").is_none());
    }
    assert_eq!(
        result.client.metadata["client_credentials_scopes"],
        json!([])
    );
    assert!(result.client.metadata.get("application_type").is_none());
    let before = db.tables(&["oauthClient", "oauthClientResource"]).await?;
    for (patch, error, description) in [
        (
            json!({"backchannel_logout_session_required":false}),
            "invalid_client_metadata",
            "Client ID Metadata Documents cannot register a back-channel logout target",
        ),
        (
            json!({"backchannel_logout_uri":"https://logout.fixture.test/target"}),
            "invalid_client_metadata",
            "Client ID Metadata Documents cannot register a back-channel logout target",
        ),
        (
            json!({"token_endpoint_auth_method":"client_secret_basic"}),
            "invalid_client_metadata",
            "Client ID Metadata Document clients cannot use a shared secret",
        ),
        (
            json!({"require_pkce":false}),
            "invalid_client_metadata",
            "pkce is required for registered clients.",
        ),
        (
            json!({"scope":"openid"}),
            "invalid_scope",
            "cannot request scope openid",
        ),
        (
            json!({"grant_types":["future_grant"]}),
            "invalid_client_metadata",
            "no mutually supported grant_type among future_grant",
        ),
        (
            json!({"grant_types":[]}),
            "invalid_client_metadata",
            "grant_types must contain at least one grant type",
        ),
    ] {
        let mut rejected = input.clone();
        let mut metadata = serde_json::to_value(&rejected.metadata)?;
        metadata
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        rejected.metadata = serde_json::from_value(metadata)?;
        rejected.existing_client = Some(result.client.clone());
        let denied = provider
            .register_client_metadata_document(rejected, auth.context())
            .await
            .unwrap_err();
        assert!(alibi::endpoint::is_endpoint_api_error(&denied.error));
        assert_eq!(
            denied.body.unwrap().to_json_value()?,
            json!({"error":error,"error_description":description})
        );
        assert_eq!(
            db.tables(&["oauthClient", "oauthClientResource"]).await?,
            before
        );
    }
    let mut wrong = input.clone();
    wrong.existing_client = Some(result.client.clone());
    wrong.client_discovery_id = "other".into();
    let denied = provider
        .register_client_metadata_document(wrong, auth.context())
        .await
        .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client_id is already owned by a different registration source"})
    );
    let mut collision_other_owner = input.clone();
    collision_other_owner.client_discovery_id = "different-owner".into();
    let denied = provider
        .register_client_metadata_document(collision_other_owner, auth.context())
        .await
        .unwrap_err();
    assert!(
        !alibi::endpoint::is_endpoint_api_error(&denied.error),
        "a conflicting create without an owned snapshot preserves the underlying unique error"
    );
    assert_eq!(
        db.tables(&["oauthClient", "oauthClientResource"]).await?,
        before
    );
    // A stale create retries once against the same discovery owner after the real unique failure.
    let retried = provider
        .register_client_metadata_document(input.clone(), auth.context())
        .await?;
    assert!(!retried.created);
    assert_eq!(retried.client.id, result.client.id);
    let mut private_key = input.clone();
    private_key.existing_client = Some(result.client.clone());
    private_key.metadata.client_id = input.client_id.clone();
    private_key.metadata.metadata.token_endpoint_auth_method = Some("private_key_jwt".into());
    private_key.metadata.metadata.jwks_uri = Some("https://client.fixture.test/keys".into());
    let private_key = provider
        .register_client_metadata_document(private_key, auth.context())
        .await?;
    assert!(private_key.client_secret.is_none());
    assert!(private_key.client.client_secret.is_none());
    assert_eq!(
        private_key.client.metadata["token_endpoint_auth_method"],
        "private_key_jwt"
    );
    let mut controlled = result.client.clone();
    for (name, value) in [
        ("disabled", json!(true)),
        ("skip_consent", json!(true)),
        ("enable_end_session", json!(false)),
        ("client_credentials_scopes", json!(["operator-scope"])),
        ("application_type", json!("web")),
        ("dpop_bound_access_tokens", json!(true)),
    ] {
        controlled.metadata[name] = value;
    }
    let controlled = auth
        .store()
        .update_oauth_client_metadata(&input.client_id, controlled.metadata, chrono::Utc::now())
        .await?
        .unwrap();
    let mut replacement = input.clone();
    replacement.metadata = serde_json::from_value(
        json!({"client_id":input.client_id,"redirect_uris":["http://127.0.0.1/callback"],"grant_types":["authorization_code","future_grant"],"disabled":false,"skip_consent":false,"enable_end_session":true}),
    )?;
    replacement.existing_client = Some(controlled);
    let replaced = provider
        .register_client_metadata_document(replacement.clone(), auth.context())
        .await?;
    assert!(!replaced.created);
    assert_eq!(replaced.client.id, result.client.id);
    assert_eq!(replaced.client.created_at, result.client.created_at);
    for (name, value) in [
        ("client_name", json!("Remote")),
        ("disabled", json!(true)),
        ("skip_consent", json!(true)),
        ("enable_end_session", json!(false)),
        ("client_credentials_scopes", json!(["operator-scope"])),
        ("dpop_bound_access_tokens", json!(true)),
    ] {
        assert_eq!(replaced.client.metadata[name], value, "{name}");
    }
    assert!(
        replaced.client.metadata.get("application_type").is_none(),
        "only the explicit null application type clears the model column"
    );
    assert_eq!(
        auth.store()
            .list_oauth_client_resources(&input.client_id)
            .await?
            .len(),
        1
    );
    assert_eq!(db.count("oauthConsent").await?, 2);
    assert_eq!(db.count("oauthAccessToken").await?, 0);
    auth.store().delete_oauth_client(&input.client_id).await?;
    let denied = provider
        .register_client_metadata_document(replacement, auth.context())
        .await
        .unwrap_err();
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_client","error_description":"client no longer exists"})
    );
    Ok(())
}
async fn oauth_registration_resources_persist_only_admitted_links<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let a = "https://api.fixture.test/registration/a";
    let b = "https://api.fixture.test/registration/b";
    let c = "https://api.fixture.test/registration/c";
    let disabled = "https://api.fixture.test/registration/disabled";
    let resources = vec![
        json!(a),
        json!({"identifier":b,"allowedScopes":["email"],"accessTokenTtl":123}),
        json!(c),
        json!({"identifier":disabled,"disabled":true}),
        json!("relative"),
    ];
    let mut owner = None;
    for (mode, defaults, allowed) in [
        ("absent", None, None),
        ("empty-default", Some(vec![]), None),
        ("empty-allowed", None, Some(vec![])),
        ("empty", Some(vec![]), Some(vec![])),
        ("default", Some(vec![a, a]), Some(vec![])),
        ("allowed-only", None, Some(vec![b])),
        (
            "union",
            Some(vec![a, a]),
            Some(vec![b, a, b, disabled, "relative"]),
        ),
        ("disabled-default", Some(vec![disabled]), None),
        ("missing-default", Some(vec!["relative"]), None),
    ] {
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    resources: resources.clone(),
                    allow_dynamic_client_registration: true,
                    allow_unauthenticated_client_registration: true,
                    client_registration_default_resources: defaults
                        .clone()
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    client_registration_allowed_resources: allowed
                        .clone()
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        if owner.is_none() {
            owner = Some(cookies(
                &Box::pin(signup(&auth, "registration-resources@example.test")).await,
            ));
        }
        let cookie = owner.as_ref().unwrap();
        assert!(
            auth.store().get_oauth_resource(a).await?.is_some(),
            "real provider initialization owns resources"
        );
        for requested in [
            None,
            Some(vec![]),
            Some(vec![a]),
            Some(vec![b, b]),
            Some(vec![b, b, a]),
            Some(vec![c]),
            Some(vec![disabled]),
            Some(vec!["urn:fixture:unknown"]),
        ] {
            let mut input = json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":"none"});
            if let Some(requested) = &requested {
                input["resources"] = json!(requested);
            }
            let baseline = defaults.clone().unwrap_or_default();
            let admitted = baseline
                .iter()
                .chain(allowed.iter().flatten())
                .copied()
                .collect::<Vec<_>>();
            let denied = requested
                .iter()
                .flatten()
                .find(|id| !admitted.contains(id))
                .map(|id| format!("requested resource {id} is not allowed for client registration"))
                .or_else(|| {
                    baseline
                        .iter()
                        .chain(requested.iter().flatten())
                        .find_map(|id| {
                            if *id == disabled {
                                Some(format!("requested resource {id} is disabled"))
                            } else if *id == "relative" {
                                Some(format!("requested resource {id} does not exist"))
                            } else {
                                None
                            }
                        })
                });
            let before = db
                .tables(&[
                    "oauthClient",
                    "oauthClientResource",
                    "oauthConsent",
                    "oauthAccessToken",
                    "verification",
                ])
                .await?;
            let input = serde_json::from_value::<
                alibi::plugins::oauth_provider::RegisterOAuthClientInput,
            >(input)?;
            let output = Box::pin(auth.dispatch_endpoint(
                OAuthProviderPlugin::register_oauth_client_endpoint(&input)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                    ..Default::default()
                },
            ))
            .await;
            if let Some(description) = denied {
                let error = output.unwrap_err();
                assert_eq!(error.error.status_code(), 400, "{mode}:{requested:?}");
                assert_eq!(
                    error.body.unwrap().to_json_value()?,
                    json!({"error":"invalid_target","error_description":description})
                );
                assert_eq!(
                    db.tables(&[
                        "oauthClient",
                        "oauthClientResource",
                        "oauthConsent",
                        "oauthAccessToken",
                        "verification"
                    ])
                    .await?,
                    before
                );
                continue;
            }
            let output = output?.into_response()?;
            assert_eq!(output.status, 201);
            let value = body(&output);
            let mut expected = Vec::new();
            for id in baseline.iter().chain(requested.iter().flatten()) {
                if !expected.contains(id) {
                    expected.push(*id);
                }
            }
            assert_eq!(
                value.get("resources"),
                (!expected.is_empty()).then(|| json!(&expected)).as_ref(),
                "{mode}:{requested:?}"
            );
            let id = value["client_id"].as_str().unwrap();
            let row = auth.store().get_oauth_client(id).await?.unwrap();
            assert_eq!(row.metadata["client_credentials_scopes"], json!([]));
            assert!(
                row.metadata.get("resources").is_none(),
                "resources are relation rows, not client metadata"
            );
            let links = auth.store().list_oauth_client_resources(id).await?;
            let mut linked = links
                .iter()
                .map(|row| row.resource_id.as_str())
                .collect::<Vec<_>>();
            linked.sort_unstable();
            let mut sorted = expected.clone();
            sorted.sort_unstable();
            assert_eq!(linked, sorted);
            for link in &links {
                assert_eq!(link.client_id, id);
                assert_eq!(link.metadata, Value::Null);
                assert!(link.created_at.is_some());
            }
            assert_eq!(db.count("oauthConsent").await?, 0);
            assert_eq!(db.count("oauthAccessToken").await?, 0);
            // Exercise the capability through real authorize/consent/code/token endpoints once.
            if mode == "union" && requested == Some(vec![b, b, a]) {
                let verifier = "registration-resource-verifier-abcdefghijklmnopqrstuvwxyz";
                let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier));
                for (resource, unlink) in [(a, false), (b, false), (b, true), (c, false)] {
                    let before = db
                        .tables(&[
                            "oauthAccessToken",
                            "oauthRefreshToken",
                            "verification",
                            "oauthConsent",
                        ])
                        .await?;
                    let authorized=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_authorize_endpoint(&json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","resource":resource,"prompt":"consent","code_challenge":challenge,"code_challenge_method":"S256"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone()),("accept".into(),"application/json".into())].into_iter().collect()),request:Some(request("/oauth2/authorize",None,cookie)),..Default::default()})).await?.into_response()?;
                    let target = url::Url::parse(ORIGIN)?
                        .join(body(&authorized)["url"].as_str().unwrap())?;
                    if resource == c {
                        assert_eq!(
                            target.query_pairs().find(|(k, _)| k == "error").unwrap().1,
                            "invalid_target"
                        );
                        assert_eq!(
                            db.tables(&[
                                "oauthAccessToken",
                                "oauthRefreshToken",
                                "verification",
                                "oauthConsent"
                            ])
                            .await?,
                            before
                        );
                        continue;
                    }
                    assert_eq!(target.path(), "/consent");
                    let consent = Box::pin(auth.dispatch_endpoint(
                        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, target.query())?,
                        EndpointOptions {
                            headers: Some(
                                [("cookie".into(), cookie.clone())].into_iter().collect(),
                            ),
                            request: Some(request("/oauth2/consent", None, cookie)),
                            ..Default::default()
                        },
                    ))
                    .await?
                    .into_response()?;
                    let callback = url::Url::parse(body(&consent)["url"].as_str().unwrap())?;
                    let code = callback
                        .query_pairs()
                        .find(|(k, _)| k == "code")
                        .unwrap()
                        .1
                        .into_owned();
                    if unlink {
                        let removed = Box::pin(auth.dispatch_endpoint(
                            OAuthProviderPlugin::admin_unlink_client_resource_endpoint(
                                resource, id,
                            )?,
                            EndpointOptions {
                                headers: Some(
                                    [("cookie".into(), cookie.clone())].into_iter().collect(),
                                ),
                                ..Default::default()
                            },
                        ))
                        .await?
                        .into_response()?;
                        assert_eq!(removed.status, 200);
                        assert_eq!(
                            auth.store()
                                .list_oauth_client_resources(id)
                                .await?
                                .iter()
                                .map(|row| row.resource_id.as_str())
                                .collect::<Vec<_>>(),
                            vec![a]
                        );
                    }
                    let authority = db
                        .tables(&["oauthAccessToken", "oauthRefreshToken"])
                        .await?;
                    let output=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::oauth2_token_endpoint(&json!({"grant_type":"authorization_code","client_id":id,"redirect_uri":"https://app.fixture.test/callback","code":code,"code_verifier":verifier}))?,EndpointOptions::default())).await;
                    if unlink {
                        let error = output.unwrap_err();
                        assert_eq!(error.error.status_code(), 400);
                        assert_eq!(
                            error.body.unwrap().to_json_value()?,
                            json!({"error":"invalid_target","error_description":format!("client {id} is not linked to resource(s) {resource}")})
                        );
                        assert_eq!(
                            db.tables(&["oauthAccessToken", "oauthRefreshToken"])
                                .await?,
                            authority
                        );
                        continue;
                    }
                    let token = output?.into_response()?;
                    assert_eq!(token.status, 200);
                    let issued = body(&token);
                    assert_eq!(issued["scope"], "email");
                    if resource == b {
                        assert_eq!(issued["expires_in"], 123);
                    }
                    let claims = JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
                        claims: alibi::plugins::jwt::JwtClaimsConfig {
                            issuer: Some(format!(
                                "{}{}",
                                auth.config().base_url.trim_end_matches('/'),
                                auth.config().base_path
                            )),
                            audience: Some(alibi::plugins::jwt::JwtAudience::One(resource.into())),
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                    .verify_jwt(
                        issued["access_token"].as_str().unwrap(),
                        None,
                        None,
                        auth.context(),
                    )
                    .await?
                    .unwrap();
                    assert_eq!(claims["scope"], "email");
                    assert_eq!(claims["aud"], resource);
                }
            }
        }
        if mode == "union" {
            // Managed endpoint schema strips requested resources; only defaults are linked.
            for operation in ["createOAuthClient", "adminCreateOAuthClient"] {
                let created=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider",operation).with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","resources":[b,c],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()})).await?.into_response()?;
                assert_eq!(body(&created)["resources"], json!([a]));
                let id = body(&created)["client_id"].as_str().unwrap().to_owned();
                assert_eq!(
                    auth.store()
                        .list_oauth_client_resources(&id)
                        .await?
                        .iter()
                        .map(|row| row.resource_id.as_str())
                        .collect::<Vec<_>>(),
                    vec![a]
                );
            }
        }
    }
    // Admission success is not registration success: a genuine second-link write
    // failure must leave neither the client nor the first relation behind.
    for operation in [
        "createOAuthClient",
        "adminCreateOAuthClient",
        "registerOAuthClient",
    ] {
        let dynamic = operation == "registerOAuthClient";
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                resources: resources.clone(),
                allow_dynamic_client_registration: true,
                allow_unauthenticated_client_registration: true,
                client_registration_default_resources: Some(if dynamic {
                    vec![a.into()]
                } else {
                    vec![a.into(), b.into()]
                }),
                client_registration_allowed_resources: Some(vec![b.into()]),
                ..Default::default()
            }))
            .build()
            .await?;
        let input = json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","resources":[b,c],"client_name":"Atomic registration"});
        let mut input = input;
        if dynamic {
            input["resources"] = json!([b]);
        }
        let cookie = owner.as_ref().unwrap();
        let tables = [
            "oauthClient",
            "oauthClientResource",
            "oauthConsent",
            "oauthAccessToken",
            "oauthRefreshToken",
            "verification",
        ];
        let before = db.tables(&tables).await?;
        _ = db.execute(&format!("CREATE TRIGGER registration_managed_fault BEFORE INSERT ON \"oauthClientResource\" WHEN NEW.\"resourceId\"='{b}' BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM \"oauthClient\" WHERE \"clientId\"=NEW.\"clientId\") AND EXISTS(SELECT 1 FROM \"oauthClientResource\" WHERE \"clientId\"=NEW.\"clientId\" AND \"resourceId\"='{a}') THEN RAISE(ABORT,'real second registration relation failure') ELSE RAISE(ABORT,'registration write order changed') END; END"), &[]).await?;
        let error = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        assert!(
            !alibi::endpoint::is_endpoint_api_error(&error.error),
            "storage failures remain ordinary errors: {error:?}"
        );
        assert!(
            error
                .error
                .to_string()
                .contains("real second registration relation failure"),
            "{error:?}"
        );
        assert_eq!(
            db.tables(&tables).await?,
            before,
            "{operation} must roll back the row and first link without granting authority"
        );
        _ = db
            .execute("DROP TRIGGER registration_managed_fault", &[])
            .await?;
        let created = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&input)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 201);
        let value = body(&created);
        assert_eq!(value["resources"], json!([a, b]));
        let client = auth
            .store()
            .get_oauth_client(value["client_id"].as_str().unwrap())
            .await?
            .unwrap();
        assert!(client.metadata.get("client_discovery_id").is_none());
        assert!(client.user_id.is_some());
        assert_eq!(
            client.client_secret.as_deref(),
            Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(
                        value["client_secret"].as_str().unwrap()
                    ))
                    .as_str()
            )
        );
    }
    for (defaults, allowed, option, identifier) in [
        (Some(vec![c]), None, "clientRegistrationDefaultResources", c),
        (None, Some(vec![c]), "clientRegistrationAllowedResources", c),
        (
            Some(vec!["first"]),
            Some(vec!["second"]),
            "clientRegistrationDefaultResources",
            "first",
        ),
    ] {
        let result = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                resources: vec![json!(a)],
                client_registration_default_resources: defaults
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                client_registration_allowed_resources: allowed
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                ..Default::default()
            }))
            .build()
            .await;
        assert!(
            matches!(result,Err(alibi::AuthError::Config(message)) if message==format!("{option} resource {identifier} not found in resources"))
        );
    }
    Ok(())
}
async fn oauth_registration_pkce_policy_controls_genuine_code_exchanges<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut cookie = None;
    let verifier = "registration-pkce-verifier-abcdefghijklmnopqrstuvwxyz";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    for policy in [None, Some(true), Some(false)] {
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: true,
                    allow_unauthenticated_client_registration: true,
                    client_registration_require_pkce: policy,
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        if cookie.is_none() {
            cookie = Some(cookies(
                &Box::pin(signup(&auth, "registration-pkce@example.test")).await,
            ));
        }
        let cookie = cookie.as_ref().unwrap();
        for source in [
            "dynamic-confidential",
            "dynamic-public",
            "managed",
            "admin-true",
            "admin-false",
        ] {
            let explicit_values = if source.starts_with("dynamic") {
                vec![None, Some(true), Some(false)]
            } else {
                vec![Some(source == "admin-true")]
            };
            for explicit in explicit_values {
                let public = source == "dynamic-public";
                let optional = source == "admin-false"
                    || (source == "dynamic-confidential" && policy == Some(false));
                let mut input = json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":if public{"none"}else{"client_secret_basic"}});
                if let Some(explicit) = explicit {
                    input["require_pkce"] = json!(explicit);
                }
                let operation = if source.starts_with("dynamic") {
                    "registerOAuthClient"
                } else if source.starts_with("admin") {
                    "adminCreateOAuthClient"
                } else {
                    "createOAuthClient"
                };
                let created = Box::pin(auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", operation).with_body(&input)?,
                    EndpointOptions {
                        headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                        ..Default::default()
                    },
                ))
                .await?
                .into_response()?;
                assert_eq!(created.status, 201);
                let client = body(&created);
                let id = client["client_id"].as_str().unwrap();
                for (name, pkce, proof) in [
                    ("absent", json!({}), None),
                    ("unsolicited-verifier", json!({}), Some(verifier)),
                    ("empty", json!({"code_challenge":""}), None),
                    (
                        "empty-pair",
                        json!({"code_challenge":"","code_challenge_method":"S256"}),
                        None,
                    ),
                    (
                        "missing-method",
                        json!({"code_challenge":challenge}),
                        Some(verifier),
                    ),
                    (
                        "invalid-method",
                        json!({"code_challenge":challenge,"code_challenge_method":"plain"}),
                        Some(verifier),
                    ),
                    (
                        "malformed",
                        json!({"code_challenge":"short","code_challenge_method":"S256"}),
                        Some(verifier),
                    ),
                    (
                        "missing-verifier",
                        json!({"code_challenge":challenge,"code_challenge_method":"S256"}),
                        None,
                    ),
                    (
                        "wrong-verifier",
                        json!({"code_challenge":challenge,"code_challenge_method":"S256"}),
                        Some("wrong"),
                    ),
                    (
                        "valid",
                        json!({"code_challenge":challenge,"code_challenge_method":"S256"}),
                        Some(verifier),
                    ),
                ] {
                    if name == "missing-verifier" && !optional && !public {
                        continue;
                    }
                    let mut query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"email","prompt":"consent"});
                    query
                        .as_object_mut()
                        .unwrap()
                        .extend(pkce.as_object().unwrap().clone());
                    let authorized = Box::pin(
                        auth.dispatch_endpoint(
                            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize")
                                .with_query(&query)?,
                            EndpointOptions {
                                headers: Some(
                                    [
                                        ("cookie".into(), cookie.clone()),
                                        ("accept".into(), "application/json".into()),
                                    ]
                                    .into_iter()
                                    .collect(),
                                ),
                                request: Some(request("/oauth2/authorize", None, cookie)),
                                ..Default::default()
                            },
                        ),
                    )
                    .await?
                    .into_response()?;
                    let target = url::Url::parse(ORIGIN)?
                        .join(body(&authorized)["url"].as_str().unwrap())?;
                    let admitted = matches!(
                        name,
                        "valid" | "malformed" | "missing-verifier" | "wrong-verifier"
                    ) || (optional
                        && matches!(name, "absent" | "empty" | "unsolicited-verifier"));
                    if !admitted {
                        assert_eq!(
                            target
                                .query_pairs()
                                .find(|(k, _)| k == "error")
                                .map(|(_, v)| v.into_owned()),
                            Some("invalid_request".into()),
                            "{policy:?}:{source}:{explicit:?}:{name}"
                        );
                        assert!(!target.query_pairs().any(|(k, _)| k == "code"));
                        continue;
                    }
                    assert_eq!(
                        target.path(),
                        "/consent",
                        "{policy:?}:{source}:{explicit:?}:{name}: {target}"
                    );
                    let consent = Box::pin(auth.dispatch_endpoint(
                        OAuthProviderPlugin::oauth2_consent_endpoint(true, None, target.query())?,
                        EndpointOptions {
                            headers: Some(
                                [("cookie".into(), cookie.clone())].into_iter().collect(),
                            ),
                            request: Some(request("/oauth2/consent", None, cookie)),
                            ..Default::default()
                        },
                    ))
                    .await?
                    .into_response()?;
                    let callback = url::Url::parse(body(&consent)["url"].as_str().unwrap())?;
                    let code = callback
                        .query_pairs()
                        .find(|(k, _)| k == "code")
                        .unwrap()
                        .1
                        .into_owned();
                    let mut token_body = json!({"grant_type":"authorization_code","client_id":id,"redirect_uri":"https://app.fixture.test/callback","code":code});
                    if let Some(proof) = proof {
                        token_body["code_verifier"] = json!(proof);
                    }
                    let mut physical = request("/oauth2/token", None, "");
                    if !public {
                        _ = physical.headers.insert(
                            "authorization".into(),
                            format!(
                                "Basic {}",
                                base64::engine::general_purpose::STANDARD.encode(format!(
                                    "{id}:{}",
                                    client["client_secret"].as_str().unwrap()
                                ))
                            ),
                        );
                    }
                    _ = physical.headers.insert(
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    );
                    physical.body = Some(
                        url::form_urlencoded::Serializer::new(String::new())
                            .extend_pairs(
                                token_body
                                    .as_object()
                                    .unwrap()
                                    .iter()
                                    .map(|(k, v)| (k.as_str(), v.as_str().unwrap())),
                            )
                            .finish()
                            .into_bytes(),
                    );
                    let output = Box::pin(
                        auth.dispatch_endpoint(
                            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token")
                                .with_body(&token_body)?,
                            EndpointOptions {
                                headers: Some(physical.headers.clone()),
                                request: Some(physical),
                                ..Default::default()
                            },
                        ),
                    )
                    .await;
                    let success = matches!(name, "valid" | "absent" | "empty");
                    if success {
                        let token = output?.into_response()?;
                        assert_eq!(token.status, 200);
                        assert_eq!(body(&token)["scope"], "email");
                        assert_eq!(body(&token)["token_type"], "Bearer");
                        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                            sha2::Sha256::digest(body(&token)["access_token"].as_str().unwrap()),
                        );
                        let stored = auth
                            .store()
                            .get_oauth_token(alibi::store::OAuthTokenKind::Access, &hash)
                            .await?
                            .unwrap();
                        assert_eq!(stored.client_id, id);
                    } else {
                        let error = output.unwrap_err();
                        assert_eq!(
                            error.error.status_code(),
                            if public && name == "missing-verifier" {
                                400
                            } else {
                                401
                            },
                            "{policy:?}:{source}:{name}"
                        );
                        assert_eq!(
                            error
                                .body
                                .as_ref()
                                .unwrap()
                                .get("error")
                                .and_then(alibi::utils::json::JsValue::as_str),
                            Some("invalid_request")
                        );
                    }
                }
                let row = auth.store().get_oauth_client(id).await?.unwrap();
                let expected = if source.starts_with("admin") {
                    Some(json!(source == "admin-true"))
                } else {
                    optional.then(|| json!(false))
                };
                assert_eq!(row.metadata.get("require_pkce"), expected.as_ref());
                let updated=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","updateOAuthClient").with_body(&json!({"client_id":id,"update":{"client_name":"Updated","require_pkce":!optional}}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()})).await?.into_response()?;
                assert_eq!(updated.status, 200);
                assert_eq!(
                    auth.store()
                        .get_oauth_client(id)
                        .await?
                        .unwrap()
                        .metadata
                        .get("require_pkce"),
                    expected.as_ref()
                );
            }
        }
    }
    Ok(())
}
async fn oauth_registration_scope_capabilities_are_not_grants<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (defaults, allowed, invalid) in [
        (Some(vec!["unknown"]), None, "unknown"),
        (None, Some(vec!["unknown"]), "unknown"),
        (Some(vec![""]), None, ""),
        (
            Some(vec![" email"]),
            Some(vec!["first-invalid"]),
            "first-invalid",
        ),
    ] {
        let result = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_registration_default_scopes: defaults
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                client_registration_allowed_scopes: allowed
                    .map(|v| v.into_iter().map(str::to_owned).collect()),
                ..Default::default()
            }))
            .build()
            .await;
        assert!(
            matches!(result, Err(alibi::AuthError::Config(message)) if message == format!("clientRegistrationAllowedScope {invalid} not found in scopes"))
        );
    }
    let mut owner = None;
    for (mode, defaults, allowed, expected) in [
        (
            "fallback",
            None,
            None,
            "openid profile email offline_access",
        ),
        (
            "allowed-empty",
            None,
            Some(vec![]),
            "openid profile email offline_access",
        ),
        ("custom-provider", None, None, "email profile openid"),
        ("empty", Some(vec![]), None, ""),
        ("both-empty", Some(vec![]), Some(vec![]), ""),
        (
            "allowed-only",
            Some(vec![]),
            Some(vec!["profile"]),
            "profile",
        ),
        ("default-only", Some(vec!["email"]), None, "email"),
        (
            "union",
            Some(vec!["email", "email"]),
            Some(vec!["profile", "email", "profile"]),
            "email profile",
        ),
        (
            "allowed-fallback",
            None,
            Some(vec!["email"]),
            "openid profile email offline_access",
        ),
    ] {
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: true,
                    allow_unauthenticated_client_registration: true,
                    scopes: if mode == "custom-provider" {
                        ["email", "profile", "openid", "email", ""]
                            .map(str::to_owned)
                            .into()
                    } else {
                        OAuthProviderConfig::default().scopes
                    },
                    client_registration_default_scopes: defaults
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    client_registration_allowed_scopes: allowed
                        .map(|v| v.into_iter().map(str::to_owned).collect()),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        if owner.is_none() {
            owner = Some(Box::pin(signup(&auth, "registration-scopes@example.test")).await);
        }
        let cookie = cookies(owner.as_ref().unwrap());
        for requested in [
            None,
            Some(""),
            Some(" "),
            Some("email"),
            Some("profile"),
            Some("openid"),
            Some("forbidden"),
        ] {
            let mut input = json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"});
            if let Some(scope) = requested {
                input["scope"] = json!(scope);
            }
            let before = db.tables(REGISTRATION_TABLES).await?;
            let output = auth
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                        .with_body(&input)?,
                    EndpointOptions {
                        headers: Some(Default::default()),
                        ..Default::default()
                    },
                )
                .await;
            if requested.is_some_and(|scope| {
                !scope.trim().is_empty() && !expected.split(' ').any(|allowed| allowed == scope)
            }) {
                let error = output.unwrap_err();
                assert_eq!(error.error.status_code(), 400, "{mode}:{requested:?}");
                assert_eq!(
                    error.body.as_deref(),
                    Some(&alibi::utils::json::JsValue::from(
                        json!({"error":"invalid_scope","error_description":format!("cannot request scope {}",requested.unwrap())})
                    ))
                );
                assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
                continue;
            }
            let output = output?.into_response()?;
            assert_eq!(output.status, 201);
            let value = body(&output);
            assert_eq!(value["scope"], expected, "{mode}:{requested:?}");
            let id = value["client_id"].as_str().unwrap();
            let row = auth.store().get_oauth_client(id).await?.unwrap();
            assert_eq!(row.metadata["scope"], expected);
            assert_eq!(db.count("oauthConsent").await?, 0);
            assert_eq!(db.count("oauthAccessToken").await?, 0);
            if mode == "union" && requested == Some("email") {
                // A later request can use the additional capability, but registration granted nothing.
                for (scope, path) in [("profile", "/consent"), ("openid", "/callback")] {
                    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":scope,"code_challenge":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","code_challenge_method":"S256"});
                    let response = auth
                        .dispatch_endpoint(
                            ServerEndpoint::<Value>::new("oauth-provider", "oauth2Authorize")
                                .with_query(&query)?,
                            EndpointOptions {
                                headers: Some(
                                    [
                                        ("cookie".into(), cookie.clone()),
                                        ("accept".into(), "application/json".into()),
                                    ]
                                    .into_iter()
                                    .collect(),
                                ),
                                request: Some(request("/oauth2/authorize", None, "")),
                                ..Default::default()
                            },
                        )
                        .await?
                        .into_response()?;
                    let destination =
                        url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
                    assert_eq!(destination.path(), path);
                    assert_eq!(
                        destination
                            .query_pairs()
                            .find(|(key, _)| key == "error")
                            .map(|(_, v)| v.into_owned()),
                        (scope == "openid").then(|| "invalid_scope".into())
                    );
                }
            }
        }
        // Managed creation and owner updates use provider scopes, not DCR capability policy.
        let managed = auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"openid"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie.clone())].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(body(&managed)["scope"], "openid");
        let id = body(&managed)["client_id"].as_str().unwrap().to_owned();
        for patch in [
            json!({"client_name":"Scopes unchanged"}),
            json!({"scope":""}),
            json!({"scope":"profile"}),
        ] {
            let updated = auth
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "updateOAuthClient")
                        .with_body(&json!({"client_id":id,"update":patch}))?,
                    EndpointOptions {
                        headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                        ..Default::default()
                    },
                )
                .await?
                .into_response()?;
            assert_eq!(
                body(&updated)["scope"],
                patch
                    .get("scope")
                    .cloned()
                    .unwrap_or_else(|| json!("openid"))
            );
        }
    }
    Ok(())
}
async fn oauth_dynamic_registration_enforces_policy_and_persists_clients<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = std::sync::Arc::new(initial_access_token::RegistrationPolicy::default());
    let mut auths = Vec::new();
    for mode in 0..5 {
        auths.push(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(JwtPlugin::new())
                .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                    allow_dynamic_client_registration: mode != 0,
                    allow_unauthenticated_client_registration: matches!(mode, 2 | 4),
                    initial_access_token_validator: (mode >= 3).then(|| {
                        policy.clone()
                            as std::sync::Arc<dyn alibi::plugins::OAuthInitialAccessTokenValidator>
                    }),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
    }
    let owner = signup(&auths[0], "oauth-registration-owner@example.test").await;
    let before = db.tables(REGISTRATION_TABLES).await?;
    for (mode, input, cookie, status) in [
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"client_name":" \u{feff} "}),
            String::new(),
            400,
        ),
        (
            0,
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            403,
        ),
        (
            1,
            json!({"redirect_uris":["https://app.fixture.test/callback"]}),
            String::new(),
            401,
        ),
        (
            2,
            json!({"grant_types":["client_credentials"]}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"scope":"forbidden"}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"skip_consent":true}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"subject_type":"pairwise"}),
            String::new(),
            400,
        ),
        (
            2,
            json!({"redirect_uris":["https://app.fixture.test/callback"],"resources":42}),
            String::new(),
            400,
        ),
        (1, json!({"client_name":42}), cookies(&owner), 400),
    ] {
        let e = auths[mode]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some([("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.error.status_code(), status);
        assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
    }
    for mode in [2, 1] {
        for (authorization, status, error, description) in [
            (
                "bEaReR unconfigured",
                401,
                "invalid_token",
                "Invalid initial access token",
            ),
            (
                "Bearer",
                400,
                "invalid_request",
                "Malformed initial access token Authorization header",
            ),
            (
                "Bearer first second",
                400,
                "invalid_request",
                "Malformed initial access token Authorization header",
            ),
        ] {
            let denied = auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("authorization".into(),authorization.into())].into_iter().collect()),..Default::default()}).await.unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            assert_eq!(
                denied.body.as_deref(),
                Some(&alibi::utils::json::JsValue::from(
                    json!({"error":error,"error_description":description})
                ))
            );
            let headers = denied.headers.as_ref().unwrap();
            assert_eq!(
                headers.get("www-authenticate"),
                Some(&format!("Bearer error=\"{error}\""))
            );
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(headers.get("pragma").map(String::as_str), Some("no-cache"));
            assert!(!headers.contains_key("set-cookie"));
            assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
        }
    }
    for (mode, public, cookie) in [(1, false, cookies(&owner)), (2, true, String::new())] {
        let start = chrono::Utc::now().timestamp();
        let output=auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"client_name":if public{"\u{85}"}else{"Owned dynamic client"},"redirect_uris":["https://app.fixture.test/callback"],"scope":"email","token_endpoint_auth_method":if public{"none"}else{"client_secret_basic"},"user_id":"forged","client_id":"forged"}))?,EndpointOptions{headers:Some([("cookie".into(),cookie),("authorization".into(),if public{"Basic ignored"}else{"Bearer unconfigured"}.into())].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(output.status, 201);
        assert_eq!(
            output.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        let value = body(&output);
        assert_eq!(
            value["client_name"],
            if public {
                "\u{85}"
            } else {
                "Owned dynamic client"
            }
        );
        assert_eq!(value["scope"], "openid profile email offline_access");
        assert!(value["client_id_issued_at"].as_i64().unwrap() >= start);
        assert!(value["client_id_issued_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp());
        let id = value["client_id"].as_str().unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|c| c.is_ascii_alphabetic()));
        let row = auths[mode].store().get_oauth_client(id).await?.unwrap();
        assert_eq!(row.metadata["scope"], value["scope"]);
        if public {
            assert!(value.get("user_id").is_none());
            assert!(value.get("client_secret").is_none());
            assert!(row.user_id.is_none());
            assert!(row.client_secret.is_none());
        } else {
            let secret = value["client_secret"].as_str().unwrap();
            assert_eq!(secret.len(), 32);
            assert!(secret.bytes().all(|c| c.is_ascii_alphabetic()));
            let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(sha2::Sha256::digest(secret.as_bytes()));
            assert_eq!(row.client_secret.as_deref(), Some(hash.as_str()));
            assert_eq!(value["user_id"], body(&owner)["user"]["id"]);
            assert_eq!(row.user_id.as_deref(), body(&owner)["user"]["id"].as_str());
        }
    }
    assert_eq!(db.count("oauthClient").await?, 2);
    let token_body = json!({
        "client_name":"Token client", "redirect_uris":[" https://app.fixture.test/callback "],
        "grant_types":[" client_credentials "], "token_endpoint_auth_method":" client_secret_basic ",
        "subject_type":"public", "resources":[], "user_id":"forged", "reference_id":"forged", "client_id":"forged",
    });
    let parsed_metadata = json!({
        "client_name":"Token client", "redirect_uris":["https://app.fixture.test/callback"],
        "grant_types":["client_credentials"], "token_endpoint_auth_method":"client_secret_basic",
        "subject_type":"public", "resources":[],
    });
    let before = db.tables(REGISTRATION_TABLES).await?;
    for mode in [3, 4] {
        for (authorization, status, expected_body, invoked) in [
            (
                "Bearer rejected",
                401,
                Some(
                    json!({"error":"invalid_token","error_description":"Invalid initial access token"}),
                ),
                true,
            ),
            (
                "Bearer",
                400,
                Some(
                    json!({"error":"invalid_request","error_description":"Malformed initial access token Authorization header"}),
                ),
                false,
            ),
            (
                "Bearer first second",
                400,
                Some(
                    json!({"error":"invalid_request","error_description":"Malformed initial access token Authorization header"}),
                ),
                false,
            ),
            (
                "Bearer ordinary-error",
                500,
                Some(
                    json!({"error":"server_error","error_description":"Initial access token validation failed"}),
                ),
                true,
            ),
            (
                "Bearer api-error",
                429,
                Some(
                    json!({"error":"slow_down","error_description":"Operator registration limit"}),
                ),
                true,
            ),
            ("Bearer forbidden", 403, None, true),
            ("Bearer api-empty", 307, None, true),
        ] {
            let calls_before = policy.calls.lock().unwrap().len();
            let denied = auths[mode]
                .dispatch_endpoint(
                    ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                        .with_body(&token_body)?,
                    EndpointOptions {
                        headers: Some(
                            [
                                ("authorization".into(), authorization.into()),
                                ("x-registration-caller".into(), "fixture".into()),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(denied.error.status_code(), status);
            let expected_body = expected_body.map(alibi::utils::json::JsValue::from);
            assert_eq!(denied.body.as_deref(), expected_body.as_ref());
            assert_eq!(denied.body_absent, status == 307);
            if status == 403 {
                assert_eq!(
                    denied.error.error_payload().2,
                    "Operator forbids registration"
                );
            }
            let headers = denied.headers.as_ref().unwrap();
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-store")
            );
            assert_eq!(headers.get("pragma").map(String::as_str), Some("no-cache"));
            assert!(!headers.contains_key("set-cookie"));
            if matches!(status, 400 | 401) {
                assert_eq!(
                    headers.get("www-authenticate"),
                    Some(&format!(
                        "Bearer error=\"{}\"",
                        if status == 400 {
                            "invalid_request"
                        } else {
                            "invalid_token"
                        }
                    ))
                );
            } else {
                assert!(!headers.contains_key("www-authenticate"));
            }
            if status == 429 {
                assert_eq!(headers.get("retry-after").map(String::as_str), Some("17"));
                assert_eq!(
                    headers.get("x-registration-policy").map(String::as_str),
                    Some("limited")
                );
            }
            if status == 307 {
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert_eq!(
                    headers.get("location").map(String::as_str),
                    Some("https://operator.fixture.test/register")
                );
            }
            {
                let calls = policy.calls.lock().unwrap();
                assert_eq!(calls.len(), calls_before + usize::from(invoked));
                if invoked {
                    assert_eq!(
                        calls.last().unwrap(),
                        &json!({"token":authorization.strip_prefix("Bearer ").unwrap(),"authorization":authorization,"caller":"fixture","clientMetadata":parsed_metadata})
                    );
                }
            }
            assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
        }
    }
    // Validation and missing/non-Bearer authentication still precede admission and never call policy.
    for (input, authorization, expected) in [
        (json!({"client_name":42}), Some("Bearer accepted"), 400),
        (token_body.clone(), None, 401),
        (token_body.clone(), Some("Basic ignored"), 401),
    ] {
        let count = policy.calls.lock().unwrap().len();
        let denied = auths[3]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: Some(
                        authorization
                            .map(|header| ("authorization".into(), header.into()))
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), expected);
        assert_eq!(policy.calls.lock().unwrap().len(), count);
        assert_eq!(db.tables(REGISTRATION_TABLES).await?, before);
    }
    for (mode, token, reference) in [
        (3, "accepted", None),
        (4, "reference", Some("registration-reference")),
    ] {
        let authorization = format!("bEaReR {token}");
        let count = policy.calls.lock().unwrap().len();
        let output = auths[mode]
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "registerOAuthClient")
                    .with_body(&token_body)?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("authorization".into(), authorization.clone()),
                            ("x-registration-caller".into(), "fixture".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(output.status, 201);
        assert_eq!(policy.calls.lock().unwrap().len(), count + 1);
        assert_eq!(
            policy.calls.lock().unwrap().last().unwrap(),
            &json!({"token":token,"authorization":authorization,"caller":"fixture","clientMetadata":parsed_metadata})
        );
        let value = body(&output);
        assert!(value.get("user_id").is_none());
        assert_eq!(value.get("reference_id").and_then(Value::as_str), reference);
        let row = auths[mode]
            .store()
            .get_oauth_client(value["client_id"].as_str().unwrap())
            .await?
            .unwrap();
        assert!(row.user_id.is_none());
        assert_eq!(
            row.metadata.get("reference_id").and_then(Value::as_str),
            reference
        );
        let hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(
            value["client_secret"].as_str().unwrap(),
        ));
        assert_eq!(row.client_secret.as_deref(), Some(hash.as_str()));
        let credential_headers = [(
            "authorization".into(),
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!(
                    "{}:{}",
                    value["client_id"].as_str().unwrap(),
                    value["client_secret"].as_str().unwrap()
                ))
            ),
        )]
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
        let mut request =
            alibi::AuthRequest::new(HttpMethod::Post, "/api/auth/fixture/authenticate-client");
        request.headers = credential_headers.clone();
        let call = EndpointCall::new(
            &EndpointDefinition {
                name: "registrationCredentials",
                operation_id: "registrationCredentials",
                path: Some("/fixture/authenticate-client".into()),
                method: HttpMethod::Post,
            },
            Some(alibi::utils::json::JsValue::from(
                json!({"client_id":value["client_id"]}),
            )),
            None,
            EndpointOptions {
                headers: Some(credential_headers),
                request: Some(request),
                ..Default::default()
            },
        );
        let authenticated = OAuthProviderPlugin::new()
            .authenticate_client(
                auths[mode].context(),
                &call,
                Some("client_credentials"),
                &Default::default(),
            )
            .await?;
        assert_eq!(authenticated.client_id, row.client_id);
        assert_eq!(
            authenticated
                .client
                .metadata
                .get("reference_id")
                .and_then(Value::as_str),
            reference
        );
    }
    // A real cookie bypasses even an erroring Bearer policy; open registration keeps its fallback.
    for (mode, authorization, cookie) in [
        (3, "Bearer ordinary-error", cookies(&owner)),
        (4, "Basic ignored", String::new()),
    ] {
        let count = policy.calls.lock().unwrap().len();
        let output=auths[mode].dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","registerOAuthClient").with_body(&json!({"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"none"}))?,EndpointOptions{headers:Some([("authorization".into(),authorization.into()),("cookie".into(),cookie)].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(output.status, 201);
        let value = body(&output);
        let owner_body = body(&owner);
        assert_eq!(
            value.get("user_id"),
            (mode == 3).then_some(&owner_body["user"]["id"])
        );
        assert!(value.get("reference_id").is_none());
        assert_eq!(policy.calls.lock().unwrap().len(), count);
    }
    assert_eq!(db.count("oauthClient").await?, 6);
    Ok(())
}
