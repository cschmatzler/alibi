//! Discovery describes the actual configured issuer and admission policy without storage writes.
use super::*;
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
backend_tests!(
    oauth_server_discovery_tracks_configured_policy_without_writes,
    oauth_discovery_advertises_registry_support_and_merges_contributions
);
postgres_tests!(oauth_discovery_advertises_registry_support_and_merges_contributions);
async fn oauth_server_discovery_tracks_configured_policy_without_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for mode in ["default", "oauth", "disabled", "configured"] {
        let mut provider = OAuthProviderConfig::default();
        let mut jwt = JwtPluginConfig::default();
        if mode == "oauth" || mode == "configured" {
            provider.scopes = vec!["read".into()];
        }
        if mode == "disabled" {
            provider.disable_jwt_plugin = true;
        }
        if mode == "configured" {
            provider.advertised_scopes = Some(vec!["read".into()]);
            provider.grant_types = vec!["client_credentials".into()];
            provider.allow_dynamic_client_registration = true;
            provider.allow_unauthenticated_client_registration = true;
            jwt.claims.issuer = Some("http://issuer.fixture.test/tenant?discard=1#discard".into());
            jwt.jwks_path = "/keys".into();
            jwt.remote_url = Some("https://keys.fixture.test/jwks".into());
        }
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::with_config(jwt))
            .plugin(OAuthProviderPlugin::with_config(provider))
            .build()
            .await?;
        let before = db
            .tables(&["user", "account", "session", "verification", "jwks"])
            .await?;
        let output = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::get_oauth_server_config_endpoint(),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await?
            .decode()?;
        assert_eq!(
            output["authorization_endpoint"],
            format!("{ORIGIN}/api/auth/oauth2/authorize")
        );
        assert_eq!(
            output["token_endpoint"],
            format!("{ORIGIN}/api/auth/oauth2/token")
        );
        assert_eq!(output["code_challenge_methods_supported"], json!(["S256"]));
        if mode == "configured" {
            assert_eq!(output["issuer"], "https://issuer.fixture.test/tenant");
            assert_eq!(output["jwks_uri"], "https://keys.fixture.test/jwks");
            assert_eq!(
                output["registration_endpoint"],
                format!("{ORIGIN}/api/auth/oauth2/register")
            );
            assert_eq!(output["response_types_supported"], json!([]));
            assert_eq!(
                output["grant_types_supported"],
                json!(["client_credentials"])
            );
            assert_eq!(
                output["token_endpoint_auth_methods_supported"],
                json!([
                    "none",
                    "client_secret_basic",
                    "client_secret_post",
                    "private_key_jwt"
                ])
            );
        } else {
            assert_eq!(output["issuer"], format!("{ORIGIN}/api/auth"));
            assert!(output.get("registration_endpoint").is_none());
        }
        if mode == "oauth" || mode == "configured" {
            assert_eq!(output["scopes_supported"], json!(["read"]));
            assert!(output.get("userinfo_endpoint").is_none());
        } else {
            assert_eq!(
                output["scopes_supported"],
                json!(["openid", "profile", "email", "offline_access"])
            );
            assert_eq!(
                output["userinfo_endpoint"],
                format!("{ORIGIN}/api/auth/oauth2/userinfo")
            );
        }
        if mode == "disabled" {
            assert!(output.get("jwks_uri").is_none());
            assert_eq!(
                output["id_token_signing_alg_values_supported"],
                json!(["HS256"])
            );
            assert_eq!(output["backchannel_logout_supported"], false);
        }
        let oidc = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::get_open_id_config_endpoint(),
                alibi::endpoint::EndpointOptions::default(),
            )
            .await;
        if mode == "oauth" || mode == "configured" {
            let error = oidc.unwrap_err();
            assert_eq!(error.error.status_code(), 404);
            assert!(error.body_absent);
            assert_eq!(
                error
                    .headers
                    .as_ref()
                    .unwrap()
                    .get("content-type")
                    .map(String::as_str),
                Some("application/json")
            );
        } else {
            let document = oidc?.decode()?;
            assert_eq!(document["issuer"], format!("{ORIGIN}/api/auth"));
            assert_eq!(
                document["userinfo_endpoint"],
                format!("{ORIGIN}/api/auth/oauth2/userinfo")
            );
            assert_eq!(document["claims_parameter_supported"], true);
            assert_eq!(document["subject_types_supported"], json!(["public"]));
            assert_eq!(
                document["id_token_signing_alg_values_supported"],
                json!([if mode == "disabled" { "HS256" } else { "EdDSA" }])
            );
            for claim in ["sub", "sid", "name", "email_verified"] {
                assert!(
                    document["claims_supported"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(claim))
                );
            }
        }
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "jwks"])
                .await?,
            before
        );
    }
    B::close(connection).await
}

#[derive(Debug)]
struct MetadataDiscovery {
    id: &'static str,
    empty: bool,
}
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientDiscovery for MetadataDiscovery {
    fn id(&self) -> &str {
        self.id
    }
    fn matches(&self, _: &str) -> bool {
        false
    }
    fn discovery_metadata(&self) -> serde_json::Map<String, Value> {
        if self.empty {
            return serde_json::Map::new();
        }
        let value = if self.id == "metadata-first" {
            json!({
                "client_id_metadata_document_supported":true,"registry_order":"first","registry_first_only":17,
                "issuer":"https://untrusted.fixture.test","token_endpoint_auth_methods_supported":["wrong"],"scopes_supported":["wrong"],"claims_supported":["wrong"],"jwks_uri":"https://untrusted.fixture.test/keys"
            })
        } else {
            json!({"registry_order":"second","registry_second_only":{"enabled":true},"issuer":"https://also-untrusted.fixture.test"})
        };
        value.as_object().unwrap().clone()
    }
    async fn resolve(
        &self,
        _: &alibi::CallbackContext,
        _: &str,
        _: Option<alibi::store::OAuthClient>,
    ) -> alibi::AuthResult<Option<alibi::store::OAuthClient>> {
        Ok(None)
    }
}
async fn oauth_discovery_advertises_registry_support_and_merges_contributions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for mode in ["registry", "registry-oauth", "registry-empty"] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                client_discoveries: ["metadata-first", "metadata-second"]
                    .into_iter()
                    .map(|id| {
                        Arc::new(MetadataDiscovery {
                            id,
                            empty: mode == "registry-empty",
                        }) as Arc<dyn alibi::plugins::OAuthClientDiscovery>
                    })
                    .collect(),
                scopes: if mode == "registry-oauth" {
                    vec!["read".into()]
                } else {
                    OAuthProviderConfig::default().scopes
                },
                ..Default::default()
            }))
            .build()
            .await?;
        let before = db
            .tables(&[
                "oauthClient",
                "oauthClientAssertion",
                "oauthAccessToken",
                "oauthRefreshToken",
            ])
            .await?;
        for (operation, endpoint) in [
            (
                "getOAuthServerConfig",
                OAuthProviderPlugin::get_oauth_server_config_endpoint(),
            ),
            (
                "getOpenIdConfig",
                OAuthProviderPlugin::get_open_id_config_endpoint(),
            ),
        ] {
            let result = auth
                .dispatch_endpoint(endpoint, alibi::endpoint::EndpointOptions::default())
                .await;
            if mode == "registry-oauth" && operation == "getOpenIdConfig" {
                let error = result.unwrap_err();
                assert_eq!(error.error.status_code(), 404);
                assert!(error.body_absent);
                continue;
            }
            let document = result?.decode()?;
            assert_eq!(
                document["token_endpoint_auth_methods_supported"],
                json!([
                    "none",
                    "client_secret_basic",
                    "client_secret_post",
                    "private_key_jwt"
                ])
            );
            for name in [
                "introspection_endpoint_auth_methods_supported",
                "revocation_endpoint_auth_methods_supported",
            ] {
                assert_eq!(
                    document[name],
                    json!([
                        "client_secret_basic",
                        "client_secret_post",
                        "private_key_jwt"
                    ])
                );
            }
            assert_eq!(document["issuer"], format!("{ORIGIN}/api/auth"));
            assert_eq!(document["jwks_uri"], format!("{ORIGIN}/api/auth/jwks"));
            assert_eq!(
                document["scopes_supported"],
                if mode == "registry-oauth" {
                    json!(["read"])
                } else {
                    json!(["openid", "profile", "email", "offline_access"])
                }
            );
            if mode == "registry-empty" {
                assert!(
                    document
                        .get("client_id_metadata_document_supported")
                        .is_none()
                );
                assert!(document.get("registry_order").is_none());
            } else {
                assert_eq!(document["client_id_metadata_document_supported"], true);
                assert_eq!(document["registry_order"], "second");
                assert_eq!(document["registry_first_only"], 17);
                assert_eq!(document["registry_second_only"], json!({"enabled":true}));
                if mode == "registry-oauth" {
                    assert_eq!(document["claims_supported"], json!(["wrong"]));
                } else {
                    assert!(
                        document["claims_supported"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("sub"))
                    );
                    assert!(
                        !document["claims_supported"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("wrong"))
                    );
                }
            }
        }
        assert_eq!(
            db.tables(&[
                "oauthClient",
                "oauthClientAssertion",
                "oauthAccessToken",
                "oauthRefreshToken"
            ])
            .await?,
            before
        );
    }
    B::close(connection).await
}
