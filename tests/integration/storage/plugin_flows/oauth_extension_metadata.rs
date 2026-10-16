//! Metadata callbacks preserve document ownership and receive real logical caller context.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderExtension, OAuthProviderPlugin, jwt::JwtPlugin,
};
use std::sync::Arc;
#[path = "../../../fixtures/oauth/extension-metadata.rs"]
mod extension_metadata;
backend_tests!(oauth_extension_metadata_preserves_base_authority_and_context);
postgres_tests!(oauth_extension_metadata_preserves_base_authority_and_context);
async fn oauth_extension_metadata_preserves_base_authority_and_context<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for openid in [true, false] {
        let config = OAuthProviderConfig {
            scopes: if openid {
                OAuthProviderConfig::default().scopes
            } else {
                vec!["read".into()]
            },
            extensions: ["first", "second"]
                .into_iter()
                .map(|id| {
                    Arc::new(OAuthProviderExtension {
                        metadata: Some(Arc::new(extension_metadata::ExtensionMetadata {
                            id,
                            mutate: true,
                        })),
                        ..Default::default()
                    })
                })
                .collect(),
            ..Default::default()
        };
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(JwtPlugin::new())
            .plugin(OAuthProviderPlugin::with_config(config))
            .build()
            .await?;
        let response = Box::pin(
            auth.dispatch_endpoint(
                OAuthProviderPlugin::get_oauth_server_config_endpoint(),
                EndpointOptions {
                    headers: Some(
                        [("x-metadata-caller".into(), "actual-caller".into())]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(response.status, 200);
        let doc = body(&response);
        assert_eq!(doc["extension_stage"], "first");
        assert_eq!(doc["extension_context_header"], "actual-caller");
        assert_eq!(doc["extension_first_base_clean"], true);
        assert_eq!(doc["extension_second_base_clean"], true);
        assert_eq!(doc["extension_first_saw_mutation"], false);
        assert_eq!(doc["extension_second_saw_mutation"], true);
        assert!(doc.get("shared_mutation").is_none());
        assert_eq!(
            doc["issuer"],
            format!(
                "{}{}",
                auth.config().base_url.trim_end_matches('/'),
                auth.config().base_path
            )
        );
        assert_eq!(
            doc["grant_types_supported"],
            json!(["authorization_code", "client_credentials", "refresh_token"])
        );
        assert!(doc.get("constructor").is_none());
        assert!(doc.get("toString").is_none());
        assert_eq!(
            doc["extension_first_type"],
            if openid {
                "openid-configuration"
            } else {
                "oauth-authorization-server"
            }
        );
        if openid {
            assert!(
                doc["claims_supported"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("sub"))
            );
        } else {
            assert_eq!(doc["claims_supported"], json!(["custom-extension-claim"]));
        }
    }
    Ok(())
}
