//! Application signing policies govern registration and updates before writes.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::store::SsoProviderStore;
backend_tests!(sso_saml_signing_policies_apply_allowlists_and_deprecated_admission);
async fn sso_saml_signing_policies_apply_allowlists_and_deprecated_admission<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    for mode in [
        "algorithm-strict",
        "algorithm-reject",
        "algorithm-override",
        "algorithm-empty",
    ] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(SsoPlugin::with_config(SsoConfig {
                saml_signing_policy: super::sso_signing_policy::policy(mode),
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, &format!("{mode}@example.test")).await;
        let owned = EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        };
        let provider_id = format!("{mode}-provider");
        let input = json!({"providerId":provider_id,"issuer":"https://idp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"}}});
        let created = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&input)?,
            owned.clone(),
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 200);
        let original = store.get_sso_provider(&provider_id).await?.unwrap();
        let rejected = match mode {
            "algorithm-strict" => vec!["sha384", "sha1"],
            "algorithm-reject" => vec!["sha1"],
            _ => vec!["sha256"],
        };
        for (field, label) in [
            ("signatureAlgorithm", "signature"),
            ("digestAlgorithm", "digest"),
        ] {
            for (index, value) in rejected.iter().enumerate() {
                let (code, message) = if mode == "algorithm-reject" {
                    (
                        "SAML_DEPRECATED_CONFIG_ALGORITHM",
                        format!(
                            "SAML config uses deprecated {label} algorithm: {value}. Consider using SHA-256 or stronger."
                        ),
                    )
                } else {
                    (
                        "SAML_ALGORITHM_NOT_ALLOWED",
                        format!("SAML {label} algorithm not in allow-list: {value}"),
                    )
                };
                let rejected_id = format!("{mode}-{field}-{index}");
                let mut candidate = input.clone();
                candidate["providerId"] = json!(rejected_id);
                candidate["samlConfig"][field] = json!(value);
                for (update, body) in [
                    (false, candidate),
                    (
                        true,
                        json!({"providerId":provider_id,"samlConfig":{(field):value}}),
                    ),
                ] {
                    let endpoint = if update {
                        SsoPlugin::update_sso_provider_endpoint(&body)?
                    } else {
                        SsoPlugin::register_sso_provider_endpoint(&body)?
                    };
                    let response =
                        match Box::pin(auth.dispatch_endpoint(endpoint, owned.clone())).await {
                            Ok(output) => output.into_response()?,
                            Err(error) => error.error.to_auth_response(),
                        };
                    assert_eq!(response.status, 400);
                    assert_eq!(
                        super::body(&response),
                        json!({"code":code,"message":message})
                    );
                }
                assert!(store.get_sso_provider(&rejected_id).await?.is_none());
                assert_eq!(
                    store.get_sso_provider(&provider_id).await?.unwrap(),
                    original
                );
            }
        }
        let (signature, digest) = match mode {
            "algorithm-override" => ("RSA-SHA1", "SHA1"),
            "algorithm-empty" => ("", ""),
            _ => ("RSA-SHA256", "SHA256"),
        };
        let accepted_id = format!("{mode}-accepted");
        let mut accepted = input.clone();
        accepted["providerId"] = json!(accepted_id);
        accepted["samlConfig"]["signatureAlgorithm"] = json!(signature);
        accepted["samlConfig"]["digestAlgorithm"] = json!(digest);
        for (update, body) in [
            (false, accepted),
            (
                true,
                json!({"providerId":provider_id,"samlConfig":{"signatureAlgorithm":signature,"digestAlgorithm":digest}}),
            ),
        ] {
            let endpoint = if update {
                SsoPlugin::update_sso_provider_endpoint(&body)?
            } else {
                SsoPlugin::register_sso_provider_endpoint(&body)?
            };
            let response = Box::pin(auth.dispatch_endpoint(endpoint, owned.clone()))
                .await?
                .into_response()?;
            assert_eq!(response.status, 200);
        }
        for id in [&provider_id, &accepted_id] {
            let provider = store.get_sso_provider(id).await?.unwrap();
            let config: Value = serde_json::from_str(provider.saml_config.as_deref().unwrap())?;
            assert_eq!(config["signatureAlgorithm"], signature);
            assert_eq!(config["digestAlgorithm"], digest);
        }
    }
    B::close(connection).await
}
