//! A real IdP signature redeems issued SAML state and creates a usable session.
use super::saml_idp as idp;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::SsoPlugin;
use alibi::{
    AuthAccount, AuthVerification,
    store::{AccountStore, VerificationStore},
};
backend_tests!(
    sso_saml_acs_validates_signed_grant_and_rejects_wrong_key_and_replay,
    sso_trusted_saml_verification_requires_mapping_and_exact_first_true_attribute
);
async fn sso_saml_acs_validates_signed_grant_and_rejects_wrong_key_and_replay<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "saml-acs-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let input = json!({"providerId":"acs-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"callbackUrl":format!("{ORIGIN}/complete")}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    for (http, wrong_key) in [(false, false), (true, false), (false, true), (true, true)] {
        let email = if wrong_key {
            "wrong-key-user@example.test"
        } else {
            "saml-employee@example.test"
        };
        let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"acs-provider","providerType":"saml","callbackURL":format!("{ORIGIN}/complete"),"errorCallbackURL":format!("{ORIGIN}/failed")}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(started.status, 200);
        let grant = idp::grant(body(&started)["url"].as_str().unwrap(), email, wrong_key)?;
        let endpoint = ServerEndpoint::<Value>::new("sso", "acsEndpoint")
            .with_params(&json!({"providerId":"acs-provider"}))?
            .with_body(
                &json!({"SAMLResponse":grant["SAMLResponse"],"RelayState":grant["RelayState"]}),
            )?;
        // Exercise a real cross-site IdP form POST even when a session cookie is present.
        let invoke = |endpoint| async {
            if http {
                let form = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("SAMLResponse", grant["SAMLResponse"].as_str().unwrap())
                    .append_pair("RelayState", grant["RelayState"].as_str().unwrap())
                    .finish();
                let mut incoming =
                    AuthRequest::new(HttpMethod::Post, "/sso/saml2/sp/acs/acs-provider");
                incoming.headers.extend([
                    (
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    ),
                    ("origin".into(), "https://idp.example.test".into()),
                    ("cookie".into(), cookies(&owner)),
                ]);
                incoming.body = Some(form.into_bytes());
                Box::pin(auth.handle_request(incoming))
                    .await
                    .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
            } else {
                Ok(
                    Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
                        .await?
                        .into_response()?,
                )
            }
        };
        let completed = invoke(endpoint.clone()).await?;
        assert_eq!(completed.status, 302);
        let location = url::Url::parse(completed.headers.get("location").unwrap())?;
        assert!(
            store
                .get_latest_verification_by_identifier(&format!(
                    "auth-state:{}",
                    grant["RelayState"].as_str().unwrap()
                ))
                .await?
                .is_none()
        );
        let request_identifier = format!(
            "saml-authn-request:{}",
            grant["requestId"].as_str().unwrap()
        );
        let assertion = format!(
            "saml-used-assertion:{}",
            grant["assertionId"].as_str().unwrap()
        );
        if wrong_key {
            assert_eq!(location.path(), "/failed");
            let query = location
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(query["error"], "saml_error");
            assert_eq!(query["error_description"], "Invalid SAML response");
            assert!(
                store
                    .get_latest_verification_by_identifier(&request_identifier)
                    .await?
                    .is_some()
            );
            assert!(
                store
                    .get_latest_verification_by_identifier(&assertion)
                    .await?
                    .is_none()
            );
            assert!(store.get_account("acs-provider", email).await?.is_none());
            assert!(
                !completed
                    .headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.starts_with("better-auth.session_token="))
            );
        } else {
            assert_eq!(location.as_str(), format!("{ORIGIN}/complete"));
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert_eq!(body(&session)["user"]["name"], "SSO employee");
            assert_eq!(body(&session)["user"]["emailVerified"], false);
            assert!(
                body(&session)["session"]["token"]
                    .as_str()
                    .is_some_and(|token| !token.is_empty())
            );
            assert!(
                store
                    .get_latest_verification_by_identifier(&request_identifier)
                    .await?
                    .is_none()
            );
            let used = store
                .get_latest_verification_by_identifier(&assertion)
                .await?
                .ok_or("Assertion replay proof missing")?;
            let proof: Value = serde_json::from_str(used.value())?;
            assert_eq!(proof["assertionId"], grant["assertionId"]);
            assert_eq!(proof["issuer"], "https://idp.example.test/entity");
            assert_eq!(proof["providerId"], "acs-provider");
            let account = store
                .get_account("acs-provider", email)
                .await?
                .ok_or("SAML account missing")?;
            assert_eq!(
                account.user_id(),
                body(&session)["user"]["id"].as_str().unwrap()
            );
            assert_eq!(account.access_token(), Some(""));
            assert_eq!(account.refresh_token(), Some(""));
            assert_ne!(
                account.user_id(),
                body(&owner)["user"]["id"].as_str().unwrap()
            );
            let replay = invoke(endpoint).await?;
            assert_eq!(replay.status, 302);
            let query = url::Url::parse(replay.headers.get("location").unwrap())?
                .query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(query["error"], "invalid_saml_response");
            assert_eq!(query["error_description"], "Unknown or expired request ID");
        }
    }
    let mut rejected = request("/sign-out", Some(json!({})), &cookies(&owner));
    _ = rejected
        .headers
        .insert("origin".into(), "https://idp.example.test".into());
    _ = call(&auth, rejected, 403).await;
    authenticated(&auth, &cookies(&owner), "saml-acs-owner@example.test").await;
    B::close(connection).await
}

async fn sso_trusted_saml_verification_requires_mapping_and_exact_first_true_attribute<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(alibi::plugins::SsoConfig {
            trust_email_verified: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "trusted-saml-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    for mapped in [true, false] {
        let provider = if mapped {
            "trusted-saml-provider"
        } else {
            "unmapped-saml-provider"
        };
        let mut mapping = json!({"email":"email","name":"displayName"});
        if mapped {
            mapping["emailVerified"] = json!("verified-mailbox");
        }
        let registered = Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider,"issuer":"https://sp.example.test/entity","domain":"example.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity"},"wantAssertionsSigned":true,"mapping":mapping}}))?,EndpointOptions { headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default() })).await?.into_response()?;
        assert_eq!(registered.status, 200);
        let claims = if mapped {
            vec![
                (vec!["true"], true),
                (vec!["false"], false),
                (vec!["TRUE"], false),
                (vec!["1"], false),
                (vec!["true", "false"], true),
                (vec!["false", "true"], false),
            ]
        } else {
            vec![(vec!["true"], false)]
        };
        for (index, (values, expected)) in claims.into_iter().enumerate() {
            let email = format!("trusted-saml-{mapped}-{index}@example.test");
            let started = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::sign_in_sso_endpoint(
                    &json!({"providerId":provider,"callbackURL":format!("{ORIGIN}/complete")}),
                )?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let grant = idp::grant_with_verified(
                body(&started)["url"].as_str().unwrap(),
                &email,
                false,
                Some(&values),
            )?;
            let completed = Box::pin(auth.dispatch_endpoint(
                SsoPlugin::acs_endpoint(provider, &grant)?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(
                completed.headers.get("location").map(String::as_str),
                Some(format!("{ORIGIN}/complete").as_str())
            );
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], email);
            assert_eq!(body(&session)["user"]["emailVerified"], expected);
        }
    }
    B::close(connection).await
}
