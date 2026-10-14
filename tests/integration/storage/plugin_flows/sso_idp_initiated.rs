//! Signed unsolicited assertions obey explicit admission and retain replay protection.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{
    AuthVerification,
    store::{AccountStore, VerificationStore},
};
backend_tests!(sso_idp_initiated_saml_requires_opt_in_and_trusted_nonreplayed_assertions);
async fn sso_idp_initiated_saml_requires_opt_in_and_trusted_nonreplayed_assertions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    for allowed in [true, false] {
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(SsoPlugin::with_config(SsoConfig {
                saml_allow_idp_initiated: allowed,
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, &format!("unsolicited-owner-{allowed}@example.test")).await;
        let provider_id = format!("unsolicited-{allowed}");
        let registration = json!({"providerId":provider_id,"issuer":"https://idp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem"),"idpMetadata":{"entityID":"https://idp.example.test/entity"},"idpInitiatedCallbackUrl":"/idp-complete"}});
        let created = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&registration)?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(created.status, 200);
        for (http, wrong_key) in [(false, false), (true, false), (false, true), (true, true)] {
            let email = format!("unsolicited-{allowed}-{http}-{wrong_key}@example.test");
            let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":provider_id,"providerType":"saml","callbackURL":format!("{ORIGIN}/unused-relay")}))?,EndpointOptions::default())).await?.into_response()?;
            assert_eq!(started.status, 200);
            let grant = super::saml_idp::unsolicited_grant(
                body(&started)["url"].as_str().unwrap(),
                &email,
                wrong_key,
            )?;
            let payload = json!({"SAMLResponse":grant["SAMLResponse"]});
            let invoke = || async {
                if http {
                    let mut request = AuthRequest::new(
                        HttpMethod::Post,
                        format!("/sso/saml2/sp/acs/{provider_id}"),
                    );
                    _ = request.headers.insert(
                        "content-type".into(),
                        "application/x-www-form-urlencoded".into(),
                    );
                    _ = request
                        .headers
                        .insert("origin".into(), "https://idp.example.test".into());
                    request.body = Some(
                        url::form_urlencoded::Serializer::new(String::new())
                            .append_pair("SAMLResponse", grant["SAMLResponse"].as_str().unwrap())
                            .finish()
                            .into_bytes(),
                    );
                    Box::pin(auth.handle_request(request))
                        .await
                        .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
                } else {
                    Ok(Box::pin(auth.dispatch_endpoint(
                        SsoPlugin::acs_endpoint(&provider_id, &payload)?,
                        EndpointOptions::default(),
                    ))
                    .await?
                    .into_response()?)
                }
            };
            let completed = invoke().await?;
            assert_eq!(completed.status, 302);
            let location =
                url::Url::parse(ORIGIN)?.join(completed.headers.get("location").unwrap())?;
            assert_eq!(location.path(), "/idp-complete");
            let used = store
                .get_latest_verification_by_identifier(&format!(
                    "saml-used-assertion:{}",
                    grant["assertionId"].as_str().unwrap()
                ))
                .await?;
            let account = store.get_account(&provider_id, &email).await?;
            if wrong_key || !allowed {
                assert_eq!(
                    location
                        .query_pairs()
                        .find(|(key, _)| key == "error")
                        .unwrap()
                        .1,
                    if wrong_key {
                        "saml_error"
                    } else {
                        "unsolicited_response"
                    }
                );
                assert!(used.is_none());
                assert!(account.is_none());
                assert!(
                    !completed
                        .headers
                        .get_all("set-cookie")
                        .any(|value| value.starts_with("better-auth.session_token="))
                );
            } else {
                assert!(location.query().is_none());
                assert!(account.is_some());
                let proof: Value = serde_json::from_str(used.unwrap().value())?;
                assert_eq!(proof["assertionId"], grant["assertionId"]);
                let session = call(
                    &auth,
                    request("/get-session", None, &cookies(&completed)),
                    200,
                )
                .await;
                assert_eq!(body(&session)["user"]["email"], email);
                let replay = invoke().await?;
                let replay =
                    url::Url::parse(ORIGIN)?.join(replay.headers.get("location").unwrap())?;
                assert_eq!(
                    replay
                        .query_pairs()
                        .find(|(key, _)| key == "error")
                        .unwrap()
                        .1,
                    "replay_detected"
                );
            }
            assert!(
                store
                    .get_latest_verification_by_identifier(&format!(
                        "saml-authn-request:{}",
                        grant["requestId"].as_str().unwrap()
                    ))
                    .await?
                    .is_some()
            );
            assert!(
                store
                    .get_latest_verification_by_identifier(&format!(
                        "auth-state:{}",
                        grant["RelayState"].as_str().unwrap()
                    ))
                    .await?
                    .is_some()
            );
            if allowed && !http && !wrong_key {
                let identifier = format!(
                    "saml-authn-request:{}",
                    grant["requestId"].as_str().unwrap()
                );
                _ = store
                    .update_verification_by_identifier(
                        &identifier,
                        alibi::UpdateVerification {
                            expires_at: Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
                            ..Default::default()
                        },
                    )
                    .await?;
                let correlated_email = "expired-correlated@example.test";
                let correlated = super::saml_idp::grant(
                    body(&started)["url"].as_str().unwrap(),
                    correlated_email,
                    false,
                )?;
                let denied = Box::pin(auth.dispatch_endpoint(
                    SsoPlugin::acs_endpoint(
                        &provider_id,
                        &json!({"SAMLResponse":correlated["SAMLResponse"]}),
                    )?,
                    EndpointOptions::default(),
                ))
                .await?
                .into_response()?;
                let location =
                    url::Url::parse(ORIGIN)?.join(denied.headers.get("location").unwrap())?;
                assert_eq!(
                    location
                        .query_pairs()
                        .find(|(key, _)| key == "error")
                        .unwrap()
                        .1,
                    "invalid_saml_response"
                );
                assert_eq!(
                    location
                        .query_pairs()
                        .find(|(key, _)| key == "error_description")
                        .unwrap()
                        .1,
                    "Unknown or expired request ID"
                );
                assert!(
                    store
                        .get_account(&provider_id, correlated_email)
                        .await?
                        .is_none()
                );
                assert!(
                    store
                        .get_latest_verification_by_identifier(&format!(
                            "saml-used-assertion:{}",
                            correlated["assertionId"].as_str().unwrap()
                        ))
                        .await?
                        .is_none()
                );
            }
        }
    }
    B::close(connection).await
}
