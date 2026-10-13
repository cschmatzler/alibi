//! Logout starts from a real SAML login and retires its actual local session.
use super::saml_idp as idp;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{AuthVerification, store::VerificationStore};
use base64::Engine as _;
use std::io::Read as _;
backend_tests!(
    sso_logout_uses_acs_session_index_and_retires_session,
    sso_logout_response_retires_proof_and_rejects_external_relay,
    sso_idp_logout_matches_session_index_before_retiring_session,
    sso_logout_required_signature_preserves_proof_until_trusted_completion
);
async fn sso_logout_uses_acs_session_index_and_retires_session<B: Backend>(db: Db) -> TestResult {
    logout_flow::<B>(db, false, false).await
}
async fn sso_logout_response_retires_proof_and_rejects_external_relay<B: Backend>(
    db: Db,
) -> TestResult {
    logout_flow::<B>(db, true, false).await
}
async fn sso_logout_required_signature_preserves_proof_until_trusted_completion<B: Backend>(
    db: Db,
) -> TestResult {
    logout_flow::<B>(db, true, true).await
}
async fn logout_flow<B: Backend>(db: Db, complete: bool, signed: bool) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            saml_enable_single_logout: true,
            saml_want_logout_response_signed: signed,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "saml-logout-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let input = json!({"providerId":"logout-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity","singleLogoutService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","Location":"https://idp.example.test/logout"}]},"wantAssertionsSigned":true}});
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
    let started = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::sign_in_sso_endpoint(
            &json!({"providerId":"logout-provider","callbackURL":format!("{ORIGIN}/complete")}),
        )?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let email = "saml-logout-user@example.test";
    let grant = idp::grant(body(&started)["url"].as_str().unwrap(), email, false)?;
    let completed = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "acsEndpoint")
                .with_params(&json!({"providerId":"logout-provider"}))?
                .with_body(&grant)?,
            EndpointOptions::default(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(completed.status, 302);
    let cookie = cookies(&completed);
    let session = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert_eq!(body(&session)["user"]["email"], email);
    let session = body(&session)["session"].clone();
    let lookup = format!("saml-session-by-id:{}", session["id"].as_str().unwrap());
    let key = format!("saml-session:logout-provider:{email}");
    let stored = store
        .get_latest_verification_by_identifier(&key)
        .await?
        .ok_or("SAML session record missing")?;
    let value: Value = serde_json::from_str(stored.value())?;
    assert_eq!(value["sessionId"], session["id"]);
    assert_eq!(value["sessionToken"], session["token"]);
    assert_eq!(value["sessionIndex"], "session-index");
    assert_eq!(value["nameID"], email);
    assert_eq!(
        store
            .get_latest_verification_by_identifier(&lookup)
            .await?
            .unwrap()
            .value(),
        key
    );
    let before = chrono::Utc::now();
    let output = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("sso", "initiateSLO")
                .with_params(&json!({"providerId":"logout-provider"}))?
                .with_body(&json!({"callbackURL":format!("{ORIGIN}/logged-out")}))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    let after = chrono::Utc::now();
    assert_eq!(output.status, 302);
    let url = url::Url::parse(output.headers.get("location").unwrap())?;
    assert_eq!(
        url.origin().ascii_serialization(),
        "https://idp.example.test"
    );
    assert_eq!(url.path(), "/logout");
    let query = url
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert!(!query.contains_key("RelayState"));
    let bytes = base64::engine::general_purpose::STANDARD.decode(&query["SAMLRequest"])?;
    let mut xml = String::new();
    _ = flate2::read::DeflateDecoder::new(bytes.as_slice()).read_to_string(&mut xml)?;
    let doc = bergshamra::xml::uppsala::parse(&xml)?;
    let root = doc.document_element().unwrap();
    assert_eq!(doc.element(root).unwrap().name.local_name, "LogoutRequest");
    assert_eq!(
        doc.get_attribute(root, "Destination"),
        Some("https://idp.example.test/logout")
    );
    assert_eq!(doc.get_attribute(root, "Version"), Some("2.0"));
    let find = |name: &str| {
        doc.descendants(root)
            .into_iter()
            .find(|node| {
                doc.element(*node)
                    .is_some_and(|element| element.name.local_name == name)
            })
            .unwrap()
    };
    assert_eq!(doc.element_text(find("NameID")), Some(email));
    assert_eq!(
        doc.element_text(find("SessionIndex")),
        Some("session-index")
    );
    assert_eq!(
        doc.element_text(find("Issuer")),
        Some("https://sp.example.test/entity")
    );
    let id = doc.get_attribute(root, "ID").unwrap();
    _ = uuid::Uuid::parse_str(id.strip_prefix('_').unwrap())?;
    let issue =
        chrono::DateTime::parse_from_rfc3339(doc.get_attribute(root, "IssueInstant").unwrap())?;
    assert!(
        issue.timestamp_millis() >= before.timestamp_millis()
            && issue.timestamp_millis() <= after.timestamp_millis()
    );
    let proof = store
        .get_latest_verification_by_identifier(&format!("saml-logout-request:{id}"))
        .await?
        .ok_or("Logout proof missing")?;
    assert_eq!(proof.value(), "logout-provider");
    assert!(
        proof.expires_at().timestamp_millis() >= before.timestamp_millis() + 300000
            && proof.expires_at().timestamp_millis() <= after.timestamp_millis() + 300000
    );
    assert!(
        store
            .get_latest_verification_by_identifier(&key)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_latest_verification_by_identifier(&lookup)
            .await?
            .is_none()
    );
    let retired = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert!(body(&retired).is_null());
    assert!(
        output
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.starts_with("better-auth.session_token=")
                && cookie.contains("Max-Age=0"))
    );
    if complete {
        let response_xml = format!(
            r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_idp-logout-response" Version="2.0" IssueInstant="{}" InResponseTo="{id}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#,
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        );
        let mut response = base64::engine::general_purpose::STANDARD.encode(&response_xml);
        if signed {
            for rejected_response in [response.clone(), idp::signed_logout(&response_xml, true)?] {
                let rejected = Box::pin(
                    auth.dispatch_endpoint(
                        ServerEndpoint::<Value>::new("sso", "sloEndpoint")
                            .with_params(&json!({"providerId":"logout-provider"}))?
                            .with_body(&json!({"SAMLResponse":rejected_response}))?,
                        EndpointOptions {
                            method: Some(HttpMethod::Post),
                            ..Default::default()
                        },
                    ),
                )
                .await
                .unwrap_err();
                assert_eq!(rejected.error.status_code(), 400);
                let retained = store
                    .get_latest_verification_by_identifier(&format!("saml-logout-request:{id}"))
                    .await?
                    .ok_or("Rejected signature consumed logout proof")?;
                assert_eq!(retained.value(), proof.value());
                assert_eq!(retained.expires_at(), proof.expires_at());
            }
            response = idp::signed_logout(&response_xml, false)?;
        }
        let endpoint = ServerEndpoint::<Value>::new("sso", "sloEndpoint")
            .with_params(&json!({"providerId":"logout-provider"}))?
            .with_body(
                &json!({"SAMLResponse":response,"RelayState":"https://attacker.example/steal"}),
            )?;
        let completed = Box::pin(auth.dispatch_endpoint(
            endpoint.clone(),
            EndpointOptions {
                method: Some(HttpMethod::Post),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(completed.status, 302);
        assert_eq!(
            completed.headers.get("location").map(String::as_str),
            Some(ORIGIN)
        );
        assert!(
            store
                .get_latest_verification_by_identifier(&format!("saml-logout-request:{id}"))
                .await?
                .is_none()
        );
        let repeated = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                method: Some(HttpMethod::Post),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(repeated.status, 302);
    }
    B::close(connection).await
}

async fn sso_idp_logout_matches_session_index_before_retiring_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            saml_enable_single_logout: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "idp-logout-owner@example.test").await;
    let cert = include_str!("../../../compat/fixtures/salesforce-transport/leaf.pem");
    let input = json!({"providerId":"idp-logout-provider","issuer":"https://sp.example.test/entity","domain":"company.test","samlConfig":{"entryPoint":"https://idp.example.test/sso","cert":cert,"idpMetadata":{"entityID":"https://idp.example.test/entity","singleLogoutService":[{"Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST","Location":"https://idp.example.test/logout-post"}]},"wantAssertionsSigned":true}});
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
    for matching in [true, false] {
        let email = if matching {
            "matched-logout@example.test"
        } else {
            "mismatched-logout@example.test"
        };
        let started=Box::pin(auth.dispatch_endpoint(SsoPlugin::sign_in_sso_endpoint(&json!({"providerId":"idp-logout-provider","callbackURL":format!("{ORIGIN}/complete")}))?,EndpointOptions::default())).await?.into_response()?;
        let grant = idp::grant(body(&started)["url"].as_str().unwrap(), email, false)?;
        let completed = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("sso", "acsEndpoint")
                    .with_params(&json!({"providerId":"idp-logout-provider"}))?
                    .with_body(&grant)?,
                EndpointOptions::default(),
            ),
        )
        .await?
        .into_response()?;
        assert_eq!(completed.status, 302);
        let cookie = cookies(&completed);
        let session =
            body(&call(&auth, request("/get-session", None, &cookie), 200).await)["session"]
                .clone();
        let request_id = if matching {
            "_idp-matching-request"
        } else {
            "_idp-mismatched-request"
        };
        let index = if matching {
            "session-index"
        } else {
            "another-session"
        };
        let xml = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="{}"><saml:Issuer>https://idp.example.test/entity</saml:Issuer><saml:NameID>{email}</saml:NameID><samlp:SessionIndex>{index}</samlp:SessionIndex></samlp:LogoutRequest>"#,
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        );
        let endpoint=ServerEndpoint::<Value>::new("sso","sloEndpoint").with_params(&json!({"providerId":"idp-logout-provider"}))?.with_body(&json!({"SAMLRequest":base64::engine::general_purpose::STANDARD.encode(xml),"RelayState":"opaque-relay"}))?;
        let output = Box::pin(auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                method: Some(HttpMethod::Post),
                ..Default::default()
            },
        ))
        .await?
        .into_response()?;
        assert_eq!(output.status, 200);
        assert_eq!(
            output.headers.get("content-type").map(String::as_str),
            Some("text/html")
        );
        let html = std::str::from_utf8(&output.body)?;
        assert!(html.contains("action=\"https://idp.example.test/logout-post\""));
        assert!(html.contains("name=\"RelayState\" value=\"opaque-relay\""));
        let encoded = html
            .split("name=\"SAMLResponse\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
        let doc = bergshamra::xml::uppsala::parse(&xml)?;
        let root = doc.document_element().unwrap();
        assert_eq!(doc.get_attribute(root, "InResponseTo"), Some(request_id));
        assert_eq!(
            doc.get_attribute(root, "Destination"),
            Some("https://idp.example.test/logout-post")
        );
        let current = call(&auth, request("/get-session", None, &cookie), 200).await;
        assert_eq!(body(&current).is_null(), matching);
        assert!(
            store
                .get_latest_verification_by_identifier(&format!(
                    "saml-session:idp-logout-provider:{email}"
                ))
                .await?
                .is_none()
        );
        assert_eq!(
            store
                .get_latest_verification_by_identifier(&format!(
                    "saml-session-by-id:{}",
                    session["id"].as_str().unwrap()
                ))
                .await?
                .is_none(),
            matching
        );
    }
    B::close(connection).await
}
