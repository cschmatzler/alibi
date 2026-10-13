//! Logout starts from a real SAML login and retires its actual local session.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{SsoConfig, SsoPlugin};
use alibi::{AuthVerification, store::VerificationStore};
use base64::Engine as _;
use std::io::Read as _;
#[path = "../../../support/sso_saml_grant.rs"]
mod idp;
backend_tests!(sso_logout_uses_acs_session_index_and_retires_session);
async fn sso_logout_uses_acs_session_index_and_retires_session<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            saml_enable_single_logout: true,
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
    assert_eq!(query["RelayState"], format!("{ORIGIN}/logged-out"));
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
    B::close(connection).await
}
