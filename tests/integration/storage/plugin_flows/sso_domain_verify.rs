//! Domain confirmation reads real TXT answers and commits the actual provider flag.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SsoConfig, SsoPlugin};
use hickory_proto::{
    op::{Message, OpCode},
    rr::{RData, Record, rdata::TXT},
};
backend_tests!(sso_domain_verify_checks_txt_records_and_commits_provider_state);
postgres_tests!(sso_domain_verify_checks_txt_records_and_commits_provider_state);
async fn sso_domain_verify_checks_txt_records_and_commits_provider_state<B: Backend>(
    db: Db,
) -> TestResult {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let records = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let queries = Arc::new(Mutex::new(Vec::<String>::new()));
    let entries = records.clone();
    let seen = queries.clone();
    let dns = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let Ok(query) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.metadata.recursion_available = true;
            for question in query.queries {
                let name = question.name.clone();
                seen.lock().unwrap().push(name.to_utf8());
                _ = response.add_query(question);
                for chunks in entries.lock().unwrap().iter() {
                    _ = response.add_answer(Record::from_rdata(
                        name.clone(),
                        0,
                        RData::TXT(TXT::new(chunks.clone())),
                    ));
                }
            }
            if let Ok(packet) = response.to_vec() {
                _ = socket.send_to(&packet, peer).await;
            }
        }
    });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(SsoPlugin::with_config(SsoConfig {
            domain_verification: true,
            domain_verification_dns_servers: vec![address],
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "sso-verify-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let created=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":"verify-provider","issuer":"https://idp.example.com","domain":"company.com","oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true}}))?,owned.clone())).await?.into_response()?;
    assert_eq!(created.status, 200);
    let token = body(&created)["domainVerificationToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let endpoint = SsoPlugin::verify_domain_endpoint("verify-provider")?;
    *records.lock().unwrap() = vec![vec!["wrong-proof".into()]];
    let denied = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 502);
    assert_eq!(
        body(&denied.error.to_auth_response()),
        json!({"code":"DOMAIN_VERIFICATION_FAILED","message":"Unable to verify domain ownership for company.com. Try again later"})
    );
    assert_eq!(
        auth.store()
            .get_sso_provider("verify-provider")
            .await?
            .unwrap()
            .domain_verified,
        Some(false)
    );
    *records.lock().unwrap() = vec![vec![
        " _better-auth-token-verify-provider=".into(),
        format!("{token} "),
    ]];
    let verified = Box::pin(auth.dispatch_endpoint(endpoint.clone(), owned.clone()))
        .await?
        .into_response()?;
    assert_eq!(verified.status, 204);
    assert_eq!(
        verified.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(verified.body.is_empty());
    assert_eq!(
        auth.store()
            .get_sso_provider("verify-provider")
            .await?
            .unwrap()
            .domain_verified,
        Some(true)
    );
    assert!(
        queries
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "_better-auth-token-verify-provider.company.com.")
    );
    assert!(!queries.lock().unwrap().is_empty());
    let repeated = Box::pin(auth.dispatch_endpoint(endpoint, owned.clone()))
        .await
        .unwrap_err();
    assert_eq!(repeated.error.status_code(), 409);
    assert_eq!(
        body(&repeated.error.to_auth_response()),
        json!({"code":"DOMAIN_VERIFIED","message":"Domain has already been verified"})
    );
    let request = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::request_domain_verification_endpoint("verify-provider")?,
        owned,
    ))
    .await
    .unwrap_err();
    assert_eq!(request.error.status_code(), 409);
    dns.abort();
    B::close(connection).await
}
