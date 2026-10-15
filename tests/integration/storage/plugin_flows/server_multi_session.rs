//! Direct server calls must deliver usable device proofs and retire them on logout.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::MultiSessionPlugin;
backend_tests!(server_multi_session_issues_usable_proofs_and_retires_them);
postgres_tests!(server_multi_session_issues_usable_proofs_and_retires_them);
async fn sdk<S: AuthSchema>(
    auth: &Alibi<S>,
    plugin: &'static str,
    operation: &'static str,
    value: Option<Value>,
    cookie: &str,
) -> alibi::AuthResult<AuthResponse> {
    let mut endpoint = ServerEndpoint::<Value>::new(plugin, operation);
    if let Some(value) = value {
        endpoint = endpoint.with_body(&value)?;
    }
    Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers: Some([("cookie".into(), cookie.into())].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await
    .map_err(|error| error.error)?
    .into_response()
}
async fn server_multi_session_issues_usable_proofs_and_retires_them<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(MultiSessionPlugin::new())
        .build()
        .await?;
    let mut jar = String::new();
    let mut tokens = Vec::new();
    for name in ["owner", "other"] {
        let response = sdk(&auth, "email-password", "signUpEmail", Some(json!({"email":format!("sdk-multi-{name}@example.com"),"name":name,"password":PASSWORD})), &jar).await?;
        assert_eq!(response.status, 200);
        let token = body(&response)["token"].as_str().unwrap().to_owned();
        let proof_name = format!("better-auth.session_token_multi-{}=", token.to_lowercase());
        let proof = response
            .headers
            .get_all("set-cookie")
            .find(|cookie| cookie.starts_with(&proof_name))
            .expect("SDK signup must publish its genuine signed device proof");
        let pair = proof.split(';').next().unwrap();
        if !jar.is_empty() {
            jar.push_str("; ");
        }
        jar.push_str(pair);
        tokens.push(token);
    }
    let listed = sdk(&auth, "multi-session", "listDeviceSessions", None, &jar).await?;
    assert_eq!(listed.status, 200);
    assert_eq!(body(&listed).as_array().unwrap().len(), 2);
    for token in &tokens {
        assert!(
            body(&listed)
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["session"]["token"] == *token)
        );
    }
    let logout = sdk(
        &auth,
        "session-management",
        "signOut",
        Some(json!({})),
        &jar,
    )
    .await?;
    assert_eq!(logout.status, 200);
    for token in &tokens {
        assert!(
            auth.store().get_session_record(token).await?.is_none(),
            "SDK logout must delete each delivered device session"
        );
        let name = format!("better-auth.session_token_multi-{}=;", token.to_lowercase());
        assert!(
            logout
                .headers
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with(&name) && cookie.contains("Max-Age=0"))
        );
    }
    let listed = sdk(&auth, "multi-session", "listDeviceSessions", None, &jar).await?;
    assert_eq!(body(&listed), json!([]));
    Ok(())
}
