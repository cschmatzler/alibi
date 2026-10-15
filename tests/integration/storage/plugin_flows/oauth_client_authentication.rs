//! Client authentication admission owns cardinality and physical form precedence.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
backend_tests!(oauth_client_authentication_rejects_ambiguous_methods_and_normalizes_forms);
postgres_tests!(oauth_client_authentication_rejects_ambiguous_methods_and_normalizes_forms);
struct Case {
    name: &'static str,
    body: Value,
    entries: Vec<(String, String)>,
    authorization: Option<String>,
    detail: Option<&'static str>,
}
fn entries(body: &Value) -> Vec<(String, String)> {
    body.as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap().into()))
        .collect()
}
async fn invoke<S: AuthSchema>(auth: &Alibi<S>, case: &Case) -> alibi::AuthResult<AuthResponse> {
    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&case.entries)
        .finish();
    let mut request = request("/oauth2/introspect", Some(case.body.clone()), "");
    request.body = Some(encoded.into_bytes());
    _ = request.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    if let Some(header) = &case.authorization {
        _ = request
            .headers
            .insert("authorization".into(), header.clone());
    }
    let output = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Introspect").with_body(&case.body)?,
        EndpointOptions {
            headers: Some(request.headers.clone()),
            request: Some(request),
            ..Default::default()
        },
    ))
    .await;
    match output {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
async fn oauth_client_authentication_rejects_ambiguous_methods_and_normalizes_forms<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "client-admission-owner@example.test").await;
    let mut clients = Vec::new();
    for method in ["client_secret_basic", "client_secret_post"] {
        let response=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":method,"redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":method}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
        assert_eq!(response.status, 201);
        clients.push(body(&response));
    }
    let basic = &clients[0];
    let post = &clients[1];
    let header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            basic["client_id"].as_str().unwrap(),
            basic["client_secret"].as_str().unwrap()
        ))
    );
    let post_body = json!({"token":"not-issued","client_id":post["client_id"],"client_secret":post["client_secret"]});
    let basic_body = json!({"token":"not-issued","client_id":basic["client_id"],"client_secret":basic["client_secret"]});
    let mut cases = vec![Case {
        name: "header-and-secret",
        entries: entries(&basic_body),
        body: basic_body,
        authorization: Some(header.clone()),
        detail: Some("A request must use only one client authentication method"),
    }];
    let mixed = json!({"token":"not-issued","client_id":post["client_id"],"client_secret":post["client_secret"],"client_assertion":"test","client_assertion_type":"urn:test"});
    cases.push(Case {
        name: "secret-and-assertion",
        entries: entries(&mixed),
        body: mixed,
        authorization: None,
        detail: Some("A request must use only one client authentication method"),
    });
    let mixed =
        json!({"token":"not-issued","client_assertion":"test","client_assertion_type":"urn:test"});
    cases.push(Case {
        name: "header-and-assertion",
        entries: entries(&mixed),
        body: mixed,
        authorization: Some(header.clone()),
        detail: Some("A request must use only one client authentication method"),
    });
    for (field, value, detail) in [
        (
            "client_id",
            post["client_id"].as_str().unwrap(),
            "client_id must not be repeated",
        ),
        (
            "client_secret",
            post["client_secret"].as_str().unwrap(),
            "client_secret must not be repeated",
        ),
        (
            "client_assertion",
            "test",
            "client_assertion must not be repeated",
        ),
        (
            "client_assertion_type",
            "urn:test",
            "client_assertion_type must not be repeated",
        ),
    ] {
        let mut form = entries(&post_body);
        form.push((field.into(), value.into()));
        if field.starts_with("client_assertion") {
            form.push((field.into(), value.into()));
        }
        cases.push(Case {
            name: field,
            body: post_body.clone(),
            entries: form,
            authorization: None,
            detail: Some(detail),
        });
    }
    let allowed = vec![
        ("token".into(), "not-issued".into()),
        ("client_id".into(), String::new()),
        (
            "client_id".into(),
            post["client_id"].as_str().unwrap().into(),
        ),
        ("client_secret".into(), String::new()),
        (
            "client_secret".into(),
            post["client_secret"].as_str().unwrap().into(),
        ),
        ("resource".into(), "one".into()),
        ("resource".into(), "two".into()),
    ];
    cases.push(Case {
        name: "empty-duplicates-and-resources",
        body: post_body.clone(),
        entries: allowed,
        authorization: None,
        detail: None,
    });
    cases.push(Case {
        name: "request-auth-authority",
        body: json!({"token":"not-issued","client_id":"wrong","client_secret":"wrong"}),
        entries: entries(&post_body),
        authorization: None,
        detail: None,
    });
    let empty = json!({"token":"not-issued","client_secret":"","client_assertion":"","client_assertion_type":""});
    cases.push(Case {
        name: "basic-with-empty-fields",
        entries: entries(&empty),
        body: empty,
        authorization: Some(header),
        detail: None,
    });
    let before = db
        .tables(&[
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken",
            "verification",
            "oauthClientAssertion",
        ])
        .await?;
    for case in cases {
        let response = invoke(&auth, &case).await?;
        assert_eq!(
            response.status,
            if case.detail.is_some() { 400 } else { 200 },
            "{}",
            case.name
        );
        assert_eq!(
            body(&response),
            case.detail.map_or_else(
                || json!({"active":false}),
                |detail| json!({"error":"invalid_request","error_description":detail})
            ),
            "{}",
            case.name
        );
        assert_eq!(
            db.tables(&[
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
                "verification",
                "oauthClientAssertion"
            ])
            .await?,
            before
        );
    }
    B::close(connection).await
}
