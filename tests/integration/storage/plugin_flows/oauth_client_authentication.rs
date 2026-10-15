//! Client authentication admission owns cardinality and physical form precedence.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
use base64::Engine as _;
backend_tests!(
    oauth_client_authentication_rejects_ambiguous_methods_and_normalizes_forms,
    oauth_client_authentication_parses_basic_form_credentials_and_preserves_reference_decode_quirks
);
postgres_tests!(
    oauth_client_authentication_rejects_ambiguous_methods_and_normalizes_forms,
    oauth_client_authentication_parses_basic_form_credentials_and_preserves_reference_decode_quirks
);
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

#[derive(Debug)]
struct FormCredentials;
impl alibi::plugins::OAuthClientIdGenerator for FormCredentials {
    fn generate(&self) -> alibi::AuthResult<String> {
        Ok("client +/é:fixed".into())
    }
}
impl alibi::plugins::OAuthClientSecretGenerator for FormCredentials {
    fn generate(&self) -> alibi::AuthResult<String> {
        Ok("secret +/é:tail".into())
    }
}
async fn oauth_client_authentication_parses_basic_form_credentials_and_preserves_reference_decode_quirks<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cfg = alibi::plugins::OAuthProviderConfig {
        client_id_generator: Some(Arc::new(FormCredentials)),
        client_secret_generator: Some(Arc::new(FormCredentials)),
        ..Default::default()
    };
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::with_config(cfg))
        .build()
        .await?;
    let owner = signup(&auth, "basic-form-owner@example.test").await;
    let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","createOAuthClient").with_body(&json!({"client_name":"Basic grammar","redirect_uris":["https://app.fixture.test/callback"],"token_endpoint_auth_method":"client_secret_basic"}))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}).await?.into_response()?;
    assert_eq!(created.status, 201);
    let client = body(&created);
    assert_eq!(client["client_id"], "client +/é:fixed");
    assert_eq!(client["client_secret"], "secret +/é:tail");
    let encode = |value: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("v", value)
            .finish()
            .strip_prefix("v=")
            .unwrap()
            .to_owned()
    };
    let payload = format!(
        "{}:{}",
        encode(client["client_id"].as_str().unwrap()),
        encode(client["client_secret"].as_str().unwrap())
    );
    let b64 = |value: &str| base64::engine::general_purpose::STANDARD.encode(value);
    let encoded = b64(&payload);
    let invalid = "invalid authorization header format";
    let unsupported = "unsupported authorization scheme";
    let cases = [
        ("canonical", format!("Basic {encoded}"), 200, None, None),
        ("lowercase", format!("basic {encoded}"), 200, None, None),
        ("spaces", format!("bAsIc   {encoded}"), 200, None, None),
        (
            "percent-space",
            format!("Basic {}", b64(&payload.replace('+', "%20"))),
            200,
            None,
            None,
        ),
        (
            "unpadded",
            format!("Basic {}", encoded.trim_end_matches('=')),
            200,
            None,
            None,
        ),
        (
            "ignored-after-padding",
            format!("Basic {encoded}=garbage"),
            200,
            None,
            None,
        ),
        (
            "unescaped-secret-separator",
            format!("Basic {}", b64(&format!("{payload}&ignored=1"))),
            200,
            None,
            None,
        ),
        (
            "missing-colon",
            format!("Basic {}", b64("no-colon")),
            401,
            Some(invalid),
            Some("Basic"),
        ),
        (
            "empty-id",
            format!("Basic {}", b64(":secret")),
            401,
            Some(invalid),
            Some("Basic"),
        ),
        (
            "empty-secret",
            format!("Basic {}", b64("client:")),
            401,
            Some(invalid),
            Some("Basic"),
        ),
        (
            "malformed-base64",
            "Basic %%%".into(),
            401,
            Some(invalid),
            Some("Basic"),
        ),
        (
            "bare-basic",
            "Basic".into(),
            401,
            Some(unsupported),
            Some("Basic"),
        ),
        (
            "tab-basic",
            format!("Basic\t{encoded}"),
            401,
            Some(unsupported),
            Some("Basic"),
        ),
        (
            "bearer",
            "Bearer example".into(),
            401,
            Some(unsupported),
            Some("Bearer"),
        ),
        (
            "invalid-scheme",
            "@bad example".into(),
            400,
            Some("Invalid authorization header format"),
            None,
        ),
    ];
    let before = db
        .tables(&[
            "oauthClient",
            "oauthAccessToken",
            "oauthRefreshToken",
            "verification",
            "oauthClientAssertion",
        ])
        .await?;
    for (name, authorization, status, detail, challenge) in cases {
        let body = json!({"token":"not-issued"});
        let response = invoke(
            &auth,
            &Case {
                name,
                entries: entries(&body),
                body,
                authorization: Some(authorization),
                detail: None,
            },
        )
        .await?;
        assert_eq!(
            response.status,
            status,
            "{name}: {}",
            super::body(&response)
        );
        assert_eq!(
            response.headers.get("WWW-Authenticate").map(String::as_str),
            challenge,
            "{name}"
        );
        assert_eq!(super::body(&response),detail.map_or_else(||json!({"active":false}),|detail|json!({"error":if status==400{"invalid_request"}else{"invalid_client"},"error_description":detail})),"{name}");
        assert_eq!(
            db.tables(&[
                "oauthClient",
                "oauthAccessToken",
                "oauthRefreshToken",
                "verification",
                "oauthClientAssertion"
            ])
            .await?,
            before,
            "{name}"
        );
    }
    B::close(connection).await
}
