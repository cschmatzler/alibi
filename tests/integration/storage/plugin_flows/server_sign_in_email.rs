//! Public credential sign-in owns session issuance independently of HTTP.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};

backend_tests!(server_sign_in_email_validates_credentials_and_issues_usable_owned_sessions);

async fn server_sign_in_email_validates_credentials_and_issues_usable_owned_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(alibi::CookieCacheConfig {
        enabled: true,
        max_age: 300.0,
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .build()
        .await?;
    let owner = signup(&auth, "logical-signin-owner@example.test").await;
    let foreign = signup(&auth, "logical-signin-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let endpoint = |input: &Value| {
        ServerEndpoint::<Value>::new("email-password", "signInEmail").with_body(input)
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, status) in [
        (json!({}), 400),
        (json!({"email":null,"password":PASSWORD}), 400),
        (
            json!({"email":"logical-signin-owner@example.test","password":7}),
            400,
        ),
        (
            json!({"email":"logical-signin-owner@example.test","password":PASSWORD,"rememberMe":"no"}),
            400,
        ),
        (
            json!({"email":"logical-signin-owner@example.test","password":PASSWORD,"callbackURL":null}),
            400,
        ),
        (json!({"email":"not-an-email","password":PASSWORD}), 400),
        (
            json!({"email":"logical-signin-owner@example.test","password":"wrong-password"}),
            401,
        ),
        (
            json!({"email":"missing-owner@example.test","password":PASSWORD}),
            401,
        ),
        (
            json!({"email":"logical-signin-owner@example.test","password":""}),
            401,
        ),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(endpoint(&input)?, EndpointOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    let mut incoming = request("/incoming-login", None, "");
    incoming.method = HttpMethod::Post;
    incoming.headers.extend([
        ("origin".into(), "https://untrusted.example.test".into()),
        ("sec-fetch-site".into(), "cross-site".into()),
        ("sec-fetch-mode".into(), "navigate".into()),
    ]);
    let denied = Box::pin(auth.dispatch_endpoint(
        endpoint(&json!({"email":"logical-signin-owner@example.test","password":PASSWORD}))?,
        EndpointOptions {
            request: Some(incoming),
            ..Default::default()
        },
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let mut minted = Vec::new();
    for (remember, callback) in [
        (None, None),
        (Some(false), Some("")),
        (Some(true), Some("https://external.example.test/done")),
    ] {
        let mut input = json!({"email":"LOGICAL-SIGNIN-OWNER@EXAMPLE.TEST","password":PASSWORD,"userId":foreign_id});
        if let Some(remember) = remember {
            input["rememberMe"] = json!(remember);
        }
        if let Some(callback) = callback {
            input["callbackURL"] = json!(callback);
        }
        let selected = if remember.is_none() {
            EmailPasswordPlugin::sign_in_email_endpoint(
                &alibi::plugins::email_password::SignInEmailRequest {
                    email: "LOGICAL-SIGNIN-OWNER@EXAMPLE.TEST".into(),
                    password: PASSWORD.into(),
                    callback_url: None,
                    remember_me: None,
                },
            )?
        } else {
            ServerEndpoint::<alibi::plugins::email_password::SignInEmailResponse>::new(
                "email-password",
                "signInEmail",
            )
            .with_body(&input)?
        };
        let login = Box::pin(
            auth.dispatch_endpoint(
                selected,
                EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookies(&foreign)),
                            ("origin".into(), "https://untrusted.example.test".into()),
                            ("user-agent".into(), "logical-login-agent".into()),
                            ("x-forwarded-for".into(), "192.0.2.205".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?;
        let value = match login.decode()? {
            alibi::plugins::email_password::SignInEmailResponse::Session(session) => {
                serde_json::to_value(session)?
            }
            other @ alibi::plugins::email_password::SignInEmailResponse::TwoFactor { .. } => {
                panic!("unexpected second factor: {other:?}")
            }
        };
        assert_eq!(value["user"]["id"], owner_id);
        assert_eq!(
            value["redirect"],
            callback.is_some_and(|url| !url.is_empty())
        );
        assert_eq!(value.get("url").and_then(Value::as_str), callback);
        assert_eq!(
            login.headers().get("location").map(String::as_str),
            callback.filter(|url| !url.is_empty())
        );
        let token = value["token"].as_str().unwrap();
        assert!(!minted.contains(&token.to_owned()));
        minted.push(token.to_owned());
        let rows: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
        let row = rows.iter().find(|row| row["token"] == token).unwrap();
        assert_eq!(row["userId"], owner_id);
        assert_eq!(row["ipAddress"], "192.0.2.205");
        assert_eq!(row["userAgent"], "logical-login-agent");
        let expiry = chrono::DateTime::parse_from_rfc3339(row["expiresAt"].as_str().unwrap())?;
        let created = chrono::DateTime::parse_from_rfc3339(row["createdAt"].as_str().unwrap())?;
        let seconds = (expiry - created).num_seconds();
        if remember == Some(false) {
            assert!((86_395..=86_405).contains(&seconds));
        } else {
            assert!(seconds >= 6 * 86_400);
        }
        let fields = login
            .headers()
            .get_all("set-cookie")
            .cloned()
            .collect::<Vec<_>>();
        let authority = fields
            .iter()
            .find(|cookie| cookie.starts_with("better-auth.session_token="))
            .unwrap();
        assert_eq!(authority.contains("Max-Age="), remember != Some(false));
        assert!(
            fields
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.session_data="))
        );
        assert_eq!(
            fields
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.dont_remember=")),
            remember == Some(false)
        );
        let cookie = fields
            .iter()
            .map(|cookie| cookie.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        authenticated(&auth, &cookie, "logical-signin-owner@example.test").await;
        assert_eq!(db.table("user").await?, before[0]);
        assert_eq!(db.table("account").await?, before[1]);
    }
    let original: Vec<Value> = serde_json::from_str(&before[2])?;
    let after: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
    assert_eq!(after.len(), original.len() + 3);
    assert!(original.iter().all(|row| after.contains(row)));
    authenticated(
        &auth,
        &cookies(&foreign),
        "logical-signin-foreign@example.test",
    )
    .await;
    B::close(connection).await
}
