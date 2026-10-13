//! Public sign-up creates a credential owner and publishes only its session.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};

backend_tests!(server_sign_up_email_creates_owned_credentials_and_usable_sessions);

async fn server_sign_up_email_creates_owned_credentials_and_usable_sessions<B: Backend>(
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
        .plugin(super::auth_probe::fast_password().enable_username(false))
        .build()
        .await?;
    let foreign = signup(&auth, "logical-signup-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let endpoint = |input: &Value| {
        ServerEndpoint::<Value>::new("email-password", "signUpEmail").with_body(input)
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, status) in [
        (json!({}), 400),
        (
            json!({"name":"Owner","email":"invalid","password":PASSWORD}),
            400,
        ),
        (
            json!({"name":"Owner","email":"new-owner@example.test","password":""}),
            400,
        ),
        (
            json!({"name":"Owner","email":"new-owner@example.test","password":PASSWORD,"image":null}),
            400,
        ),
        (
            json!({"name":"Owner","email":"new-owner@example.test","password":PASSWORD,"rememberMe":null}),
            400,
        ),
        (
            json!({"name":"Owner","email":"new-owner@example.test","password":"short"}),
            400,
        ),
    ] {
        let denial =
            Box::pin(auth.dispatch_endpoint(endpoint(&input)?, EndpointOptions::default()))
                .await
                .unwrap_err();
        assert_eq!(denial.error.status_code(), status);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    }
    for (index, remember) in [None, Some(false), Some(true)].into_iter().enumerate() {
        let email = format!("logical-signup-owner-{index}@example.test");
        let name = if index == 0 { "" } else { "New Owner" };
        let mut input = json!({"name":name,"email":email.to_uppercase(),"password":PASSWORD,"image":"image-is-a-string","callbackURL":"https://external.example.test/done","userId":foreign_id,"emailVerified":true,"role":"admin","username":7,"displayUsername":false});
        if let Some(remember) = remember {
            input["rememberMe"] = json!(remember);
        }
        let mut typed = alibi::plugins::email_password::SignUpEmailRequest::new(
            name,
            email.to_uppercase(),
            PASSWORD,
        );
        typed.image = Some("image-is-a-string".into());
        typed.callback_url = Some("https://external.example.test/done".into());
        typed.remember_me = remember;
        for (key, value) in [
            ("userId", json!(foreign_id)),
            ("emailVerified", json!(true)),
            ("role", json!("admin")),
            ("username", json!(7)),
            ("displayUsername", json!(false)),
        ] {
            let _ = typed.additional_fields.insert(
                key.into(),
                alibi::utils::json::parse_value(&value.to_string())?,
            );
        }
        let created = Box::pin(
            auth.dispatch_endpoint(
                EmailPasswordPlugin::sign_up_email_endpoint(&typed)?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("cookie".into(), cookies(&foreign)),
                            ("origin".into(), "https://untrusted.example.test".into()),
                            ("x-forwarded-for".into(), "192.0.2.205".into()),
                            ("user-agent".into(), "logical-signup-agent".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?;
        let value = serde_json::to_value(created.decode()?)?;
        let user = value["user"]["id"].as_str().unwrap();
        let token = value["token"].as_str().unwrap();
        assert_ne!(user, foreign_id);
        assert_eq!(value["user"]["email"], email);
        assert_eq!(value["user"]["name"], name);
        assert_eq!(value["user"]["emailVerified"], false);
        assert_eq!(value["user"]["image"], "image-is-a-string");
        assert_ne!(value["user"]["role"], "admin");
        assert!(created.headers().get("location").is_none());
        let credentials: Vec<Value> = serde_json::from_str(&db.table("account").await?)?;
        let account = credentials
            .iter()
            .find(|row| row["userId"] == user && row["providerId"] == "credential")
            .unwrap();
        assert_eq!(account["accountId"], user);
        assert!(
            account["password"]
                .as_str()
                .is_some_and(|hash| !hash.is_empty())
        );
        let rows: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
        let session = rows.iter().find(|row| row["token"] == token).unwrap();
        assert_eq!(session["userId"], user);
        assert_eq!(session["ipAddress"], "192.0.2.205");
        assert_eq!(session["userAgent"], "logical-signup-agent");
        let seconds =
            (chrono::DateTime::parse_from_rfc3339(session["expiresAt"].as_str().unwrap())?
                - chrono::DateTime::parse_from_rfc3339(session["createdAt"].as_str().unwrap())?)
            .num_seconds();
        if remember == Some(false) {
            assert!((86_395..=86_405).contains(&seconds));
        } else {
            assert!(seconds >= 6 * 86_400);
        }
        let cookies = created
            .headers()
            .get_all("set-cookie")
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            cookies
                .iter()
                .find(|c| c.starts_with("better-auth.session_token="))
                .unwrap()
                .contains("Max-Age="),
            remember != Some(false)
        );
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("better-auth.session_data="))
        );
        assert_eq!(
            cookies
                .iter()
                .any(|c| c.starts_with("better-auth.dont_remember=")),
            remember == Some(false)
        );
        let cookie = cookies
            .iter()
            .map(|c| c.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        authenticated(&auth, &cookie, &email).await;
        let stable = db.tables(&["user", "account", "session"]).await?;
        let duplicate =
            Box::pin(auth.dispatch_endpoint(endpoint(&input)?, EndpointOptions::default()))
                .await
                .unwrap_err();
        assert_eq!(duplicate.error.status_code(), 422);
        assert_eq!(db.tables(&["user", "account", "session"]).await?, stable);
        let login = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&login)["user"]["id"], user);
    }
    let users: Vec<Value> = serde_json::from_str(&db.table("user").await?)?;
    let original_users: Vec<Value> = serde_json::from_str(&before[0])?;
    let accounts: Vec<Value> = serde_json::from_str(&db.table("account").await?)?;
    let original_accounts: Vec<Value> = serde_json::from_str(&before[1])?;
    let sessions: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
    let original_sessions: Vec<Value> = serde_json::from_str(&before[2])?;
    assert_eq!(users.len(), original_users.len() + 3);
    assert_eq!(accounts.len(), original_accounts.len() + 3);
    assert_eq!(sessions.len(), original_sessions.len() + 6);
    assert!(original_users.iter().all(|row| users.contains(row)));
    assert!(original_accounts.iter().all(|row| accounts.contains(row)));
    assert!(original_sessions.iter().all(|row| sessions.contains(row)));
    B::close(connection).await
}
