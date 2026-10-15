//! Last-login tracking applies to genuine direct server issuance.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{LastLoginMethodConfig, LastLoginMethodPlugin};
backend_tests!(
    server_last_login_tracks_issuance_cookie_and_database,
    server_last_login_preserves_logical_callback_context_and_cookie_consent
);
postgres_tests!(
    server_last_login_tracks_issuance_cookie_and_database,
    server_last_login_preserves_logical_callback_context_and_cookie_consent
);
async fn server_last_login_tracks_issuance_cookie_and_database<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for stored in [false, true] {
        let auth = builder::<B>(&connection)
            .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
                store_in_database: stored,
                ..Default::default()
            }))
            .build()
            .await?;
        let email = format!("sdk-last-login-{stored}@example.com");
        for operation in ["signUpEmail", "signInEmail"] {
            let response = Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("email-password", operation)
                        .with_body(&json!({"email":email,"name":"Owner","password":PASSWORD}))?,
                    EndpointOptions::default(),
                ),
            )
            .await
            .map_err(|error| error.error)?
            .into_response()?;
            assert_eq!(response.status, 200);
            assert!(
                response.headers.get_all("set-cookie").any(|cookie| cookie
                    .starts_with("better-auth.last_used_login_method=email;")
                    && !cookie.contains("HttpOnly")),
                "SDK issuance must publish the script-readable last-login cookie"
            );
            let users: Value = serde_json::from_str(&db.table("user").await?)?;
            let user = users
                .as_array()
                .unwrap()
                .iter()
                .find(|user| user["email"] == email)
                .unwrap();
            if stored {
                assert_eq!(user["lastLoginMethod"], "email");
            } else {
                assert!(user["lastLoginMethod"].is_null());
            }
        }
    }
    Ok(())
}

struct Application {
    mode: &'static str,
    contexts: Mutex<Vec<alibi::plugins::LastLoginMethodContext>>,
}
impl alibi::plugins::ResolveLastLoginMethod for Application {
    fn resolve(
        &self,
        context: &alibi::plugins::LastLoginMethodContext,
    ) -> alibi::AuthResult<Option<String>> {
        assert!(context.endpoint.is_some());
        assert!(matches!(
            context.route_path.as_str(),
            "/sign-up/email" | "/sign-in/email"
        ));
        assert_eq!(
            context.method(),
            if context.endpoint_response.is_some() {
                None
            } else {
                Some(&HttpMethod::Post)
            }
        );
        assert_eq!(
            context.header("x-last-login-probe").map(String::as_str),
            Some("sdk")
        );
        assert!(context.body.as_ref().unwrap().get("email").is_some());
        self.contexts.lock().unwrap().push(context.clone());
        Ok((self.mode == "custom").then(|| "enterprise".into()))
    }
}
#[async_trait::async_trait]
impl alibi::plugins::BeforeStoreLastLoginMethodCookie for Application {
    async fn before_store(
        &self,
        context: &alibi::plugins::LastLoginMethodContext,
        method: &str,
    ) -> alibi::AuthResult<bool> {
        assert!(context.response.is_none());
        let output = context.endpoint_response.as_ref().unwrap();
        assert!(output.headers.get_all("set-cookie").next().is_some());
        assert!(output.value.is_some());
        let session = context.new_session.as_ref().unwrap();
        assert_eq!(session.session.user_id, session.user.id);
        assert_eq!(
            method,
            if self.mode == "custom" {
                "enterprise"
            } else {
                "email"
            }
        );
        if self.mode == "cookie-error" {
            return Err(alibi::AuthError::internal("application consent failed"));
        }
        Ok(self.mode != "denied")
    }
}
async fn server_last_login_preserves_logical_callback_context_and_cookie_consent<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for mode in ["custom", "denied", "cookie-error"] {
        let application = Arc::new(Application {
            mode,
            contexts: Mutex::new(Vec::new()),
        });
        let config = LastLoginMethodConfig {
            store_in_database: true,
            resolver: Some(application.clone()),
            before_store_cookie: Some(application.clone()),
            cookie_name: if mode == "custom" {
                "fixture.last_login_method".into()
            } else {
                "better-auth.last_used_login_method".into()
            },
            max_age: if mode == "custom" { 123.9 } else { 2_592_000.0 },
        };
        let auth = builder::<B>(&connection)
            .plugin(LastLoginMethodPlugin::with_config(config))
            .build()
            .await?;
        let email = format!("sdk-last-login-{mode}@example.com");
        let request = (mode == "custom").then(|| AuthRequest::new(HttpMethod::Get, "/original"));
        let response = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("email-password", "signUpEmail")
                    .with_body(&json!({"email":email,"name":"Owner","password":PASSWORD}))?,
                EndpointOptions {
                    headers: Some(
                        [("x-last-login-probe".into(), "sdk".into())]
                            .into_iter()
                            .collect(),
                    ),
                    request,
                    ..Default::default()
                },
            ),
        )
        .await
        .map_err(|error| error.error)?
        .into_response()?;
        assert_eq!(response.status, 200);
        {
            let contexts = application.contexts.lock().unwrap();
            assert_eq!(contexts.len(), 3);
            assert!(
                contexts
                    .iter()
                    .all(|context| context.request.is_some() == (mode == "custom"))
            );
            assert!(contexts.last().unwrap().endpoint_response.is_some());
            assert!(contexts[0].new_session.is_none());
            assert!(contexts[1].new_session.is_some());
            assert!(contexts[2].new_session.is_some());
        }
        let cookies = response
            .headers
            .get_all("set-cookie")
            .filter(|cookie| {
                cookie.starts_with("fixture.last_login_method=")
                    || cookie.starts_with("better-auth.last_used_login_method=")
            })
            .collect::<Vec<_>>();
        if mode == "custom" {
            assert_eq!(cookies.len(), 1);
            assert!(cookies[0].starts_with("fixture.last_login_method=enterprise;"));
            assert!(cookies[0].contains("Max-Age=123"));
        } else {
            assert!(cookies.is_empty());
        }
        let users: Value = serde_json::from_str(&db.table("user").await?)?;
        let user = users
            .as_array()
            .unwrap()
            .iter()
            .find(|user| user["email"] == email)
            .unwrap();
        assert_eq!(
            user["lastLoginMethod"],
            if mode == "custom" {
                "enterprise"
            } else {
                "email"
            }
        );
        assert!(
            auth.store()
                .get_session_record(body(&response)["token"].as_str().unwrap())
                .await?
                .is_some()
        );
        application.contexts.lock().unwrap().clear();
        let response = Box::pin(
            auth.dispatch_endpoint(
                ServerEndpoint::<Value>::new("email-password", "signInEmail")
                    .with_body(&json!({"email":email,"password":PASSWORD}))?,
                EndpointOptions {
                    headers: Some(
                        [("x-last-login-probe".into(), "sdk".into())]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await
        .map_err(|error| error.error)?
        .into_response()?;
        assert_eq!(response.status, 200);
        {
            let contexts = application.contexts.lock().unwrap();
            assert_eq!(contexts.len(), 2);
            assert!(contexts[0].new_session.is_none());
            assert!(contexts[1].new_session.is_some());
            assert!(contexts.iter().all(|context| context.request.is_none()));
        }
    }
    Ok(())
}
