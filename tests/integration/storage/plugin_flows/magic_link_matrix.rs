//! Magic-link issuance policy, callback validation and redemption outcomes.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, MagicLinkTokenGenerator,
    MagicLinkTokenHasher, MagicLinkTokenStorage, SendMagicLink,
};
use alibi_core::hooks::RequestHookContext;
use alibi_core::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi_core::{AuthError, AuthResult, CallbackContext};
use async_trait::async_trait;

backend_tests!(
    magic_link_request_matrix,
    magic_link_issuance_policies,
    magic_link_redemption_matrix
);

#[derive(Default)]
struct Outbox {
    sent: Mutex<Vec<MagicLinkDelivery>>,
    failure: Mutex<Option<&'static str>>,
}
#[async_trait]
impl SendMagicLink for Outbox {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.sent.lock().unwrap().push(delivery.clone());
        match *self.failure.lock().unwrap() {
            Some("internal") => Err(AuthError::internal("mail down")),
            Some("api") => Err(AuthError::forbidden("mail refused")),
            _ => Ok(()),
        }
    }
}

struct Generator(&'static str);
#[async_trait]
impl MagicLinkTokenGenerator for Generator {
    async fn generate(&self, email: &str) -> AuthResult<String> {
        match self.0 {
            "fail" => Err(AuthError::internal("generator down")),
            _ => Ok(format!("token-for-{}", email.replace(['@', '.'], "-"))),
        }
    }
}

struct Hasher(&'static str);
#[async_trait]
impl MagicLinkTokenHasher for Hasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        match self.0 {
            "internal" => Err(AuthError::internal("hasher down")),
            "api" => Err(AuthError::forbidden("hasher refused")),
            _ => Ok(format!("hashed-{token}")),
        }
    }
}

struct Deny;
#[async_trait]
impl UserInfoValidator for Deny {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(data
            .user
            .email
            .as_deref()
            .is_some_and(|email| email.starts_with("denied"))
            .then(|| UserValidationRejection {
                error: "DENIED".into(),
                error_description: Some("Closed community".into()),
            }))
    }
}

fn redeem(delivery: &MagicLinkDelivery, extra: &[(&str, &str)]) -> AuthRequest {
    let link = url::Url::parse(&delivery.url).unwrap();
    let mut request = AuthRequest::new(HttpMethod::Get, link.path());
    request.query.extend(link.query_pairs().into_owned());
    for (key, value) in extra {
        _ = request.query.insert((*key).into(), (*value).into());
    }
    request
}

async fn magic_link_request_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for text in [
        "[]",
        "null",
        "{}",
        r#"{"email":5}"#,
        r#"{"email":"not-an-email"}"#,
        r#"{"email":"a@example.test","name":5}"#,
        r#"{"email":"a@example.test","callbackURL":5,"newUserCallbackURL":5,"errorCallbackURL":5}"#,
        r#"{"email":"a@example.test","metadata":[]}"#,
        r#"{"email":"a@example.test","metadata":"text"}"#,
        r#"{"email":"a@example.test","metadata":{"campaign":"spring"},"newUserCallbackURL":"/welcome","errorCallbackURL":"/oops","callbackURL":"/home","name":"Ann"}"#,
        r#"{"email":"b@example.test","callbackURL":"","newUserCallbackURL":"","errorCallbackURL":""}"#,
    ] {
        let _ = probe.post(text, "/sign-in/magic-link", text, "").await;
    }
    let delivered: Vec<_> = outbox.sent.lock().unwrap().drain(..).collect();
    probe.trace.value(
        "deliveries",
        json!(delivered
            .iter()
            .map(|sent| {
                let link = url::Url::parse(&sent.url).unwrap();
                json!({
                    "email": sent.email,
                    "metadata": sent.metadata.as_ref().map(|value| value.to_json_value().unwrap()),
                    "query": link
                        .query_pairs()
                        .filter(|(key, _)| key != "token")
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>()),
    );
    probe.trace.assert("magic-link/request-matrix");
    B::close(connection).await
}

async fn magic_link_issuance_policies<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "no sender",
        "internal sender failure",
        "api sender failure",
        "generator failure",
        "custom generator",
        "hashed",
        "custom hasher",
        "hasher internal failure",
        "hasher api failure",
        "invalid expiry",
        "zero expiry",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        *outbox.failure.lock().unwrap() = match mode {
            "internal sender failure" => Some("internal"),
            "api sender failure" => Some("api"),
            _ => None,
        };
        let config = MagicLinkConfig {
            send_magic_link: (mode != "no sender").then(|| outbox.clone() as _),
            generate_token: match mode {
                "generator failure" => Some(Arc::new(Generator("fail"))),
                "custom generator" => Some(Arc::new(Generator("ok"))),
                _ => None,
            },
            storage: match mode {
                "hashed" => MagicLinkTokenStorage::Hashed,
                "custom hasher" => MagicLinkTokenStorage::Custom(Arc::new(Hasher("ok"))),
                "hasher internal failure" => {
                    MagicLinkTokenStorage::Custom(Arc::new(Hasher("internal")))
                }
                "hasher api failure" => MagicLinkTokenStorage::Custom(Arc::new(Hasher("api"))),
                _ => MagicLinkTokenStorage::Plain,
            },
            expires_in: match mode {
                "invalid expiry" => f64::INFINITY,
                "zero expiry" => 0.0,
                _ => 300.0,
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(MagicLinkPlugin::new(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let _ = probe
            .post(
                "request",
                "/sign-in/magic-link",
                r#"{"email":"Issue@Example.test"}"#,
                "",
            )
            .await;
        let token = outbox
            .sent
            .lock()
            .unwrap()
            .last()
            .map(|sent| sent.token.clone())
            .unwrap_or_default();
        let identifiers = db
            .text("SELECT identifier FROM verifications", &[])
            .await?
            .map(|identifier| {
                if token.is_empty() {
                    "<undelivered>".to_owned()
                } else {
                    identifier.replace(&token, "<token>")
                }
            });
        probe.trace.value("stored", json!(identifiers));
        let sent = outbox.sent.lock().unwrap().last().cloned();
        if let Some(sent) = sent {
            let response = Box::pin(auth.handle_request(redeem(&sent, &[]))).await?;
            probe.trace.response("redeem", &response);
        }
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("magic-link/issuance-policies");
    Ok(())
}

async fn magic_link_redemption_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(Deny));
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let issue = async |probe: &mut Probe<'_, B::Schema>, email: &str| {
        let _ = probe
            .post(
                &format!("issue {email}"),
                "/sign-in/magic-link",
                &json!({"email":email,"name":"Link User","callbackURL":"/home","newUserCallbackURL":"/welcome","errorCallbackURL":"/oops"}).to_string(),
                "",
            )
            .await;
        outbox.sent.lock().unwrap().pop().unwrap()
    };
    let verify = async |probe: &mut Probe<'_, B::Schema>, label: &str, input: AuthRequest| {
        let response = Box::pin(auth.handle_request(input)).await.unwrap();
        probe.trace.response(label, &response);
        response
    };
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(&mut probe, "new user", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(&mut probe, "returning user", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "fresh@example.test").await;
    let _ = verify(
        &mut probe,
        "no callback returns session json",
        redeem(&sent, &[("callbackURL", "")]),
    )
    .await;
    let sent = issue(&mut probe, "denied@example.test").await;
    let _ = verify(&mut probe, "denied by policy", redeem(&sent, &[])).await;
    let _ = signup(&auth, "unverified@example.test").await;
    let sent = issue(&mut probe, "unverified@example.test").await;
    let _ = verify(&mut probe, "unverified owner", redeem(&sent, &[])).await;
    let sent = issue(&mut probe, "bad@example.test").await;
    for (label, extra) in [
        ("missing token", vec![("token", "")]),
        (
            "untrusted callback",
            vec![("callbackURL", "https://evil.example")],
        ),
        (
            "untrusted new user callback",
            vec![("newUserCallbackURL", "https://evil.example")],
        ),
        (
            "untrusted error callback",
            vec![("errorCallbackURL", "https://evil.example")],
        ),
        ("malformed escape", vec![("callbackURL", "/a%2")]),
        ("malformed escape pair", vec![("errorCallbackURL", "/a%zz")]),
        ("encoded callback", vec![("callbackURL", "%2Fhome%3Fx%3D1")]),
        ("unknown token", vec![("token", "unknown")]),
    ] {
        let _ = verify(&mut probe, label, redeem(&sent, &extra)).await;
    }
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/magic-link/verify");
    request.headers.extend([("origin".into(), ORIGIN.into())]);
    let _ = verify(&mut probe, "query without token", request).await;
    probe.trace.value(
        "rows",
        json!([db.count("users").await?, db.count("sessions").await?]),
    );
    probe.trace.assert("magic-link/redemption-matrix");
    B::close(connection).await
}
