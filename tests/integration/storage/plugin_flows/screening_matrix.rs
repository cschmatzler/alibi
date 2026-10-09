//! Compromised-password and CAPTCHA admission against varied provider replies.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::captcha::{
    BotIdConfig, BotIdVerification, CaptchaConfig, CaptchaPlugin, CaptchaProvider, CheckBotId,
    RecaptchaConfig, SiteKeyCaptchaConfig, TurnstileConfig, ValidateBotIdRequest,
};
use alibi::plugins::haveibeenpwned::{
    HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient,
};
use alibi_core::AuthResult;

backend_tests!(pwned_range_reply_matrix, captcha_reply_and_path_matrix);

const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

fn client(provider: &Provider) -> PwnedPasswordClient {
    PwnedPasswordClient::new(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        provider.url.clone(),
    )
}

async fn pwned_range_reply_matrix<B: Backend>(db: Db) -> TestResult {
    let provider = Provider::start("text/plain", "").await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
            client: client(&provider),
            custom_password_compromised_message: Some("Pick another password".into()),
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let hit = format!("{SUFFIX}:42");
    let escaped = format!(r#""\ud800A\b\f\r\t\/\\\"\n{hit}\r\n""#);
    let replies: Vec<(&str, &'static str, String)> = vec![
        ("plain hit", "text/plain", format!("{hit}\r\n")),
        ("json string hit", "application/json", format!("\"{hit}\"")),
        ("escaped surrogate lines", "application/json", escaped),
        (
            "lone surrogate array",
            "application/json",
            r#"["\ud800"]"#.into(),
        ),
        (
            "lone surrogate object",
            "application/json",
            r#"{"a":"\ud800"}"#.into(),
        ),
        ("json number", "application/json", "42".into()),
        (
            "vendor json",
            "application/vnd.api+json",
            format!("{hit}\n"),
        ),
        ("mixed case json", "Application/JSON", format!("{hit}\n")),
        ("svg media", "image/svg", format!("{hit}\n")),
        (
            "binary media",
            "application/octet-stream",
            format!("{hit}\n"),
        ),
        (
            "invalid vendor suffix",
            "application/vnd ai+json",
            format!("{hit}\n"),
        ),
        (
            "other lines first",
            "text/plain",
            format!("0000:1\nABC\n{}:5\n", &SUFFIX[..10]),
        ),
        (
            "lowercase suffix",
            "text/plain",
            format!("{}:1\n", SUFFIX.to_lowercase()),
        ),
        (
            "bare newline terminator",
            "text/plain",
            format!("x:1\n{hit}\n"),
        ),
        ("zero count", "text/plain", format!("{SUFFIX}:0\r\n")),
        ("absent suffix", "text/plain", "FFFFF:1\n".into()),
        ("empty count", "text/plain", format!("{SUFFIX}:\n")),
        ("non digit count", "text/plain", format!("{SUFFIX}:4x\n")),
        (
            "leading zero count",
            "text/plain",
            format!("{SUFFIX}:007\n"),
        ),
        (
            "count above safe integer",
            "text/plain",
            format!("{SUFFIX}:9007199254740992\n"),
        ),
        (
            "count above u64",
            "text/plain",
            format!("{SUFFIX}:99999999999999999999999\n"),
        ),
    ];
    for (index, (label, content_type, text)) in replies.into_iter().enumerate() {
        provider.respond(200, content_type, text);
        let input = json!({"email":format!("pwned{index}@example.test"),"password":"password","name":"Owner"});
        trace.response(
            label,
            &Box::pin(auth.handle_request(request("/sign-up/email", Some(input), ""))).await?,
        );
    }
    trace.value("users", json!(db.count("users").await?));

    provider.respond(200, "text/plain", format!("{hit}\n"));
    for (label, paths, enabled) in [
        (
            "custom path included",
            Some(vec!["/sign-up/email".to_owned()]),
            true,
        ),
        (
            "custom path excluded",
            Some(vec!["/change-password".to_owned()]),
            true,
        ),
        ("disabled", None, false),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = builder::<B>(&connection)
            .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
                enabled,
                paths,
                client: client(&provider),
                ..Default::default()
            }))
            .build()
            .await?;
        let input = json!({"email":"scoped@example.test","password":"password","name":"Owner"});
        trace.response(
            label,
            &Box::pin(auth.handle_request(request("/sign-up/email", Some(input), ""))).await?,
        );
        B::close(connection).await?;
    }
    trace.assert("screening/pwned-reply-matrix");
    B::close(connection).await
}

struct Bot(Result<bool, &'static str>);
#[async_trait::async_trait]
impl CheckBotId for Bot {
    async fn check(&self) -> AuthResult<BotIdVerification> {
        self.0
            .map(|is_bot| BotIdVerification {
                is_bot,
                is_verified_bot: Some(!is_bot),
                verified_bot_name: None,
                verified_bot_category: None,
            })
            .map_err(alibi_core::AuthError::internal)
    }
}
struct Judge(bool);
#[async_trait::async_trait]
impl ValidateBotIdRequest for Judge {
    async fn validate(&self, _: &AuthRequest, _: &BotIdVerification) -> AuthResult<bool> {
        Ok(self.0)
    }
}

async fn captcha_reply_and_path_matrix<B: Backend>(db: Db) -> TestResult {
    let provider = Provider::start("application/json", "").await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let sign_in = |token: Option<&str>| {
        let mut input = request(
            "/sign-in/email",
            Some(json!({"email":"nobody@example.test","password":PASSWORD})),
            "",
        );
        if let Some(token) = token {
            _ = input
                .headers
                .insert("x-captcha-response".into(), token.into());
        }
        input
    };
    let http = || reqwest::Client::builder().no_proxy().build().unwrap();
    let mut turnstile = TurnstileConfig::new("provider-secret");
    turnstile.http.site_verify_url = Some(provider.url.clone());
    let auth = builder::<B>(&connection)
        .plugin(
            CaptchaPlugin::new(CaptchaConfig::new(CaptchaProvider::CloudflareTurnstile(
                turnstile,
            )))
            .with_http_client(http()),
        )
        .build()
        .await?;
    trace.response(
        "missing header",
        &Box::pin(auth.handle_request(sign_in(None))).await?,
    );
    trace.response(
        "empty header",
        &Box::pin(auth.handle_request(sign_in(Some("")))).await?,
    );
    let replies: [(&str, u16, &'static str, &str); 12] = [
        ("success", 200, "application/json", r#"{"success":true}"#),
        (
            "provider 500",
            500,
            "application/json",
            r#"{"success":true}"#,
        ),
        ("binary media", 200, "image/png", r#"{"success":true}"#),
        ("invalid json text", 200, "text/plain", "not json"),
        ("empty body", 200, "text/plain", ""),
        ("json null", 200, "application/json", "null"),
        ("json zero", 200, "application/json", "0"),
        ("json array", 200, "application/json", "[]"),
        (
            "numeric success",
            200,
            "application/json",
            r#"{"success":1}"#,
        ),
        (
            "empty string success",
            200,
            "application/json",
            r#"{"success":""}"#,
        ),
        (
            "object success",
            200,
            "application/json",
            r#"{"success":{}}"#,
        ),
        (
            "string success",
            200,
            "application/json",
            r#"{"success":"x"}"#,
        ),
    ];
    for (label, status, content_type, text) in replies {
        provider.respond(status, content_type, text);
        trace.response(
            label,
            &Box::pin(auth.handle_request(sign_in(Some("proof")))).await?,
        );
    }
    let _ = provider.take();

    let site_key = |url: &url::Url| {
        let mut options = SiteKeyCaptchaConfig::new("provider-secret");
        options.http.site_verify_url = Some(url.clone());
        options
    };
    let mut recaptcha = RecaptchaConfig::new("provider-secret");
    recaptcha.http.site_verify_url = Some(provider.url.clone());
    let mut empty = SiteKeyCaptchaConfig::new("");
    empty.http.site_verify_url = Some(provider.url.clone());
    let paths = |patterns: &[&str]| patterns.iter().map(|path| (*path).to_owned()).collect();
    let scenarios: Vec<(&str, CaptchaProvider, Vec<String>, &str)> = vec![
        (
            "recaptcha low score",
            CaptchaProvider::GoogleRecaptcha(recaptcha),
            Vec::new(),
            "/sign-in/email",
        ),
        (
            "empty secret",
            CaptchaProvider::HCaptcha(empty),
            Vec::new(),
            "/sign-in/email",
        ),
        (
            "wildcard segment",
            CaptchaProvider::CaptchaFox(site_key(&provider.url)),
            paths(&["/sign-in/e?ail", "/sign-up/*"]),
            "/sign-in/email",
        ),
        (
            "globstar descendants",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&["/sign-in/**"]),
            "/sign-in/email",
        ),
        (
            "unprotected path",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&["/sign-up/*"]),
            "/sign-in/email",
        ),
        (
            "oversized pattern",
            CaptchaProvider::HCaptcha(site_key(&provider.url)),
            paths(&[&"*a".repeat(5000)]),
            "/sign-in/email",
        ),
    ];
    provider.respond(200, "application/json", r#"{"success":true,"score":0.1}"#);
    for (label, kind, endpoints, path) in scenarios {
        let mut config = CaptchaConfig::new(kind);
        config.endpoints = endpoints;
        let auth = builder::<B>(&connection)
            .plugin(CaptchaPlugin::new(config).with_http_client(http()))
            .build()
            .await?;
        let mut input = sign_in(None);
        input.path = format!("/api/auth{path}");
        trace.response(label, &Box::pin(auth.handle_request(input)).await?);
        let mut input = sign_in(Some("proof"));
        input.path = format!("/api/auth{path}");
        trace.response(
            &format!("{label} with token"),
            &Box::pin(auth.handle_request(input)).await?,
        );
    }

    let bots: [(&str, Bot, Option<bool>); 5] = [
        ("human", Bot(Ok(false)), None),
        ("bot", Bot(Ok(true)), None),
        ("check failure", Bot(Err("down")), None),
        ("validator accepts bot", Bot(Ok(true)), Some(true)),
        ("validator rejects human", Bot(Ok(false)), Some(false)),
    ];
    for (label, bot, judge) in bots {
        let auth = builder::<B>(&connection)
            .plugin(CaptchaPlugin::new(CaptchaConfig::new(
                CaptchaProvider::VercelBotId(BotIdConfig {
                    check_bot_id: Arc::new(bot),
                    validate_request: judge.map(|verdict| Arc::new(Judge(verdict)) as _),
                }),
            )))
            .build()
            .await?;
        trace.response(label, &Box::pin(auth.handle_request(sign_in(None))).await?);
    }
    trace.assert("screening/captcha-reply-path-matrix");
    B::close(connection).await
}
