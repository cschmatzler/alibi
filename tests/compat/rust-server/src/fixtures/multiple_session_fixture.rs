//! Equivalent configured session-token generation and multiple-session runtimes.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    EmailPasswordPlugin, MultiSessionConfig, MultiSessionPlugin, SessionManagementPlugin,
};
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::{AuthBuilder, AuthConfig, AuthResult, prelude::CreateSession};
use alibi::{CookieAttributes, CookieOverride, SameSite};
use axum::Router;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TokenHook(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl alibi::seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        let rank = match count % 3 {
            1 => 3,
            2 => 1,
            _ => 2,
        };
        session.token = Some(format!("{rank:04}{count:028}"));
        Ok(alibi::seaorm::HookControl::Continue)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut runtimes = std::collections::HashMap::new();
    for (name, maximum_sessions) in [
        ("multi-session", 5.0),
        ("multi-session-limited", 2.0),
        ("multi-session-zero", 0.0),
        ("multi-session-fractional", 1.5),
        ("multi-session-negative", -1.0),
        ("multi-session-nan", f64::NAN),
        ("multi-session-infinite", f64::INFINITY),
        ("multi-session-negative-infinite", f64::NEG_INFINITY),
        ("multi-session-cookie-alias", 5.0),
        ("multi-session-cookie-prefix", 5.0),
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name.starts_with("multi-session-cookie-") {
            config.advanced.cookie_prefix = Some("device-proof".into());
            config.advanced.default_cookie_attributes = CookieAttributes {
                path: Some(path.clone()),
                http_only: Some(false),
                same_site: Some(SameSite::Strict),
                max_age: Some(71.0),
                ..Default::default()
            };
            if name.ends_with("alias") {
                config.advanced.cookies.insert(
                    "session_token".into(),
                    CookieOverride {
                        name: Some("configured-device-token".into()),
                        attributes: CookieAttributes {
                            http_only: Some(true),
                            same_site: Some(SameSite::Lax),
                            max_age: Some(123.0),
                            ..Default::default()
                        },
                    },
                );
            }
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    crate::backend::store::<TestSchema>(config, database.clone())
                        .hook(TokenHook(counter.clone())),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
                    maximum_sessions,
                }))
                .build()
                .await?,
        );
        runtimes.insert(name.to_owned(), auth.clone());
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let runtimes = Arc::new(runtimes);
    let selection_runtimes = runtimes.clone();
    router = router.route(
        "/__test/server-api/multi-session-select",
        axum::routing::post(move |axum::Json(input): axum::Json<serde_json::Value>| {
            let runtimes = selection_runtimes.clone();
            async move {
                use axum::response::IntoResponse as _;
                let selected = runtimes
                    .get(input["profile"].as_str().unwrap_or("multi-session"))
                    .unwrap();
                let mut endpoint = alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(
                    "multi-session",
                    "setActiveSession",
                );
                if let Some(body) = input.get("body") {
                    endpoint = endpoint.with_body(body).unwrap();
                }
                match selected
                    .dispatch_endpoint(
                        endpoint,
                        alibi::endpoint::EndpointOptions {
                            headers: input
                                .get("headers")
                                .map(|headers| serde_json::from_value(headers.clone()).unwrap()),
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(output) => output.into_response().unwrap().into_response(),
                    Err(error) => {
                        let mut response = error.error.to_auth_response();
                        if let Some(body) = error.body {
                            response.body = serde_json::to_vec(&*body).unwrap();
                        }
                        if let Some(headers) = error.headers {
                            for (name, value) in headers.iter() {
                                response.headers.append(name, value);
                            }
                        }
                        response.into_response()
                    }
                }
            }
        }),
    );
    router = router.route(
        "/__test/server-api/multi-session-list",
        axum::routing::post(move |request: axum::extract::Request| {
            let runtimes = runtimes.clone();
            async move {
                use axum::response::IntoResponse as _;
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                let input: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let selected = runtimes
                    .get(input["profile"].as_str().unwrap_or("multi-session"))
                    .unwrap();
                let original = if input["originalRequest"].as_bool() == Some(true) {
                    let mut request =
                        alibi::AuthRequest::new(alibi::HttpMethod::Post, parts.uri.path())
                            .with_url(
                                url::Url::parse(&format!(
                                    "http://{}{}",
                                    parts.headers.get("host").unwrap().to_str().unwrap(),
                                    parts.uri
                                ))
                                .unwrap(),
                            );
                    request.headers = parts
                        .headers
                        .iter()
                        .filter_map(|(name, value)| {
                            value
                                .to_str()
                                .ok()
                                .map(|value| (name.to_string(), value.to_owned()))
                        })
                        .collect();
                    request.body = Some(bytes.to_vec());
                    Some(request)
                } else {
                    None
                };
                match selected
                    .dispatch_endpoint(
                        alibi::endpoint::ServerEndpoint::<serde_json::Value>::new(
                            "multi-session",
                            "listDeviceSessions",
                        ),
                        alibi::endpoint::EndpointOptions {
                            headers: input
                                .get("headers")
                                .map(|headers| serde_json::from_value(headers.clone()).unwrap()),
                            request: original,
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(output) => output.into_response().unwrap().into_response(),
                    Err(error) => error.error.to_auth_response().into_response(),
                }
            }
        }),
    );
    let path = "/__test/profiles/multi-session-stateless/api/auth";
    let config = config
        .clone()
        .base_path(path)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            strategy: alibi::CookieCacheStrategy::Jwe,
            max_age: 300.0,
            ..Default::default()
        });
    let auth = Arc::new(
        AuthBuilder::without_database(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(MultiSessionPlugin::new())
            .build()
            .await?,
    );
    router = router.nest(path, auth.clone().axum_router().with_state(auth));
    Ok(router)
}
