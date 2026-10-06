//! Organization selection must be readable from the newly issued cache alone.
use better_auth::plugins::organization::{OrganizationConfig, TeamsConfig};
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::endpoint::{EndpointOptions, ServerEndpoint};
use better_auth_core::{AuthRequest, CookieCacheConfig, CookieCacheStrategy, HttpMethod};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::collections::BTreeMap;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn build(config: AuthConfig) -> BetterAuth<Schema> {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database))
        .plugin(EmailPasswordPlugin::new())
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await
        .unwrap()
}

fn request(method: HttpMethod, path: &str, body: Option<Value>, cookies: &str) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(
        request
            .headers
            .insert("origin".into(), "http://localhost:42594".into()),
    );
    if !cookies.is_empty() {
        drop(request.headers.insert("cookie".into(), cookies.into()));
    }
    request.body = body.map(|body| serde_json::to_vec(&body).unwrap());
    request
}

fn update_cookies(cookies: &mut BTreeMap<String, String>, headers: &[String]) {
    for header in headers {
        let pair = header.split(';').next().unwrap();
        let (name, value) = pair.split_once('=').unwrap();
        drop(cookies.insert(name.into(), value.into()));
    }
}

fn cookie_header(cookies: &BTreeMap<String, String>) -> String {
    cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[tokio::test]
async fn organization_changes_refresh_the_cache_for_http_and_native_calls() {
    for native in [false, true] {
        for strategy in [
            CookieCacheStrategy::Compact,
            CookieCacheStrategy::Jwt,
            CookieCacheStrategy::Jwe,
        ] {
            let config = AuthConfig::new("organization-cookie-cache-secret-at-least-32")
                .base_url("http://localhost:42594")
                .session_cookie_cache(CookieCacheConfig {
                    enabled: true,
                    strategy: strategy.clone(),
                    ..Default::default()
                });
            let auth = build(config.clone()).await;
            // This instance has no session rows: successful reads must use the cookie cache.
            let reader = build(config).await;
            let signup = auth
                .handle_request(request(
                    HttpMethod::Post,
                    "/sign-up/email",
                    Some(json!({
                        "email":"cache@example.test", "name":"Cache", "password":"Password123!", "rememberMe": !native
                    })),
                    "",
                ))
                .await
                .unwrap();
            assert_eq!(signup.status, 200);
            let mut cookies = BTreeMap::new();
            update_cookies(
                &mut cookies,
                &signup
                    .headers
                    .get_all("set-cookie")
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let mut first_id = Value::Null;
            let mut team_id = Value::Null;
            let mut second_id = Value::Null;
            for step in 0..5 {
                let (operation, path, body) = match step {
                    0 => (
                        "createOrganization",
                        "/organization/create",
                        json!({"name":"First", "slug":"first"}),
                    ),
                    1 => (
                        "createOrganization",
                        "/organization/create",
                        json!({"name":"Second", "slug":"second", "keepCurrentActiveOrganization":true}),
                    ),
                    2 => (
                        "setActiveOrganization",
                        "/organization/set-active",
                        json!({"organizationSlug":"second"}),
                    ),
                    _ => (
                        "setActiveOrganization",
                        "/organization/set-active",
                        json!({"organizationId":null}),
                    ),
                };
                let (value, headers) = if native {
                    let endpoint = ServerEndpoint::<Value>::new("organization", operation)
                        .with_body(&body)
                        .unwrap();
                    let response = auth
                        .dispatch_endpoint(
                            endpoint,
                            EndpointOptions {
                                headers: Some([("cookie".into(), cookie_header(&cookies))].into()),
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap();
                    let headers = response
                        .headers()
                        .get_all("set-cookie")
                        .cloned()
                        .collect::<Vec<_>>();
                    (response.decode().unwrap(), headers)
                } else {
                    let response = auth
                        .handle_request(request(
                            HttpMethod::Post,
                            path,
                            Some(body),
                            &cookie_header(&cookies),
                        ))
                        .await
                        .unwrap();
                    assert_eq!(response.status, 200);
                    (
                        serde_json::from_slice::<Value>(&response.body).unwrap(),
                        response
                            .headers
                            .get_all("set-cookie")
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                };
                let changed = matches!(step, 0 | 2 | 3);
                assert_eq!(
                    headers
                        .iter()
                        .any(|header| header.starts_with("better-auth.session_data=")),
                    changed,
                    "native={native}, strategy={strategy:?}, step={step}"
                );
                if changed {
                    let cache = headers
                        .iter()
                        .find(|header| header.starts_with("better-auth.session_data="))
                        .unwrap();
                    assert_eq!(
                        cache.contains("Max-Age="),
                        !native,
                        "cache must preserve rememberMe"
                    );
                }
                update_cookies(&mut cookies, &headers);
                if step == 0 {
                    first_id = value.get("id").unwrap().clone();
                } else if step == 1 {
                    second_id = value.get("id").unwrap().clone();
                }
                let read = reader
                    .handle_request(request(
                        HttpMethod::Get,
                        "/get-session",
                        None,
                        &cookie_header(&cookies),
                    ))
                    .await
                    .unwrap();
                assert_eq!(read.status, 200);
                let cached: Value = serde_json::from_slice(&read.body).unwrap();
                let session = cached
                    .get("session")
                    .expect("the refreshed cache must authenticate without a stored session");
                let expected = match step {
                    0 | 1 => &first_id,
                    2 => &second_id,
                    _ => &Value::Null,
                };
                assert_eq!(session.get("activeOrganizationId").unwrap(), expected);
                if step == 0 {
                    team_id = session.get("activeTeamId").unwrap().clone();
                    assert!(
                        team_id.is_string(),
                        "creation must publish its default team"
                    );
                }
                assert_eq!(session.get("activeTeamId").unwrap(), &team_id);
            }
        }
    }
}
