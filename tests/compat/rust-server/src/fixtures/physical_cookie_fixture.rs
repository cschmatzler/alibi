//! Genuine physical token/preference production and independent scoped SQLite rows.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_core::{CookieAttributes, CookieOverride, SameSite};
use alibi_seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use axum::{Json, Router, extract::Query, routing::get};
use chrono::Duration;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Storage {
    user_id: Option<String>,
    email: Option<String>,
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let mut router = Router::new();
    for mode in [
        "serializer-valid",
        "serializer-host",
        "serializer-age-boundary",
        "serializer-age-limit",
        "serializer-expiry-limit",
        "cross-localhost",
        "cross-ipv6",
        "cross-inferred",
        "cross-proxy",
        "default",
        "attributes",
        "secure",
        "none",
        "short",
        "legacy",
        "legacy-alias",
        "secure-prefix",
        "https-default",
        "https-disabled",
        "secure-custom",
        "secure-alias",
        "dynamic-https",
        "dynamic-http",
        "dynamic-auto",
    ] {
        let path = format!("/__test/profiles/physical-cookie-{mode}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.advanced.use_secure_cookies = match mode {
            "cross-localhost" | "cross-ipv6" | "cross-inferred" | "cross-proxy"
            | "https-default" | "dynamic-https" | "dynamic-http" | "dynamic-auto" => None,
            "secure-prefix" | "secure-custom" | "secure-alias" => Some(true),
            _ => Some(false),
        };
        if mode.starts_with("cross-") {
            config = config
                .base_url(match mode {
                    "cross-localhost" => "https://localhost:4377",
                    "cross-ipv6" => "https://[::1]:4377",
                    _ => "https://cookie177.test",
                })
                .cross_sub_domain_cookies_from_base_url();
            config.advanced.trust_forwarded_host = true;
            config.trusted_origins.extend([
                "https://cookie177.test:*".into(),
                "https://auth.cookie177.test:*".into(),
            ]);
            if mode == "cross-proxy" {
                config = config.dynamic_base_url(alibi_core::config::DynamicBaseUrl {
                    allowed_hosts: vec!["cookie177.test:*".into(), "auth.cookie177.test:*".into()],
                    protocol: Some(alibi_core::config::BaseUrlProtocol::Https),
                    fallback: None,
                });
            }
        }
        if mode.starts_with("https-") {
            config = config.base_url("https://localhost");
        }
        if mode.starts_with("dynamic-") {
            config = config.dynamic_base_url(alibi_core::config::DynamicBaseUrl {
                allowed_hosts: vec!["localhost:*".into(), "127.0.0.1:*".into()],
                protocol: Some(match mode {
                    "dynamic-https" => alibi_core::config::BaseUrlProtocol::Https,
                    "dynamic-http" => alibi_core::config::BaseUrlProtocol::Http,
                    _ => alibi_core::config::BaseUrlProtocol::Auto,
                }),
                fallback: None,
            });
        }
        config.trusted_origins.push("https://localhost".into());
        config.trusted_origins.push(base.base_url.clone());
        config.session.expires_in = Duration::seconds(match mode {
            "serializer-age-boundary" => 34_560_000,
            "serializer-age-limit" => 34_560_001,
            "short" => 60,
            _ => 604_800,
        });
        if mode.starts_with("serializer-") {
            config.advanced.default_cookie_attributes = CookieAttributes {
                path: Some(path.clone()),
                domain: Some("localhost".into()),
                http_only: Some(false),
                same_site: Some(SameSite::Strict),
                expires: Some(
                    chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                partitioned: Some(false),
                ..Default::default()
            };
            config.advanced.cookies.insert(
                "session_token".into(),
                CookieOverride {
                    name: (mode == "serializer-host").then(|| "__Host-policy".into()),
                    attributes: CookieAttributes {
                        secure: Some(true),
                        partitioned: Some(true),
                        http_only: Some(true),
                        expires: (mode == "serializer-expiry-limit")
                            .then(|| chrono::Utc::now() + Duration::days(401)),
                        ..Default::default()
                    },
                },
            );
            config.advanced.cookies.insert(
                "dont_remember".into(),
                CookieOverride {
                    attributes: CookieAttributes {
                        max_age: Some(121.9),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }
        if mode == "legacy" || mode == "legacy-alias" {
            config.session.cookie_name = if mode == "legacy" {
                "customsession"
            } else {
                "some.alias"
            }
            .into();
        }
        if !mode.starts_with("serializer-") {
            config.advanced.default_cookie_attributes = match mode {
                "attributes" => CookieAttributes {
                    http_only: Some(false),
                    same_site: Some(SameSite::Strict),
                    path: Some(path.clone()),
                    domain: Some("localhost".into()),
                    ..Default::default()
                },
                "secure" => CookieAttributes {
                    secure: Some(true),
                    ..Default::default()
                },
                "none" => CookieAttributes {
                    secure: Some(false),
                    same_site: Some(SameSite::None),
                    ..Default::default()
                },
                _ => CookieAttributes::default(),
            };
        }
        if mode == "secure-alias" {
            config.advanced.cookies.insert(
                "session_token".into(),
                CookieOverride {
                    name: Some("alias.session_token".into()),
                    ..Default::default()
                },
            );
        }
        if mode == "secure-custom" {
            config.advanced.cookie_prefix = Some("policy".into());
            config.advanced.default_cookie_attributes = CookieAttributes {
                secure: Some(false),
                path: Some("/discarded".into()),
                same_site: Some(SameSite::Strict),
                http_only: Some(false),
                ..Default::default()
            };
            for logical in ["session_token", "dont_remember"] {
                config.advanced.cookies.insert(
                    logical.into(),
                    CookieOverride {
                        name: (logical == "session_token").then(|| "configured_session".into()),
                        attributes: CookieAttributes {
                            path: Some(path.clone()),
                            http_only: Some(true),
                            same_site: Some(SameSite::Lax),
                            secure: Some(false),
                            ..Default::default()
                        },
                    },
                );
            }
        }
        if mode == "attributes" {
            drop(config.advanced.cookies.insert(
                "session_token".into(),
                CookieOverride {
                    name: Some("physical_session".into()),
                    ..Default::default()
                },
            ));
            drop(config.advanced.cookies.insert(
                "dont_remember".into(),
                CookieOverride {
                    name: Some("physical_preference".into()),
                    attributes: CookieAttributes {
                        max_age: Some(121.0),
                        ..Default::default()
                    },
                },
            ));
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route("/__test/physical-cookie/storage",get(move|Query(input):Query<Storage>|{let database=database.clone();async move{
  let id = match input.user_id { Some(id) => id, None => {
    let row = database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite, "SELECT id FROM users WHERE email=?", [input.email.unwrap_or_default().into()])).await.unwrap();
    let Some(row) = row else { return Json(json!({"user":[],"accounts":[],"sessions":[]})); };
    row.try_get::<String>("", "id").unwrap()
  }};
  let mut output=serde_json::Map::new();
  for(name,sql) in [
   ("user","SELECT json_object('id',id,'name',name,'email',email,'emailVerified',email_verified,'image',image,'createdAt',created_at,'updatedAt',updated_at) AS data FROM users WHERE id=?"),
   ("accounts","SELECT json_object('id',id,'accountId',account_id,'providerId',provider_id,'userId',user_id,'accessToken',access_token,'refreshToken',refresh_token,'idToken',id_token,'accessTokenExpiresAt',access_token_expires_at,'refreshTokenExpiresAt',refresh_token_expires_at,'scope',scope,'password',password,'createdAt',created_at,'updatedAt',updated_at) AS data FROM accounts WHERE user_id=? ORDER BY provider_id,account_id,id"),
   ("sessions","SELECT json_object('id',id,'expiresAt',expires_at,'token',token,'createdAt',created_at,'updatedAt',updated_at,'ipAddress',ip_address,'userAgent',user_agent,'userId',user_id) AS data FROM sessions WHERE user_id=? ORDER BY created_at,id")
  ] {let rows=database.query_all_raw(Statement::from_sql_and_values(DbBackend::Sqlite,sql,[id.clone().into()])).await.unwrap();let rows:Vec<Value>=rows.iter().map(|row|serde_json::from_str(&row.try_get::<String>("","data").unwrap()).unwrap()).collect();drop(output.insert(name.into(),json!(rows)));}
  Json(Value::Object(output))
 }})))
}
