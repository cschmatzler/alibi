#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library and integration targets"
)]
#![cfg(feature = "seaorm2")]
#![expect(
    clippy::indexing_slicing,
    reason = "Assert real SQLite-backed public handler and independently specified application-model callback snapshots"
)]
//! Native-only application schema contract. Official SDK scenarios own built-in wire parity.
#[path = "compat/rust-server/src/session_field_model.rs"]
mod application_model;

#[cfg(test)]
#[path = "session_cookie_cache_tests/tests.rs"]
mod tests;

use application_model::{ApplicationSchema, application_session};
use async_trait::async_trait;
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthRequest, AuthResult, CacheVersionContext, CacheVersionSource, CookieCacheConfig,
    CookieCacheVersion, CookieCacheVersionResolver, HttpMethod,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Statement};
use better_auth_seaorm::store::__private_test_support::migrator::run_migrations;
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Version(Mutex<Vec<Value>>);

#[async_trait]
impl CookieCacheVersionResolver for Version {
    async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String> {
        let raw = context.stored_session::<application_session::Model>();
        let event = match context.source() {
            CacheVersionSource::Created => {
                let raw = raw.unwrap();
                assert_eq!(raw.hidden.as_deref(), Some("actual-hidden-default"));
                assert_eq!(
                    raw.server_only.as_deref(),
                    Some("physical-private-sentinel")
                );
                assert!(
                    context
                        .stored_user::<better_auth_seaorm::store::entities::user::Model>()
                        .is_some()
                );
                json!({"phase":"stored","id":raw.id,"hidden":raw.hidden,"physical":raw.server_only})
            }
            CacheVersionSource::Stored => {
                panic!("This lifecycle never reaches a live physical read")
            }
            CacheVersionSource::Cached => {
                assert!(raw.is_none());
                assert!(
                    context
                        .stored_user::<better_auth_seaorm::store::entities::user::Model>()
                        .is_none()
                );
                json!({"phase":"cached","id":context.session().id})
            }
        };
        let projection = serde_json::to_value(context.session()).unwrap();
        if context.source() == CacheVersionSource::Created {
            assert_eq!(projection["hidden"], "actual-hidden-default");
        } else {
            assert!(projection.get("hidden").is_none());
        }
        assert!(projection.get("server_only").is_none());
        assert_eq!(projection["label"], "public-label");
        self.0.lock().unwrap().push(event);
        Ok("application-v1".into())
    }
}

fn request(
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    cookies: Option<String>,
) -> AuthRequest {
    let mut request = AuthRequest::new(method, path);
    drop(
        request
            .headers
            .insert("origin".into(), "http://localhost:42594".into()),
    );
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    request.body = body.map(|value| serde_json::to_vec(&value).unwrap());
    if let Some(cookies) = cookies {
        drop(request.headers.insert("cookie".into(), cookies));
    }
    request
}
