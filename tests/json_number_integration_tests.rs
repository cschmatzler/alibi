#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! JSON wire conversion must not mask incorrect persisted metadata or mutate delivery inputs.

#[cfg(test)]
#[path = "json_number_integration_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink,
};
use better_auth::plugins::{ApiKeyPlugin, EmailPasswordPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::{
    AuthRequest, AuthResponse, AuthResult, CreateOrganization, HttpMethod, UpdateOrganization,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::Value;
use std::sync::{Arc, Mutex};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://json-numbers.fixture.test";

const METADATA: &str = r#"{"z":1,"a":2,"10":1e21,"2":1e400,"1":-0.0,"rounded":9007199254740993,"nested":[-1e400,229069639655724.625],"scientific":1e21,"fixed":1e20,"tiny":3.8730639354761726e-71,"reserved":{"$serde_json::private::Number":"1e400"},"raw":{"$serde_json::private::RawValue":"hello"}}"#;

const STORED_METADATA: &str = r#"{"1":0,"2":null,"10":1e+21,"z":1,"a":2,"rounded":9007199254740992,"nested":[null,229069639655724.62],"scientific":1e+21,"fixed":100000000000000000000,"tiny":3.8730639354761726e-71,"reserved":{"$serde_json::private::Number":"1e400"},"raw":{"$serde_json::private::RawValue":"hello"}}"#;

#[derive(Default)]
struct Sender(Mutex<Vec<MagicLinkDelivery>>);

#[async_trait]
impl SendMagicLink for Sender {
    async fn send(&self, delivery: &MagicLinkDelivery) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

async fn post(
    auth: &BetterAuth<Schema>,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> (AuthResponse, Value) {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(request.headers.insert("origin".into(), ORIGIN.into()));
    if let Some(cookie) = cookie {
        drop(request.headers.insert("cookie".into(), cookie.into()));
    }
    request.body = Some(body.as_bytes().to_vec());
    let response = auth.handle_request(request).await.unwrap();
    let payload = better_auth_core::utils::json::from_slice(&response.body).unwrap();
    (response, payload)
}
