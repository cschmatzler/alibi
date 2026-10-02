#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! OAuth registration commits its user and account together before issuing a session.

#[cfg(test)]
#[path = "oauth_account_transaction_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthRequest, HttpMethod};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;
use std::sync::Arc;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct Profile;

#[async_trait]
impl OAuthIdTokenVerifier for Profile {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Ok(true)
    }
}

#[async_trait]
impl OAuthUserInfoHandler for Profile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        Ok(OAuthUserInfoResponse {
            user_output: None,
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: "google-transaction-owner".into(),
                email: "atomic@oauth.fixture.test".into(),
                name: Some("Atomic OAuth Owner".into()),
                image: None,
                email_verified: true,
            },
            data: json!({}),
        })
    }
}

fn request() -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
    request.body = Some(
        serde_json::to_vec(
            &json!({"provider":"google", "idToken":{"token":"trusted-provider-token"}}),
        )
        .unwrap(),
    );
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    request
}
