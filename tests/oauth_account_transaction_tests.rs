//! OAuth registration commits its user and account together before issuing a session.
#![expect(
    clippy::unwrap_used,
    reason = "integration setup and endpoint outcomes must succeed"
)]
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
            user: OAuthUserInfo {
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
    _ = request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
}
#[tokio::test]
async fn rejected_account_insert_rolls_back_new_oauth_user_and_retry_commits_binding() {
    let config = AuthConfig::new("oauth-atomic-fixture-secret-at-least-32-characters");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let mut provider = OAuthProvider::google("local-client", "local-secret");
    provider.verify_id_token = Some(Arc::new(Profile));
    provider.get_user_info = Some(Arc::new(Profile));
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database.clone()))
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await
        .unwrap();
    _ = database.execute_raw(Statement::from_string(DbBackend::Sqlite, "CREATE TRIGGER reject_oauth_account BEFORE INSERT ON accounts WHEN NEW.provider_id = 'google' BEGIN SELECT RAISE(FAIL, 'account insert veto'); END".to_owned())).await.unwrap();
    let rejected = auth.handle_request(request()).await.unwrap();
    assert_eq!(rejected.status, 403);
    assert!(
        !rejected
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
    );
    assert!(
        auth.store()
            .get_account("google", "google-transaction-owner")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .get_user_by_email("atomic@oauth.fixture.test")
            .await
            .unwrap()
            .is_none(),
        "a failed account insert must roll back its newly created user"
    );
    _ = database
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "DROP TRIGGER reject_oauth_account".to_owned(),
        ))
        .await
        .unwrap();
    let accepted = auth.handle_request(request()).await.unwrap();
    assert_eq!(accepted.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&accepted.body).unwrap();
    let token = body["token"].as_str().unwrap();
    let user = auth
        .store()
        .get_user_by_email("atomic@oauth.fixture.test")
        .await
        .unwrap()
        .unwrap();
    let account = auth
        .store()
        .get_account("google", "google-transaction-owner")
        .await
        .unwrap()
        .unwrap();
    let session = auth.store().get_session(token).await.unwrap().unwrap();
    assert_eq!(account.user_id(), user.id());
    assert_eq!(session.user_id(), user.id());
    assert_eq!(body["user"]["id"], user.id().to_string());
    assert!(
        accepted
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
    );
}
