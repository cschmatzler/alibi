//! OAuth registration commits its user and account together before issuing a session.

use crate::storage::{Backend, Db, TestResult, backend_tests, postgres_tests};
use async_trait::async_trait;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::{
    OAuthIdTokenVerifier, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthRequest, HttpMethod};
use serde_json::json;
use std::sync::Arc;

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

#[cfg(test)]
mod tests {
    use super::*;

    backend_tests!(rejected_account_insert_rolls_back_new_oauth_user_and_retry_commits_binding);
    postgres_tests!(rejected_account_insert_rolls_back_new_oauth_user_and_retry_commits_binding);

    async fn rejected_account_insert_rolls_back_new_oauth_user_and_retry_commits_binding<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        let config = AuthConfig::new("oauth-atomic-fixture-secret-at-least-32-characters");
        let (connection, _) = db.migrated::<B>(&config.secret).await?;
        let mut provider = OAuthProvider::google("local-client", "local-secret");
        provider.verify_id_token = Some(Arc::new(Profile));
        provider.get_user_info = Some(Arc::new(Profile));
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(OAuthPlugin::new().add_provider("google", provider))
            .build()
            .await
            .unwrap();
        if db.is_postgres() {
            _=db.execute("CREATE FUNCTION reject_oauth_account_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'account insert veto'; END $$",&[]).await?;
            _=db.execute("CREATE TRIGGER reject_oauth_account BEFORE INSERT ON accounts FOR EACH ROW WHEN (NEW.provider_id='google') EXECUTE FUNCTION reject_oauth_account_insert()",&[]).await?;
        } else {
            _ = db.execute("CREATE TRIGGER reject_oauth_account BEFORE INSERT ON accounts WHEN NEW.provider_id = 'google' BEGIN SELECT RAISE(FAIL, 'account insert veto'); END", &[]).await?;
        }
        let rejected = Box::pin(auth.handle_request(request())).await?;
        assert_eq!(rejected.status, 401);
        let failure: serde_json::Value = serde_json::from_slice(&rejected.body).unwrap();
        assert_eq!(
            failure.get("code").and_then(serde_json::Value::as_str),
            Some("OAUTH_LINK_ERROR")
        );
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
        assert_eq!(db.count("users").await?, 0);
        assert_eq!(db.count("accounts").await?, 0);
        assert_eq!(db.count("sessions").await?, 0);
        _ = db
            .execute(
                if db.is_postgres() {
                    "DROP TRIGGER reject_oauth_account ON accounts"
                } else {
                    "DROP TRIGGER reject_oauth_account"
                },
                &[],
            )
            .await?;
        let accepted = Box::pin(auth.handle_request(request())).await?;
        assert_eq!(accepted.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&accepted.body).unwrap();
        let token = (*(body).get("token").unwrap_or(&serde_json::Value::Null))
            .as_str()
            .unwrap();
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
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("id")
                .unwrap_or(&serde_json::Value::Null)),
            user.id().to_string()
        );
        assert!(
            accepted
                .headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
        );
        B::close(connection).await
    }
}
