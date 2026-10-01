//! The random default has a public native shape contract, not a nonce exemption.
#![allow(clippy::unwrap_used, reason = "native lifecycle setup must succeed")]
use better_auth::plugins::AnonymousPlugin;
use better_auth::plugins::anonymous::AnonymousConfig;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthRequest, AuthSession, AuthUser, HttpMethod};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[tokio::test]
async fn default_anonymous_identity_is_lowercase_32_characters_and_retires_its_actual_session() {
    for domain in [None, Some("anonymous.fixture.test"), Some("")] {
        let config = AuthConfig::new("native-anonymous-default-shape-secret-32")
            .base_url("http://localhost:42617");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let auth = AuthBuilder::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database))
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                email_domain_name: domain.map(str::to_owned),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/anonymous");
        request.body = Some(json!({}).to_string().into_bytes());
        let _ = request
            .headers
            .insert("content-type".into(), "application/json".into());
        let _ = request
            .headers
            .insert("origin".into(), "http://localhost:42617".into());
        let issued = auth.handle_request(request.clone()).await.unwrap();
        assert_eq!(issued.status, 200);
        let body: Value = serde_json::from_slice(&issued.body).unwrap();
        let user = body.get("user").unwrap();
        let email = user.get("email").unwrap().as_str().unwrap();
        let identifier = match domain.filter(|domain| !domain.is_empty()) {
            Some(domain) => email
                .strip_prefix("temp-")
                .unwrap()
                .strip_suffix(&format!("@{domain}"))
                .unwrap(),
            None => email
                .strip_suffix("@anonymous.placeholder.invalid")
                .unwrap(),
        };
        assert_eq!(identifier.len(), 32);
        assert!(
            identifier
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        );
        assert_eq!(user.get("name").unwrap(), "Anonymous");
        assert_eq!(user.get("isAnonymous").unwrap(), true);
        assert_eq!(user.get("emailVerified").unwrap(), false);
        let id = user.get("id").unwrap().as_str().unwrap();
        let stored = auth.store().get_user_by_id(id).await.unwrap().unwrap();
        assert_eq!(stored.email(), Some(email));
        assert_eq!(stored.is_anonymous(), Some(true));
        assert!(auth.store().get_user_accounts(id).await.unwrap().is_empty());
        let sessions = auth.store().get_user_sessions(id).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions.first().unwrap().token(),
            body.get("token").unwrap().as_str().unwrap()
        );
        let cookie = issued
            .headers
            .get_all("set-cookie")
            .map(|header| header.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let _ = request.headers.insert("cookie".into(), cookie.clone());
        let rejected = auth.handle_request(request.clone()).await.unwrap();
        assert_eq!(rejected.status, 400);
        assert_eq!(
            auth.store().get_user_by_id(id).await.unwrap().unwrap(),
            stored
        );
        assert_eq!(auth.store().get_user_sessions(id).await.unwrap(), sessions);
        request.path = "/api/auth/delete-anonymous-user".into();
        let deleted = auth.handle_request(request.clone()).await.unwrap();
        assert_eq!(deleted.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&deleted.body).unwrap(),
            json!({"success":true})
        );
        assert!(auth.store().get_user_by_id(id).await.unwrap().is_none());
        assert!(auth.store().get_user_sessions(id).await.unwrap().is_empty());
        let replay = auth.handle_request(request).await.unwrap();
        assert_eq!(replay.status, 401);
        assert_eq!(
            serde_json::from_slice::<Value>(&replay.body)
                .unwrap()
                .get("code")
                .unwrap(),
            "UNAUTHORIZED"
        );
    }
}
