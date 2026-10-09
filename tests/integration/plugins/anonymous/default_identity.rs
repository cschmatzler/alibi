//! The random default has a public native shape contract, not a nonce exemption.
#![allow(clippy::unwrap_used, reason = "native lifecycle setup must succeed")]

use crate::storage::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::AnonymousPlugin;
use alibi::plugins::anonymous::AnonymousConfig;
use alibi::{AuthBuilder, AuthConfig};
use alibi::{AuthRequest, AuthSession, AuthUser, HttpMethod};
use serde_json::{Value, json};
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    backend_tests!(
        default_anonymous_identity_is_lowercase_32_characters_and_retires_its_actual_session
    );
    postgres_tests!(
        default_anonymous_identity_is_lowercase_32_characters_and_retires_its_actual_session
    );
    async fn default_anonymous_identity_is_lowercase_32_characters_and_retires_its_actual_session<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        for domain in [None, Some("anonymous.fixture.test"), Some("")] {
            let config = AuthConfig::new("native-anonymous-default-shape-secret-32")
                .base_url("http://localhost:42617");
            let db = db.fresh().await?;
            let (connection, _) = db.migrated::<B>(&config.secret).await?;
            let auth = AuthBuilder::<B::Schema>::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    email_domain_name: domain.map(str::to_owned),
                    ..Default::default()
                }))
                .build()
                .await
                .unwrap();
            let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/anonymous");
            request.body = Some(json!({}).to_string().into_bytes());
            drop(
                request
                    .headers
                    .insert("content-type".into(), "application/json".into()),
            );
            drop(
                request
                    .headers
                    .insert("origin".into(), "http://localhost:42617".into()),
            );
            let issued = Box::pin(auth.handle_request(request.clone())).await?;
            assert_eq!(issued.status, 200);
            let body: Value = serde_json::from_slice(&issued.body).unwrap();
            let user = body.get("user").unwrap();
            let email = user.get("email").unwrap().as_str().unwrap();
            let identifier = domain.filter(|domain| !domain.is_empty()).map_or_else(
                || {
                    email
                        .strip_suffix("@anonymous.placeholder.invalid")
                        .unwrap()
                },
                |domain| {
                    email
                        .strip_prefix("temp-")
                        .unwrap()
                        .strip_suffix(&format!("@{domain}"))
                        .unwrap()
                },
            );
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
            assert_eq!(auth.store().get_user_accounts(id).await.unwrap().len(), 0);
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
            drop(request.headers.insert("cookie".into(), cookie.clone()));
            let before = db.tables(&["users", "sessions"]).await?;
            let rejected = Box::pin(auth.handle_request(request.clone())).await?;
            assert_eq!(rejected.status, 400);
            assert_eq!(db.tables(&["users", "sessions"]).await?, before);
            request.path = "/api/auth/delete-anonymous-user".into();
            let deleted = Box::pin(auth.handle_request(request.clone())).await?;
            assert_eq!(deleted.status, 200);
            assert_eq!(
                serde_json::from_slice::<Value>(&deleted.body).unwrap(),
                json!({"success":true})
            );
            assert!(auth.store().get_user_by_id(id).await.unwrap().is_none());
            assert_eq!(db.count("users").await?, 0);
            assert_eq!(db.count("sessions").await?, 0);
            assert_eq!(auth.store().get_user_sessions(id).await.unwrap().len(), 0);
            let replay = Box::pin(auth.handle_request(request)).await?;
            assert_eq!(replay.status, 401);
            assert_eq!(
                serde_json::from_slice::<Value>(&replay.body)
                    .unwrap()
                    .get("code")
                    .unwrap(),
                "UNAUTHORIZED"
            );
            B::close(connection).await?;
        }
        Ok(())
    }
}
