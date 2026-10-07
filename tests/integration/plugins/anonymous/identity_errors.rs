//! Native callback error classification before anonymous persistence starts.
#![allow(clippy::unwrap_used, reason = "native fixture setup must succeed")]
use alibi::plugins::{
    AnonymousPlugin,
    anonymous::{AnonymousConfig, AnonymousIdentity},
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi_core::{AuthRequest, HttpMethod};
#[cfg(feature = "seaorm")]
use alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema as Schema;
#[cfg(not(feature = "seaorm"))]
use alibi_sqlx::store::__private_test_support::bundled_schema::BundledSchema as Schema;
use async_trait::async_trait;
use std::sync::Arc;
struct Identity {
    name: bool,
    coded: bool,
}
impl Identity {
    fn failure(&self) -> AuthError {
        if self.coded {
            AuthError::Api {
                status: 403,
                code: Some("IDENTITY_DENIED".into()),
                message: "private identity failure".into(),
            }
        } else {
            AuthError::internal("private identity failure")
        }
    }
}
#[async_trait]
impl AnonymousIdentity for Identity {
    async fn email(&self) -> AuthResult<Option<String>> {
        if self.name {
            Ok(Some("anonymous@fixture.test".into()))
        } else {
            Err(self.failure())
        }
    }
    async fn name(&self, _: &AuthRequest) -> AuthResult<Option<String>> {
        Err(self.failure())
    }
}
#[tokio::test]
async fn identity_callback_errors_keep_api_wires_and_hide_ordinary_causes_before_any_write() {
    for name in [false, true] {
        for coded in [false, true] {
            let config = AuthConfig::new("native-identity-callback-secret-minimum32")
                .base_url("http://localhost:42918");
            #[cfg(feature = "seaorm")]
            let store = {
                let db = alibi_seaorm::Database::connect("sqlite::memory:")
                    .await
                    .unwrap();
                alibi_seaorm::store::__private_test_support::migrator::run_migrations(&db)
                    .await
                    .unwrap();
                alibi_seaorm::SeaOrmStore::<Schema>::new(config.clone(), db)
            };
            #[cfg(not(feature = "seaorm"))]
            let store = {
                let db = alibi_sqlx::SqlxPool::connect("sqlite::memory:")
                    .await
                    .unwrap();
                alibi_sqlx::store::__private_test_support::migrator::run_migrations(&db)
                    .await
                    .unwrap();
                alibi_sqlx::SqlxStore::<Schema>::new(config.clone(), db)
            };
            let auth = AuthBuilder::<Schema>::new(config)
                .store(store)
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    identity: Some(Arc::new(Identity { name, coded })),
                    ..Default::default()
                }))
                .build()
                .await
                .unwrap();
            let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/anonymous");
            request.body = Some(b"{}".to_vec());
            drop(
                request
                    .headers
                    .insert("content-type".into(), "application/json".into()),
            );
            drop(
                request
                    .headers
                    .insert("origin".into(), "http://localhost:42918".into()),
            );
            let response = auth.handle_request(request).await.unwrap();
            assert_eq!(response.status, if coded { 403 } else { 500 });
            if coded {
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                    serde_json::json!({"code":"IDENTITY_DENIED","message":"private identity failure"})
                );
            } else {
                assert!(
                    response.body.is_empty(),
                    "ordinary application causes must not reach HTTP"
                );
            }
            assert_eq!(
                auth.store().list_users(Default::default()).await.unwrap().1,
                0
            );
        }
    }
}
