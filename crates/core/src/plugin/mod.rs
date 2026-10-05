mod context;
mod contracts;
mod extensions;
mod initialization;
mod routes;

use crate::config::AuthConfig;
use crate::email::EmailProvider;
use crate::entity::AuthSession;
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::session::SessionManager;
use crate::store::AuthStore;
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
pub use context::AuthContext;
pub use contracts::AuthPlugin;
pub use contracts::BeforeRequestAction;
pub use contracts::HttpEndpointResponse;
pub use contracts::HttpRequestAction;
pub use contracts::VerificationEmailOverride;
pub use contracts::VerificationEmailOverrideHandle;
pub use extensions::ContextExtensions;
pub use initialization::AuthInitContext;
pub use initialization::AuthInitParts;
pub use routes::AuthRoute;
pub use routes::ResolvedEndpoint;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

type MetadataMap = HashMap<String, serde_json::Value>;

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::AuthUser;
    use crate::test_store::test_database;

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_route_constructors() {
        let get = AuthRoute::get("/test", "getTest");
        assert_eq!(get.method, HttpMethod::Get);
        assert_eq!(get.path, "/test");
        assert_eq!(get.operation_id, "getTest");

        let post = AuthRoute::post("/create", "createItem");
        assert_eq!(post.method, HttpMethod::Post);

        let put = AuthRoute::put("/update", "updateItem");
        assert_eq!(put.method, HttpMethod::Put);

        let delete = AuthRoute::delete("/remove", "deleteItem");
        assert_eq!(delete.method, HttpMethod::Delete);
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_route_new() {
        let route = AuthRoute::new(HttpMethod::Patch, "/patch", "patchIt");
        assert_eq!(route.method, HttpMethod::Patch);
        assert_eq!(route.path, "/patch");
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_new() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config, db);
        assert!(ctx.email_provider.is_none());
        assert!(ctx.metadata.is_empty());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_metadata() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let mut ctx = AuthContext::new(config, db);

        ctx.set_metadata("key", serde_json::json!("value"));
        assert_eq!(ctx.get_metadata("key"), Some(&serde_json::json!("value")));
        assert!(ctx.get_metadata("missing").is_none());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[test]
    fn auth_context_email_provider_error_when_none() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let db = runtime.block_on(test_database());
        let ctx = AuthContext::new(config, db);
        assert!(ctx.email_provider().is_err());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[tokio::test]
    async fn auth_context_require_session_unauthenticated() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;
        let ctx = AuthContext::new(config, db);
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let result = ctx.require_session(&req).await;
        assert!(result.is_err());
    }

    // Rust-specific surface: plugin infrastructure helpers and request-dispatch helpers in `crates/core::plugin` are Rust library APIs with no direct TS analogue.
    #[tokio::test]
    async fn auth_context_require_session_with_valid_session() {
        let config = Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"));
        let db = test_database().await;

        // Create a user
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        // Create a session
        let sm = SessionManager::new(Arc::clone(&config), Arc::clone(&db));
        let session = sm.create_session(&user, None, None).await.unwrap();

        // Build request with the session token
        let ctx = AuthContext::new(Arc::clone(&config), db);
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        drop(req.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                crate::utils::cookie_utils::sign_cookie_value(session.token(), &config.secret)
            ),
        ));

        let (found_user, _found_session) = ctx.require_session(&req).await.unwrap();
        assert_eq!(found_user.id(), user.id());
    }
}
// LCOV_EXCL_STOP
