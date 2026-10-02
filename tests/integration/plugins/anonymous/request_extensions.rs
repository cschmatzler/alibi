//! Native embedding contract: private request state is isolated per dispatch.
#![allow(
    clippy::unwrap_used,
    reason = "public boundary regressions fail on setup errors"
)]

use async_trait::async_trait;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
    CreateUser, HttpMethod,
};
use better_auth_seaorm::{Database, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Barrier;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[derive(Clone)]
struct ApplicationRequest {
    sequence: usize,
    email: String,
}

struct ApplicationContext {
    sequence: Arc<AtomicUsize>,
    concurrent: Arc<Barrier>,
}

#[async_trait]
impl AuthPlugin<Schema> for ApplicationContext {
    fn name(&self) -> &'static str {
        "application-request-context"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _request: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn before_request(
        &self,
        request: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        assert!(
            request.extensions().get::<ApplicationRequest>().is_none(),
            "caller or prior dispatch state reached an authenticated route"
        );
        let body: Value = request.body_as_json().unwrap();
        let capture = ApplicationRequest {
            sequence: self.sequence.fetch_add(1, Ordering::SeqCst) + 1,
            email: body.get("email").unwrap().as_str().unwrap().to_owned(),
        };
        request.extensions().insert(capture.clone());
        if request.header("x-concurrent").is_some() {
            _ = self.concurrent.wait().await;
        }
        let handler_copy = request.clone();
        let current = handler_copy
            .extensions()
            .get::<ApplicationRequest>()
            .unwrap();
        assert_eq!(
            current.sequence, capture.sequence,
            "another dispatch overwrote this request's context"
        );
        assert_eq!(current.email, capture.email);
        let task_context = better_auth_core::hooks::current_request_hook_context().unwrap();
        assert_eq!(
            task_context
                .extensions
                .get::<ApplicationRequest>()
                .unwrap()
                .sequence,
            capture.sequence
        );
        Ok(None)
    }

    async fn after_request(
        &self,
        request: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let capture = request.extensions().get::<ApplicationRequest>().unwrap();
        let task_context = better_auth_core::hooks::current_request_hook_context().unwrap();
        assert_eq!(
            task_context
                .extensions
                .get::<ApplicationRequest>()
                .unwrap()
                .sequence,
            capture.sequence
        );
        drop(
            response
                .headers
                .insert("x-application-sequence", capture.sequence.to_string()),
        );
        Ok(response)
    }
}

struct StorageContext(Arc<Mutex<Vec<(usize, String)>>>);

#[async_trait]
impl SeaOrmHooks<Schema> for StorageContext {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let request = ctx.request.as_ref().unwrap();
        let capture = request.extensions.get::<ApplicationRequest>().unwrap();
        assert_eq!(user.email.as_deref(), Some(capture.email.as_str()));
        self.0
            .lock()
            .unwrap()
            .push((capture.sequence, capture.email.clone()));
        Ok(HookControl::Continue)
    }
}

async fn configured() -> (
    better_auth::BetterAuth<Schema>,
    Arc<Mutex<Vec<(usize, String)>>>,
) {
    let config = AuthConfig::new("native-request-extension-regression-secret-32")
        .base_url("http://localhost:42611");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let rows = Arc::new(Mutex::new(Vec::new()));
    let store = SeaOrmStore::<Schema>::new(config.clone(), database)
        .with_hooks(vec![Arc::new(StorageContext(Arc::clone(&rows)))]);
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(ApplicationContext {
            sequence: Arc::new(AtomicUsize::new(0)),
            concurrent: Arc::new(Barrier::new(2)),
        })
        .build()
        .await
        .unwrap();
    (auth, rows)
}

fn request(email: &str) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email");
    request.body = Some(
        json!({"email": email, "name":"Actual Owner", "password":"password123"})
            .to_string()
            .into_bytes(),
    );
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(
        request
            .headers
            .insert("origin".into(), "http://localhost:42611".into()),
    );
    request.extensions().insert(ApplicationRequest {
        sequence: 999,
        email: "caller@example.test".into(),
    });
    request
}

fn sequence(response: &AuthResponse) -> usize {
    response
        .headers
        .get("x-application-sequence")
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reused_public_request_keeps_caller_state_out_of_success_failure_and_later_signin() {
        use better_auth_core::AuthUser;

        let (auth, rows) = configured().await;
        let request = request("sequential-owner@example.test");
        let created = auth.handle_request(request.clone()).await.unwrap();
        assert_eq!(created.status, 200);
        let duplicate = auth.handle_request(request.clone()).await.unwrap();
        assert_eq!(duplicate.status, 422);
        let mut signin = request.clone();
        signin.path = "/api/auth/sign-in/email".into();
        let signed_in = auth.handle_request(signin).await.unwrap();
        assert_eq!(signed_in.status, 200);
        assert_eq!(
            [
                sequence(&created),
                sequence(&duplicate),
                sequence(&signed_in)
            ],
            [1, 2, 3]
        );
        assert_eq!(
            request
                .extensions()
                .get::<ApplicationRequest>()
                .unwrap()
                .sequence,
            999
        );
        assert_eq!(
            *rows.lock().unwrap(),
            vec![(1, "sequential-owner@example.test".into())]
        );
        let user = auth
            .store()
            .get_user_by_email("sequential-owner@example.test")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            auth.store()
                .get_user_accounts(user.id().as_ref())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            auth.store()
                .get_user_sessions(user.id().as_ref())
                .await
                .unwrap()
                .len(),
            2
        );
        let first: Value = serde_json::from_slice(&created.body).unwrap();
        let last: Value = serde_json::from_slice(&signed_in.body).unwrap();
        assert_eq!(
            first.get("user").unwrap().get("id").unwrap(),
            last.get("user").unwrap().get("id").unwrap()
        );
        assert_ne!(first.get("token").unwrap(), last.get("token").unwrap());
    }

    #[tokio::test]
    async fn concurrent_cloned_public_requests_share_only_their_own_trusted_dispatch_context() {
        use better_auth_core::AuthUser;

        let (auth, rows) = configured().await;
        let mut request = request("concurrent-owner@example.test");
        drop(request.headers.insert("x-concurrent".into(), "true".into()));
        let (left, right) = tokio::join!(
            auth.handle_request(request.clone()),
            auth.handle_request(request.clone())
        );
        let left = left.unwrap();
        let right = right.unwrap();
        let mut statuses = [left.status, right.status];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 422]);
        let mut markers = [sequence(&left), sequence(&right)];
        markers.sort_unstable();
        assert_eq!(markers, [1, 2]);
        assert_eq!(
            request
                .extensions()
                .get::<ApplicationRequest>()
                .unwrap()
                .sequence,
            999
        );
        let attempts = rows.lock().unwrap().clone();
        assert_ne!(attempts.len(), 0);
        assert!(
            attempts
                .iter()
                .all(|(sequence, email)| (1..=2).contains(sequence)
                    && email == "concurrent-owner@example.test")
        );

        let user = auth
            .store()
            .get_user_by_email("concurrent-owner@example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            auth.store()
                .get_user_accounts(user.id().as_ref())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            auth.store()
                .get_user_sessions(user.id().as_ref())
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
