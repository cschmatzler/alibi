use super::*;
use crate::plugins::test_helpers::{
    create_auth_request_no_query, create_test_context, create_user_and_session,
};
use better_auth_core::hooks::with_request_hook_context;
use better_auth_core::{CreateUser, UpdateUser};
use std::sync::Arc;
use tokio::sync::Notify;
type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct Transform {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    finished: Arc<Notify>,
}
#[async_trait]
impl SessionTransform<Schema> for Transform {
    async fn transform(
        &self,
        value: Value,
        req: &AuthRequest,
        ctx: &AuthContext<Schema>,
    ) -> AuthResult<Value> {
        let id = value
            .pointer("/user/id")
            .and_then(Value::as_str)
            .expect("actual user id");
        let name = value
            .pointer("/user/name")
            .and_then(Value::as_str)
            .expect("actual user name");
        if name == "Reject" {
            self.entered.notified().await;
            return Err(better_auth_core::AuthError::internal("application failure"));
        }
        self.entered.notify_one();
        self.release.notified().await;
        assert_eq!(req.path(), "/multi-session/list-device-sessions");
        assert_eq!(
            better_auth_core::hooks::current_request_hook_context()
                .expect("retained real request")
                .headers
                .get("x-application"),
            Some(&"original".to_owned())
        );
        ctx.database
            .update_user(
                id,
                UpdateUser {
                    name: Some("Completed".into()),
                    ..Default::default()
                },
            )
            .await?;
        self.finished.notify_one();
        Ok(value)
    }
}

#[tokio::test]
async fn rejected_device_list_preserves_launched_callback_request_and_database_ownership() {
    let ctx = create_test_context().await;
    let (reject, reject_session) = create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("reject@custom.fixture.test")
            .with_name("Reject"),
        chrono::Duration::hours(1),
    )
    .await;
    let (slow, slow_session) = create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("slow@custom.fixture.test")
            .with_name("Slow"),
        chrono::Duration::hours(1),
    )
    .await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let finished = Arc::new(Notify::new());
    let plugin = CustomSessionPlugin::new(Transform {
        entered,
        release: release.clone(),
        finished: finished.clone(),
    })
    .mutate_device_sessions(true);
    let mut req = create_auth_request_no_query(
        HttpMethod::Get,
        "/multi-session/list-device-sessions",
        Some(&reject_session.token),
        None,
    );
    drop(
        req.headers
            .insert("x-application".into(), "original".into()),
    );
    use better_auth_core::utils::cookie_utils::sign_cookie_value;
    let cookies = [&reject_session.token, &slow_session.token]
        .into_iter()
        .map(|token| {
            format!(
                "{}_multi-{}={}",
                ctx.config.session.cookie_name,
                token.to_lowercase(),
                sign_cookie_value(token, &ctx.config.secret)
            )
        })
        .collect::<Vec<_>>();
    let ordinary = req.header("cookie").expect("signed current cookie").clone();
    drop(req.headers.insert(
        "cookie".into(),
        format!("{ordinary}; {}", cookies.join("; ")),
    ));
    let response = super::super::multi_session::MultiSessionPlugin::new()
        .on_request(&req, &ctx)
        .await
        .expect("real list")
        .expect("list route");
    assert_eq!(response.status, 200);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        with_request_hook_context(&req, plugin.after_request(&req, &ctx, response)),
    )
    .await
    .expect("aggregate rejects without waiting for held callback");
    assert!(matches!(
        result,
        Err(better_auth_core::AuthError::CallbackFailure(_))
    ));
    assert_eq!(
        ctx.database
            .get_user_by_id(&slow.id)
            .await
            .expect("read")
            .expect("stored slow owner")
            .name
            .as_deref(),
        Some("Slow")
    );
    release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), finished.notified())
        .await
        .expect("launched callback completes after observer rejection");
    assert_eq!(
        ctx.database
            .get_user_by_id(&slow.id)
            .await
            .expect("read")
            .expect("stored slow owner")
            .name
            .as_deref(),
        Some("Completed")
    );
    assert_eq!(
        ctx.database
            .get_user_by_id(&reject.id)
            .await
            .expect("read")
            .expect("stored reject owner")
            .name
            .as_deref(),
        Some("Reject")
    );
}
